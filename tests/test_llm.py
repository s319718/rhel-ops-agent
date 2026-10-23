from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from agent.engine import RuleEngine
from agent.llm import (
    HybridPlanner,
    Interpretation,
    LLMClient,
    LLMConfig,
    LLMError,
    LLMProtocolError,
)


ROOT = Path(__file__).resolve().parents[1]


def llm_config(**overrides: Any) -> LLMConfig:
    values = {
        "enabled": True,
        "mode": "hybrid",
        "provider": "openai-compatible",
        "base_url": "https://llm.example.invalid/v1",
        "model": "qwen2.5-7b-instruct",
        "api_key": "test-key",
        "timeout_seconds": 2,
        "confidence_threshold": 0.55,
        "structured_output": True,
        "max_actions": 6,
    }
    values.update(overrides)
    return LLMConfig(**values)


def function_call_response(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "submit_operations",
                                "arguments": json.dumps(payload, ensure_ascii=False),
                            },
                        }
                    ]
                }
            }
        ]
    }


class LLMClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")
        self.local_plan = self.engine.plan("make the machine use Chinese")
        self.assertEqual(self.local_plan["status"], "unsupported")

    def test_native_tool_call_is_parsed_and_validated(self) -> None:
        payload = {
            "language": "en",
            "confidence": 0.94,
            "rationale": "The user wants a locale change.",
            "operations": [
                {"action_id": "set_locale_zh", "parameters": {}}
            ],
        }
        calls = []

        def transport(url, body, headers, timeout):
            calls.append((url, body, headers, timeout))
            return function_call_response(payload)

        client = LLMClient(
            self.engine,
            llm_config(),
            transport=transport,
        )
        result = client.interpret("make the machine use Chinese", self.local_plan)
        self.assertEqual(result.operations[0]["action_id"], "set_locale_zh")
        self.assertEqual(result.source, "tool_call")
        self.assertEqual(calls[0][0], "https://llm.example.invalid/v1/chat/completions")
        self.assertEqual(calls[0][2]["Authorization"], "Bearer test-key")
        self.assertIn("tools", calls[0][1])
        self.assertEqual(
            calls[0][1]["tools"][0]["function"]["name"],
            "submit_operations",
        )
        self.assertEqual(calls[0][1]["response_format"]["type"], "json_schema")

    def test_strict_json_content_is_supported(self) -> None:
        payload = {
            "language": "en",
            "confidence": 0.9,
            "rationale": "Read-only disk check.",
            "operations": [{"action_id": "show_disk", "parameters": {}}],
        }
        data = {"choices": [{"message": {"content": json.dumps(payload)}}]}
        client = LLMClient(
            self.engine,
            llm_config(),
            transport=lambda *args: data,
        )
        result = client.interpret("show moon phase", self.local_plan)
        self.assertEqual(result.source, "structured_content")
        self.assertEqual(result.operations[0]["action_id"], "show_disk")

    def test_free_text_is_rejected(self) -> None:
        data = {
            "choices": [
                {
                    "message": {
                        "content": 'Here is the JSON: {"operations": []}'
                    }
                }
            ]
        }
        client = LLMClient(
            self.engine,
            llm_config(),
            transport=lambda *args: data,
        )
        with self.assertRaises(LLMProtocolError):
            client.interpret("unknown request", self.local_plan)

    def test_unknown_action_is_rejected(self) -> None:
        payload = {
            "language": "en",
            "confidence": 0.9,
            "rationale": "Unknown action.",
            "operations": [{"action_id": "run_arbitrary_shell", "parameters": {}}],
        }
        client = LLMClient(
            self.engine,
            llm_config(),
            transport=lambda *args: function_call_response(payload),
        )
        with self.assertRaises(LLMProtocolError):
            client.interpret("do something", self.local_plan)

    def test_unknown_parameter_is_rejected(self) -> None:
        payload = {
            "language": "en",
            "confidence": 0.9,
            "rationale": "Invalid extra parameter.",
            "operations": [
                {
                    "action_id": "show_disk",
                    "parameters": {"command": "rm -rf /"},
                }
            ],
        }
        client = LLMClient(
            self.engine,
            llm_config(),
            transport=lambda *args: function_call_response(payload),
        )
        with self.assertRaises(LLMProtocolError):
            client.interpret("show disk usage", self.local_plan)

    def test_remote_plain_http_is_rejected(self) -> None:
        with self.assertRaises(LLMError):
            LLMClient(
                self.engine,
                llm_config(base_url="http://llm.example.invalid/v1"),
            )


class HybridPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")
        self.config = llm_config()

    def test_hybrid_uses_validated_llm_plan(self) -> None:
        class FakeInterpreter:
            def interpret(self, message, local_plan):
                return Interpretation(
                    operations=[
                        {"action_id": "set_locale_zh", "parameters": {}}
                    ],
                    confidence=0.93,
                    language="en",
                    rationale="Locale request",
                    source="tool_call",
                    model="qwen2.5-7b-instruct",
                )

        planner = HybridPlanner(
            self.engine,
            self.config,
            interpreter=FakeInterpreter(),
        )
        plan = planner.plan("make the machine use Chinese")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["planner"], "llm")
        self.assertEqual(plan["steps"][0]["action_id"], "set_locale_zh")
        self.assertEqual(plan["confirmation_phrase"], "Confirm locale change")
        self.assertTrue(plan["requires_restart"])

    def test_blocked_request_never_calls_llm(self) -> None:
        class FailingInterpreter:
            calls = 0

            def interpret(self, message, local_plan):
                self.calls += 1
                raise AssertionError("LLM must not be called for blocked requests")

        interpreter = FailingInterpreter()
        planner = HybridPlanner(
            self.engine,
            self.config,
            interpreter=interpreter,
        )
        plan = planner.plan("rm -rf /")
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(interpreter.calls, 0)

    def test_protocol_failure_falls_back_to_rules(self) -> None:
        class BrokenInterpreter:
            def interpret(self, message, local_plan):
                raise LLMProtocolError("invalid output")

        planner = HybridPlanner(
            self.engine,
            self.config,
            interpreter=BrokenInterpreter(),
        )
        plan = planner.plan("make the machine use Chinese")
        self.assertEqual(plan["status"], "unsupported")
        self.assertEqual(plan["planner"], "rules")
        self.assertEqual(plan["llm"]["status"], "fallback")


if __name__ == "__main__":
    unittest.main()
