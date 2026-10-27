"""安全加固的回归测试：python -m unittest tests.test_security -v"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from agent.engine import RuleEngine, RuleError
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
        "mode": "llm_first",
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


class NegationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_chinese_negation_blocks_delete(self) -> None:
        plan = self.engine.plan("别删 /etc/passwd")
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["blocked"]["id"], "negation_guard")

    def test_chinese_negation_blocks_restart(self) -> None:
        plan = self.engine.plan("不要重启 nginx 服务")
        self.assertEqual(plan["status"], "blocked")

    def test_english_negation_blocks_delete(self) -> None:
        plan = self.engine.plan("don't delete /etc/passwd")
        self.assertEqual(plan["status"], "blocked")

    def test_normal_request_is_not_affected(self) -> None:
        plan = self.engine.plan("查看磁盘空间")
        self.assertEqual(plan["status"], "ready")


class DeleteConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_delete_phrase_contains_target_path(self) -> None:
        plan = self.engine.plan("删除 /var/tmp/whale-demo")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["confirmation_phrase"], "确认删除 /var/tmp/whale-demo")

    def test_delete_phrase_english_contains_target_path(self) -> None:
        plan = self.engine.plan("delete /var/tmp/whale-demo")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(
            plan["confirmation_phrase"], "Confirm delete /var/tmp/whale-demo"
        )


class RuleValidationTests(unittest.TestCase):
    def _engine_with(self, actions: list[dict[str, Any]]) -> RuleEngine:
        temp = tempfile.mkdtemp(prefix="rhel-rules-")
        path = Path(temp) / "commands.json"
        path.write_text(
            json.dumps({"actions": actions, "blocked_patterns": []}, ensure_ascii=False),
            encoding="utf-8",
        )
        return RuleEngine(Path(temp))

    def test_shell_metacharacter_in_command_is_rejected(self) -> None:
        with self.assertRaises(RuleError):
            self._engine_with(
                [
                    {
                        "id": "bad",
                        "title_zh": "bad",
                        "title_en": "bad",
                        "risk": "safe",
                        "patterns": ["bad"],
                        "commands": [["echo", "a;rm -rf /"]],
                    }
                ]
            )

    def test_unknown_placeholder_is_rejected(self) -> None:
        with self.assertRaises(RuleError):
            self._engine_with(
                [
                    {
                        "id": "bad",
                        "title_zh": "bad",
                        "title_en": "bad",
                        "risk": "safe",
                        "patterns": ["bad"],
                        "commands": [["echo", "{{missing}}"]],
                    }
                ]
            )

    def test_unsafe_rm_template_is_rejected(self) -> None:
        with self.assertRaises(RuleError):
            self._engine_with(
                [
                    {
                        "id": "bad",
                        "title_zh": "bad",
                        "title_en": "bad",
                        "risk": "destructive",
                        "patterns": ["bad"],
                        "commands": [["rm", "-rf", "{{path}}"]],
                        "params": {"path": {"label_zh": "p", "pattern": "^/.*$"}},
                    }
                ]
            )


class LLMFirstTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_llm_first_overrides_ready_rule_plan(self) -> None:
        class FakeInterpreter:
            def interpret(self, message, local_plan):
                return Interpretation(
                    operations=[{"action_id": "system_overview", "parameters": {}}],
                    confidence=0.95,
                    language="en",
                    rationale="LLM chose overview",
                    source="tool_call",
                    model="qwen2.5-7b-instruct",
                )

        planner = HybridPlanner(
            self.engine, llm_config(mode="llm_first"), interpreter=FakeInterpreter()
        )
        plan = planner.plan("show disk usage")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["planner"], "llm")
        self.assertEqual(plan["steps"][0]["action_id"], "system_overview")

    def test_llm_first_falls_back_to_rules(self) -> None:
        class BrokenInterpreter:
            def interpret(self, message, local_plan):
                raise LLMError("offline")

        planner = HybridPlanner(
            self.engine, llm_config(mode="llm_first"), interpreter=BrokenInterpreter()
        )
        plan = planner.plan("查看磁盘空间")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["planner"], "rules")

    def test_llm_missing_params_does_not_downgrade_ready_rule_plan(self) -> None:
        class IncompleteInterpreter:
            def interpret(self, message, local_plan):
                return Interpretation(
                    operations=[{"action_id": "set_hostname", "parameters": {}}],
                    confidence=0.9,
                    language="zh",
                    rationale="LLM forgot the hostname",
                    source="tool_call",
                    model="qwen2.5-7b-instruct",
                )

        planner = HybridPlanner(
            self.engine,
            llm_config(mode="llm_first"),
            interpreter=IncompleteInterpreter(),
        )
        plan = planner.plan("查看磁盘空间")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["planner"], "rules")
        self.assertEqual(plan["steps"][0]["action_id"], "show_disk")

    def test_hybrid_mode_keeps_rules_first(self) -> None:
        class FailingInterpreter:
            calls = 0

            def interpret(self, message, local_plan):
                self.calls += 1
                raise AssertionError("hybrid must not call LLM for a ready rule plan")

        interpreter = FailingInterpreter()
        planner = HybridPlanner(
            self.engine, llm_config(mode="hybrid"), interpreter=interpreter
        )
        plan = planner.plan("查看磁盘空间")
        self.assertEqual(plan["planner"], "rules")
        self.assertEqual(interpreter.calls, 0)


class ChatFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_small_talk_gets_free_chat_reply(self) -> None:
        class FakeInterpreter:
            def interpret(self, message, local_plan):
                return Interpretation(
                    operations=[],
                    confidence=0.9,
                    language="zh",
                    rationale="no operation",
                    source="tool_call",
                    model="qwen2.5-7b-instruct",
                )

            def chat(self, message, local_plan):
                return "在呢，主人想查点什么？"

        planner = HybridPlanner(
            self.engine, llm_config(), interpreter=FakeInterpreter()
        )
        plan = planner.plan("哦哦")
        self.assertEqual(plan["status"], "chat")
        self.assertEqual(plan["planner"], "llm")
        self.assertIn("在呢", plan["message"])

    def test_chat_fallback_when_interpret_raises(self) -> None:
        class FakeInterpreter:
            def interpret(self, message, local_plan):
                raise LLMError("401 invalid api key")

            def chat(self, message, local_plan):
                return "本鲸在，慢慢说。"

        planner = HybridPlanner(
            self.engine, llm_config(), interpreter=FakeInterpreter()
        )
        plan = planner.plan("不是")
        self.assertEqual(plan["status"], "chat")
        self.assertEqual(plan["message"], "本鲸在，慢慢说。")

    def test_no_chat_method_keeps_unsupported(self) -> None:
        class NoChatInterpreter:
            def interpret(self, message, local_plan):
                raise LLMError("offline")

        planner = HybridPlanner(
            self.engine, llm_config(), interpreter=NoChatInterpreter()
        )
        plan = planner.plan("哦哦")
        self.assertEqual(plan["status"], "unsupported")

    def test_protocol_errors_do_not_trip_breaker(self) -> None:
        class FreeTextInterpreter:
            def interpret(self, message, local_plan):
                raise LLMProtocolError("model returned free text")

            def chat(self, message, local_plan):
                return "在呢。"

        planner = HybridPlanner(
            self.engine, llm_config(), interpreter=FreeTextInterpreter()
        )
        for _ in range(5):
            plan = planner.plan("哦哦")
            self.assertEqual(plan["status"], "chat")
            self.assertEqual(plan["planner"], "llm")


class EmergencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_deleted_database_escalates_without_plan(self) -> None:
        plan = self.engine.plan("我不小心删除了公司重要数据库怎么办")
        self.assertEqual(plan["status"], "escalate")
        self.assertEqual(plan["steps"], [])
        steps = plan["incident"]["steps_zh"]
        self.assertTrue(any("DBA" in step for step in steps))

    def test_normal_delete_still_plans(self) -> None:
        plan = self.engine.plan("删除 /var/tmp/whale-demo")
        self.assertEqual(plan["status"], "ready")

    def test_llm_emergency_intent_escalates(self) -> None:
        class FakeInterpreter:
            def interpret(self, message, local_plan):
                return Interpretation(
                    operations=[],
                    confidence=0.92,
                    language="zh",
                    rationale="Looks like an incident",
                    source="tool_call",
                    model="glm-4-plus",
                    intent="emergency",
                )

            def chat(self, message, local_plan):
                return "请立即联系 DBA。"

        planner = HybridPlanner(
            self.engine, llm_config(), interpreter=FakeInterpreter()
        )
        plan = planner.plan("生产环境出了大问题")
        self.assertEqual(plan["status"], "escalate")
        self.assertIn("incident", plan)

    def test_non_operate_intent_with_operations_is_rejected(self) -> None:
        payload = {
            "intent": "advice",
            "language": "en",
            "confidence": 0.9,
            "rationale": "advice must not execute",
            "operations": [{"action_id": "show_disk", "parameters": {}}],
        }
        data = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "submit_operations",
                                    "arguments": json.dumps(payload),
                                },
                            }
                        ]
                    }
                }
            ]
        }
        client = LLMClient(
            self.engine, llm_config(), transport=lambda *args: data
        )
        with self.assertRaises(LLMProtocolError):
            client.interpret("hello", self.engine.plan("查看磁盘空间"))


if __name__ == "__main__":
    unittest.main()
