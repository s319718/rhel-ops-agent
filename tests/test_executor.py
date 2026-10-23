from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.config import Settings
from agent.db import Database
from agent.engine import RuleEngine
from agent.executor import ExecutionError, Executor


ROOT = Path(__file__).resolve().parents[1]


class ExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings.from_env(
            root_dir=ROOT,
            data_dir=Path(self.temp.name),
            demo=True,
            no_auth=True,
        )
        self.db = Database(self.settings.database_path)
        self.engine = RuleEngine(self.settings.rules_dir)
        self.executor = Executor(self.engine, self.db, demo=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _proposal(self, prompt: str) -> tuple[str, dict, dict]:
        plan = self.engine.plan(prompt)
        self.assertEqual(plan["status"], "ready")
        payload = self.engine.plan_payload(prompt, plan, {})
        proposal_id = self.db.create_proposal(payload, 900)
        return proposal_id, payload, plan

    def test_demo_read_only_execution(self) -> None:
        proposal_id, _, plan = self._proposal("查看磁盘空间")
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "",
        )
        self.assertEqual(result["status"], "completed")
        self.assertIn("演示模式", result["steps"][0]["commands"][0]["output"])

    def test_destructive_action_requires_phrase(self) -> None:
        proposal_id, _, plan = self._proposal("重启系统")
        with self.assertRaises(ExecutionError):
            self.executor.execute(
                proposal_id,
                [step["action_id"] for step in plan["steps"]],
                "确认执行",
            )
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "确认重启",
        )
        self.assertEqual(result["status"], "completed")

    def test_language_change_returns_restart_advice(self) -> None:
        proposal_id, _, plan = self._proposal("把系统语言改成中文")
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "确认修改语言",
        )
        self.assertTrue(result["requires_restart"])
        self.assertTrue(result["restart_reasons"])

    def test_english_reboot_requires_english_phrase(self) -> None:
        proposal_id, _, plan = self._proposal("reboot")
        with self.assertRaises(ExecutionError):
            self.executor.execute(
                proposal_id,
                [step["action_id"] for step in plan["steps"]],
                "确认重启",
            )
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "Confirm reboot",
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["language"], "en")
        self.assertEqual(result["steps"][0]["title"], "Reboot the system")
        self.assertIn("Demo mode", result["steps"][0]["commands"][0]["output"])

    def test_english_locale_change_returns_english_restart_advice(self) -> None:
        proposal_id, _, plan = self._proposal("change system language to Chinese")
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "Confirm locale change",
        )
        self.assertTrue(result["requires_restart"])
        self.assertTrue(result["restart_reasons"][0].startswith("A restart"))

    def test_new_service_action_is_executable(self) -> None:
        proposal_id, _, plan = self._proposal("start nginx service")
        self.assertEqual(plan["confirmation_phrase"], "Confirm service start")
        result = self.executor.execute(
            proposal_id,
            [step["action_id"] for step in plan["steps"]],
            "Confirm service start",
        )
        self.assertEqual(result["status"], "completed")

    def test_every_action_binary_is_allowlisted(self) -> None:
        for action in self.engine.actions:
            commands = list(action.get("commands", [])) + list(
                action.get("post_check", [])
            )
            for argv in commands:
                with self.subTest(action=action["id"], argv=argv):
                    self.assertIn(Path(argv[0]).name, self.executor.allowed_binaries)


if __name__ == "__main__":
    unittest.main()
