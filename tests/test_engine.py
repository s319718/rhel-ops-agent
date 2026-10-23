from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.config import Settings
from agent.engine import RuleEngine


ROOT = Path(__file__).resolve().parents[1]


class RuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine(ROOT / "rules")

    def test_root_delete_is_blocked(self) -> None:
        plan = self.engine.plan("rm -rf /")
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["blocked"]["id"], "blocked_delete_root")
        self.assertEqual(plan["steps"], [])

    def test_compound_request(self) -> None:
        prompt = (
            "把系统时间改成 2026-10-23 15:30:00，把 ens160 的 IP 改成 "
            "192.168.1.50/24，网关 192.168.1.1，DNS 223.5.5.5，"
            "再把系统语言改成中文"
        )
        plan = self.engine.plan(prompt, context={"remote_client": True})
        self.assertEqual(plan["status"], "ready")
        ids = {step["action_id"] for step in plan["steps"]}
        self.assertEqual(ids, {"set_datetime", "set_static_ipv4", "set_locale_zh"})
        self.assertTrue(any(item["type"] == "ssh_disconnect" for item in plan["warnings"]))
        self.assertTrue(plan["requires_restart"])
        self.assertEqual(plan["confirmation_phrase"], "确认执行高风险操作")

    def test_network_requires_missing_fields(self) -> None:
        plan = self.engine.plan("修改IP地址")
        self.assertEqual(plan["status"], "needs_input")
        names = {field["name"] for field in plan["fields"]}
        self.assertTrue({"connection", "address", "gateway", "dns"}.issubset(names))

    def test_language_requests_restart(self) -> None:
        plan = self.engine.plan("把系统语言改成中文")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["steps"][0]["action_id"], "set_locale_zh")
        self.assertTrue(plan["requires_restart"])

    def test_english_read_only_intent(self) -> None:
        plan = self.engine.plan("show failed services")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["overall_risk"], "safe")

    def test_english_plan_and_confirmation_are_localized(self) -> None:
        plan = self.engine.plan(
            "set static IP on ens160 to 192.168.1.50/24, gateway 192.168.1.1, DNS 223.5.5.5",
            context={"remote_client": True},
        )
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["language"], "en")
        self.assertEqual(plan["confirmation_phrase"], "Confirm network change")
        self.assertEqual(plan["steps"][0]["title"], "Configure a static IPv4 address")
        self.assertTrue(plan["warnings"][0]["title"].startswith("Network changes"))

    def test_english_reboot_uses_english_confirmation(self) -> None:
        plan = self.engine.plan("reboot")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["language"], "en")
        self.assertEqual(plan["confirmation_phrase"], "Confirm reboot")
        self.assertEqual(plan["steps"][0]["risk_label"], "High risk")

    def test_english_network_input_is_english(self) -> None:
        plan = self.engine.plan("configure IP address")
        self.assertEqual(plan["status"], "needs_input")
        self.assertTrue(all("Please provide" in field["error"] for field in plan["fields"]))
        self.assertTrue(all(field["label"] for field in plan["fields"]))

    def test_small_talk_does_not_generate_commands(self) -> None:
        plan = self.engine.plan("你好")
        self.assertEqual(plan["status"], "chat")
        self.assertEqual(plan["intent"], "greeting")
        self.assertEqual(plan["steps"], [])
        self.assertTrue(plan["suggestions"])
        self.assertEqual(self.engine.plan("吃了吗")["intent"], "meal")
        self.assertEqual(self.engine.plan("你是谁")["intent"], "identity")
        self.assertEqual(self.engine.plan("what can you do?")["language"], "en")

    def test_greeting_prefix_does_not_hide_real_action(self) -> None:
        plan = self.engine.plan("你好，查看磁盘空间")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["steps"][0]["action_id"], "show_disk")

    def test_common_english_actions_are_available(self) -> None:
        cases = {
            "show CPU information": "show_cpu_info",
            "show routing table": "show_routes",
            "show recent logins": "show_recent_logins",
            "show dnf history": "show_dnf_history",
            "create group ops-team": "create_group",
            "unlock user deploy": "unlock_user",
        }
        for prompt, action_id in cases.items():
            with self.subTest(prompt=prompt):
                plan = self.engine.plan(prompt)
                self.assertEqual(plan["status"], "ready")
                self.assertIn(action_id, {step["action_id"] for step in plan["steps"]})

    def test_colloquial_synonyms_are_recognized(self) -> None:
        cases = {
            "帮我看下磁盘还剩多少": "show_disk",
            "机器有点卡，谁占CPU高": "show_processes",
            "有没有安全补丁": "show_updates",
            "现在几点了": "show_time",
            "哪些端口开着": "show_listening_ports",
            "how much disk space is left": "show_disk",
            "what is the kernel version": "show_kernel_version",
        }
        for prompt, action_id in cases.items():
            with self.subTest(prompt=prompt):
                plan = self.engine.plan(prompt)
                self.assertEqual(plan["status"], "ready")
                self.assertIn(action_id, {step["action_id"] for step in plan["steps"]})

    def test_expanded_control_surface_is_loaded(self) -> None:
        self.assertGreaterEqual(len(self.engine.actions), 100)
        ids = {action["id"] for action in self.engine.actions}
        self.assertTrue(
            {
                "show_repositories",
                "show_top_memory_processes",
                "show_failed_logins",
                "show_chrony_sources",
                "show_group_members",
                "show_user_processes",
                "show_audit_status",
            }.issubset(ids)
        )

    def test_path_delete_is_not_confused_with_other_actions(self) -> None:
        plan = self.engine.plan("删除 /var/tmp/old-agent-test")
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["steps"][0]["action_id"], "delete_path")
        self.assertEqual(plan["steps"][0]["params"]["path"], "/var/tmp/old-agent-test")
        self.assertTrue(plan["requires_confirmation"])

    def test_critical_path_delete_is_rejected(self) -> None:
        plan = self.engine.plan("删除 /etc")
        self.assertEqual(plan["status"], "needs_input")
        self.assertTrue(any("禁止删除系统关键路径" in field["error"] for field in plan["fields"]))
        log_plan = self.engine.plan("删除 /var/log/secure")
        self.assertEqual(log_plan["status"], "needs_input")
        self.assertTrue(
            any("禁止删除系统关键路径" in field["error"] for field in log_plan["fields"])
        )

    def test_parameters_cannot_start_with_option_dash(self) -> None:
        plan = self.engine.plan(
            "重启服务",
            overrides={"restart_service": {"service": "--force"}},
        )
        self.assertNotEqual(plan.get("status"), "ready")

    def test_unrelated_text_has_no_action(self) -> None:
        plan = self.engine.plan("帮我写一首诗")
        self.assertEqual(plan["status"], "unsupported")


class AttackMatrixTests(unittest.TestCase):
    def test_all_attack_cases_pass(self) -> None:
        from agent.attack_tests import run_attack_matrix
        from agent.audit import AuditAnalyzer

        engine = RuleEngine(ROOT / "rules")
        analyzer = AuditAnalyzer(ROOT / "rules")
        report = run_attack_matrix(engine, analyzer)
        failures = [item for item in report["results"] if not item["passed"]]
        self.assertEqual(report["failed"], 0, failures)
        self.assertGreaterEqual(report["total"], 100)


if __name__ == "__main__":
    unittest.main()
