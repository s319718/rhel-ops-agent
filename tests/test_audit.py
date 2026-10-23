from __future__ import annotations

import unittest
from pathlib import Path

from agent.attack_tests import AUDIT_CASES
from agent.audit import AuditAnalyzer


ROOT = Path(__file__).resolve().parents[1]


class AuditAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = AuditAnalyzer(ROOT / "rules")

    def test_attack_command_rules(self) -> None:
        for case in AUDIT_CASES:
            match = self.analyzer.classify(case["command"])
            self.assertIsNotNone(match, case["command"])
            self.assertEqual(match["rule_id"], case["rule"], case["command"])

    def test_benign_command_is_ignored(self) -> None:
        self.assertIsNone(self.analyzer.classify("systemctl status sshd"))
        self.assertIsNone(self.analyzer.classify("df -h"))
        self.assertIsNone(self.analyzer.classify("dnf makecache"))


if __name__ == "__main__":
    unittest.main()
