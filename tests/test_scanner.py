from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.config import Settings
from agent.db import Database
from agent.scanner import VulnerabilityScanner


ROOT = Path(__file__).resolve().parents[1]


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings.from_env(
            root_dir=ROOT,
            data_dir=Path(self.temp.name),
            demo=True,
            no_auth=True,
        )
        self.db = Database(self.settings.database_path)
        self.scanner = VulnerabilityScanner(self.settings, self.db)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_every_rule_has_an_implementation(self) -> None:
        ids = {rule["id"] for rule in self.scanner.rules}
        self.assertEqual(len(ids), 30)
        self.assertEqual(ids, set(self.scanner.checkers))

    def test_demo_scan_returns_summary(self) -> None:
        findings, summary = self.scanner.scan()
        self.assertEqual(summary["checked"], 30)
        self.assertEqual(summary["total"], 5)
        self.assertEqual(len(findings), 5)
        self.assertTrue(0 <= summary["score"] <= 100)


if __name__ == "__main__":
    unittest.main()
