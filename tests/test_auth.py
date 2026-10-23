from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.auth import AuthManager


class AuthTests(unittest.TestCase):
    def test_password_and_signed_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            auth = AuthManager(
                root / "admin.passwd",
                root / "session.secret",
                root / "initial-password.txt",
            )
            auth.set_password("correct-horse-battery")
            self.assertTrue(auth.verify_password("correct-horse-battery"))
            self.assertFalse(auth.verify_password("wrong-password"))
            token = auth.issue_session()
            self.assertTrue(auth.verify_session(token))
            self.assertFalse(auth.verify_session(token + "tampered"))

    def test_short_password_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            auth = AuthManager(
                root / "admin.passwd",
                root / "session.secret",
                root / "initial-password.txt",
            )
            with self.assertRaises(ValueError):
                auth.set_password("short")


if __name__ == "__main__":
    unittest.main()
