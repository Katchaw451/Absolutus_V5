#!/usr/bin/env python3
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
from pipeline import PAT  # noqa: E402

class TestParser(unittest.TestCase):
    def test_failed_invalid_user(self):
        line = ("Oct 30 08:15:11 host sshd[1002]: Failed password for "
                "invalid user admin from 203.0.113.9 port 55120 ssh2")
        m = PAT.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m["user"], "admin")
        self.assertEqual(m["ip"], "203.0.113.9")
        self.assertEqual(m["res"], "Failed")

    def test_accepted(self):
        line = ("Oct 30 08:14:02 host sshd[1001]: Accepted password for "
                "katchaw from 192.168.1.10 port 50122 ssh2")
        m = PAT.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m["user"], "katchaw")
        self.assertEqual(m["res"], "Accepted")

    def test_ignores_noise(self):
        self.assertIsNone(PAT.match("random noise"))
        self.assertIsNone(PAT.match(""))

if __name__ == "__main__":
    unittest.main()
