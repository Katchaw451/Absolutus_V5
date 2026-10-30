#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))
from pipeline import AUTH_PAT, NGINX_PAT  # noqa: E402


class TestAuthParser(unittest.TestCase):
    def test_failed_invalid_user(self):
        line = ("Oct 30 08:15:11 host sshd[1002]: Failed password for "
                "invalid user admin from 203.0.113.9 port 55120 ssh2")
        m = AUTH_PAT.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m["user"], "admin")
        self.assertEqual(m["ip"], "203.0.113.9")
        self.assertEqual(m["res"], "Failed")

    def test_accepted(self):
        line = ("Oct 30 08:14:02 host sshd[1001]: Accepted password for "
                "katchaw from 192.168.1.10 port 50122 ssh2")
        m = AUTH_PAT.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m["user"], "katchaw")

    def test_ignores_noise(self):
        self.assertIsNone(AUTH_PAT.match("random noise"))
        self.assertIsNone(AUTH_PAT.match(""))


class TestNginxParser(unittest.TestCase):
    def test_combined_format(self):
        line = ('203.0.113.9 - - [30/Oct/2026:08:14:00 +0000] '
                '"GET /admin HTTP/1.1" 404 1234 "-" "curl/7.68.0"')
        m = NGINX_PAT.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m["ip"], "203.0.113.9")
        self.assertEqual(m["status"], "404")
        self.assertEqual(m["path"], "/admin")

    def test_ignores_noise(self):
        self.assertIsNone(NGINX_PAT.match("not a log line"))


if __name__ == "__main__":
    unittest.main()
