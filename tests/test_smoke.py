import unittest
from main import analyze, parse_passwd


PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
analyst:x:1000:1000:Analyst:/home/analyst:/bin/bash
legacy:x:0:1002:Legacy:/home/legacy:/bin/bash
duplicate:x:1000:1003:Duplicate:/home/duplicate:/bin/false
"""


class LinuxIdentityWatchTests(unittest.TestCase):
    def test_finds_non_root_uid_zero(self):
        report = analyze(PASSWD)
        self.assertIn("legacy", report["uid_zero_accounts"])
        types = {item["type"] for item in report["findings"]}
        self.assertIn("additional_uid_zero_account", types)

    def test_detects_duplicate_uids(self):
        report = analyze(PASSWD)
        duplicates = [item for item in report["findings"] if item["type"] == "duplicate_uid"]
        self.assertTrue(any(item["uid"] == 1000 for item in duplicates))

    def test_shadow_markers_are_summarized_not_exposed(self):
        shadow = "root:!:1:::::\nanalyst:$6$not-a-real-hash:1:::::\n"
        report = analyze(PASSWD, shadow)
        self.assertTrue(any(item["username"] == "root" and item["status"] == "locked_or_unusable_password" for item in report["shadow_review"]))
        self.assertNotIn("not-a-real-hash", str(report))

    def test_passwd_parser_ignores_malformed_lines(self):
        users = parse_passwd("bad:line\nvalid:x:1000:1000:User:/home/user:/bin/bash")
        self.assertEqual(len(users), 1)


if __name__ == "__main__":
    unittest.main()
