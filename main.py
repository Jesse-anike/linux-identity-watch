from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def parse_passwd(text: str) -> list[dict]:
    users = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7:
            continue
        name, _password_marker, uid, gid, gecos, home, shell = fields
        try:
            uid_value, gid_value = int(uid), int(gid)
        except ValueError:
            continue
        users.append({
            "username": name,
            "uid": uid_value,
            "gid": gid_value,
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "line": line_no,
        })
    return users


def parse_shadow(text: str) -> dict[str, str]:
    entries = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        entries[fields[0]] = fields[1]
    return entries


def analyze(passwd_text: str, shadow_text: str | None = None) -> dict:
    users = parse_passwd(passwd_text)
    uid_groups = defaultdict(list)
    for user in users:
        uid_groups[user["uid"]].append(user["username"])

    findings = []
    for user in users:
        if user["uid"] == 0 and user["username"] != "root":
            findings.append({
                "type": "additional_uid_zero_account",
                "severity": "high",
                "username": user["username"],
                "detail": "Non-root account has UID 0; confirm this is intentional.",
            })

        shell = user["shell"]
        if shell and shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            findings.append({
                "type": "interactive_shell",
                "severity": "info",
                "username": user["username"],
                "detail": f"Account has an interactive shell configured: {shell}",
            })

    for uid, names in uid_groups.items():
        if len(names) > 1:
            findings.append({
                "type": "duplicate_uid",
                "severity": "review",
                "uid": uid,
                "usernames": names,
                "detail": "Multiple local account names share the same UID.",
            })

    shadow_review = []
    if shadow_text is not None:
        shadow = parse_shadow(shadow_text)
        for user in users:
            value = shadow.get(user["username"])
            if value is None:
                shadow_review.append({
                    "username": user["username"],
                    "status": "no_shadow_entry",
                    "detail": "No matching record in supplied shadow export.",
                })
            elif value == "":
                shadow_review.append({
                    "username": user["username"],
                    "status": "empty_password_field",
                    "detail": "Password field is empty; verify authentication policy immediately.",
                })
            elif value.startswith(("!", "*")):
                shadow_review.append({
                    "username": user["username"],
                    "status": "locked_or_unusable_password",
                    "detail": "Password field begins with a lock/unusable marker.",
                })

    return {
        "accounts_reviewed": len(users),
        "uid_zero_accounts": [u["username"] for u in users if u["uid"] == 0],
        "unique_uid_count": len(uid_groups),
        "findings": findings,
        "shadow_review": shadow_review,
        "note": "Read-only review. Interpret service accounts and authentication markers against the host's policy.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit Linux passwd and optional shadow exports without changing accounts."
    )
    parser.add_argument("passwd_file", help="Path to passwd-format file; use - for stdin.")
    parser.add_argument("--shadow", help="Optional shadow-format file for status review.")
    parser.add_argument("--output", help="Optional JSON report path.")
    args = parser.parse_args()

    passwd_text = sys.stdin.read() if args.passwd_file == "-" else Path(args.passwd_file).read_text(encoding="utf-8", errors="replace")
    shadow_text = Path(args.shadow).read_text(encoding="utf-8", errors="replace") if args.shadow else None
    report = analyze(passwd_text, shadow_text)
    rendered = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
