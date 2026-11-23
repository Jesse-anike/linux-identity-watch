# LINUX IDENTITY WATCH — Linux Account & Privilege Auditor

A read-only Python tool for reviewing Linux local account and group databases. It highlights UID 0 accounts other than root, accounts with interactive shells, duplicate UID values, and users without a password hash entry in the supplied shadow-file export.

## Features
- Parses local `/etc/passwd` and optional `/etc/shadow` exports.
- Identifies every UID 0 account, not only the root account.
- Reports duplicate UIDs and accounts with interactive login shells.
- Flags locked, missing, or empty password hash markers in a shadow export without displaying password hashes.
- Supports JSON reports and standard input.

## Requirements
- Python 3.10+
- Python standard library only

## Run
```bash
python main.py sample/passwd --shadow sample/shadow
```

Save a report:
```bash
python main.py /etc/passwd --shadow /etc/shadow --output identity-report.json
```

The process may require appropriate local permissions to read the shadow database. Prefer using approved exports and avoid copying real shadow-file data into source control.

## Tests
```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Safety
This is a read-only audit. It does not create, modify, disable, or delete accounts; change passwords; or alter group membership. Findings require review against the host's intended service accounts and identity-management policy.

## Portfolio context
Built for Anike-Moses Melie Jesse's defensive cybersecurity portfolio, demonstrating Linux identity management, UID/GID review, authentication configuration awareness, Python parsing, and structured security reporting.
