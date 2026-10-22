# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

---

## Educational Scope & Security Caveats

Smart Password Security Lab is an **educational heuristic evaluation tool**, not a cryptographic oracle, authentication service, or breached-password detection database.
- It does not check live breach dumps (e.g. HaveIBeenPwned API).
- High heuristic scores do not guarantee safety against targeted spearphishing, keyloggers, or offline hash cracking with custom rules.
- Reputable password managers and unique passphrases combined with Multi-Factor Authentication (MFA) represent the safest industry standard.

---

## Reporting a Security Vulnerability

If you discover a privacy leak, unexpected network transmission, DOM injection vulnerability, or security defect:
1. Please do **not** open a public issue.
2. Email the maintainer directly at security@gpsofficials.internal or submit a private security advisory through GitHub.
3. Include detailed steps to reproduce the issue. Reports are reviewed and acknowledged within 48 hours.
