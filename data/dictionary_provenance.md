# Dictionary Provenance & Ethical Review Record

**Dataset:** Curated Offline Common Passwords List  
**Version:** 2.0.0  
**Review Date:** 2026-10-22  
**Scope:** Educational cybersecurity laboratory offline heuristic collection.

## 1. Provenance and Source Basis

This dictionary contains a minimal, curated selection of historically pervasive, predictable default and weak passwords frequently published in educational literature and public cybersecurity research (e.g., standard educational lists published by OWASP and NCSC guidance on common credentials).

## 2. Ethical and Privacy Review

- **No Credential Dumps:** This list is strictly synthesized from well-known public educational examples. It contains **no** compromised account credentials, unredacted breached authentication dumps, usernames, emails, or personally identifiable information (PII).
- **Public Domain / Permissive Educational Use:** Selected words represent ubiquitous English dictionary words, sequential digit keys, and canonical defaults (`admin`, `guest`, `123456`, `password`).
- **Offline & Bundled:** The dictionary is stored locally in plain text (`data/common_passwords.txt`) and statically bundled for offline use. No remote database or external lookup service is queried.

## 3. Matching Semantics

- Matching is performed **case-insensitively on the whole candidate** (`lowered == entry`).
- As per project specifications, long passphrases that happen to contain a dictionary word as a substring (e.g. `correct-horse-battery-staple`) are **not** penalized as a dictionary match.
