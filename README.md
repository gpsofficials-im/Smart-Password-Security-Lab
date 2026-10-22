# Password Strength Checker

A dependency-free educational cybersecurity project with two interfaces:

- **Python CLI** (`password_strength_checker.py`) — password input is hidden in a compatible terminal.
- **Standalone browser UI** (`index.html`) — a responsive dark interface with live feedback.
- **Automated tests** (`test_password_checker.py`) — standard-library `unittest` regression coverage.

## Features

- Five transparent core criteria: length (12+ characters), uppercase, lowercase, digit, and punctuation/symbol.
- Detection of a small local list of common passwords and obvious variants.
- Warnings for sequential characters, simple keyboard walks, and long repeated-character runs.
- Passwords are not printed in the CLI report or echoed into the result UI.
- Browser logic is local-only: no external libraries, network calls, analytics, or password persistence.
- Automated tests run in GitHub Actions for Python 3.11, 3.12, and 3.13.

## Quick start on Windows

Open PowerShell in this project folder:

```powershell
python --version
python password_strength_checker.py
```

If hidden terminal input is not supported, the CLI stops rather than intentionally falling back to visible password entry. Open a normal PowerShell or Windows Terminal session and try again.

To launch the browser interface:

```powershell
start index.html
```

The web interface analyzes locally as you type. Clearing the field removes the password from the page's current input; it is not stored by this project.

## Run tests

```powershell
python -m unittest -v
```

Or:

```powershell
python test_password_checker.py
```

No third-party Python packages or JavaScript packages are required.

## How scoring works

The score is the number of passed **core criteria**, shown as `n/5`. Common-password matches are classified as **Very Weak**. A detected sequence, keyboard walk, or repeated-character run caps the displayed classification at **Weak**, even if all five core criteria pass. The warning checks do not add points to the five-point score.

The 12-character criterion is a project heuristic, not a universal account policy. Prefer long, unique passwords (15+ characters is a useful target for password-only sign-in where supported), use a password manager, avoid re-use, and enable multi-factor authentication where available.

## Security and limitations

This tool is an educational heuristic, **not a cryptographic guarantee**. It does not check breached-password databases, estimate attack cost accurately, inspect a site's password policy, or prove that a password is safe. The common-password list is intentionally small and cannot catch every weak password or mutation. Pattern checks can produce false positives or miss patterns. Do not submit a real password to any checker unless you trust its implementation; for real accounts, a reputable password manager's generator is often the safer choice.

The CLI does not print the password or any prefix/suffix in its report. The browser UI does not display password characters in the results. The show/hide button is an explicit local display choice and should be used carefully in shared spaces.

## Repository hygiene

`.gitignore` excludes Python bytecode, test caches, virtual environments, and common editor/OS files. The workflow in `.github/workflows/tests.yml` runs the standard-library regression suite on pushes and pull requests.
