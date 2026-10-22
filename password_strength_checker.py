"""Password Strength Checker - secure, dependency-free CLI implementation.

This educational checker evaluates basic password characteristics and flags
several predictable patterns. It does not contact a server, save passwords,
or replace breached-password screening or a dedicated password-strength meter.
"""

from __future__ import annotations

import getpass
import re
import warnings
from typing import Any

MIN_PASSWORD_LENGTH = 12
RECOMMENDED_PASSWORD_LENGTH = 15

COMMON_PASSWORDS = frozenset(
    {
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "sunshine",
        "master", "welcome", "shadow", "ashley", "football",
        "jesus", "michael", "ninja", "mustang", "password1",
        "password123", "admin", "letmein", "monkey", "access",
        "hello", "charlie", "donald", "princess", "qwerty123",
        "admin123", "root", "toor", "pass", "test", "guest",
        "master123", "changeme", "orange", "secret", "123qwe",
        "zxcvbn", "1234567890", "password12", "login",
    }
)

# Common roots plus short numeric suffixes are frequent, predictable variants.
_COMMON_BASES = (
    "password", "admin", "qwerty", "welcome", "letmein", "iloveyou",
    "monkey", "dragon", "login", "changeme", "master", "guest",
)
_KEYBOARD_PATTERNS = ("qwerty", "asdf", "zxcv", "qwer", "wasd", "1qaz", "zaq1")


def check_length(password: str) -> bool:
    """Return whether the password reaches the project's 12-character target."""
    return len(password) >= MIN_PASSWORD_LENGTH


def check_uppercase(password: str) -> bool:
    """Return whether the password contains an ASCII uppercase letter."""
    return bool(re.search(r"[A-Z]", password))


def check_lowercase(password: str) -> bool:
    """Return whether the password contains an ASCII lowercase letter."""
    return bool(re.search(r"[a-z]", password))


def check_numbers(password: str) -> bool:
    """Return whether the password contains an ASCII digit."""
    return bool(re.search(r"[0-9]", password))


def check_special_characters(password: str) -> bool:
    """Return whether the password contains punctuation or a symbol (not whitespace)."""
    return bool(re.search(r"[^A-Za-z0-9\s]", password))


def check_common_passwords(password: str) -> bool:
    """Flag common passwords and obvious punctuation/case/numeric variants."""
    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS:
        return True

    # Removing separators catches forms such as "Password!" and "pass-word".
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if compact in COMMON_PASSWORDS:
        return True

    # Also catch a small, common set of leetspeak substitutions (e.g. P@ssw0rd).
    leet_text = lowered.translate(str.maketrans({"@": "a", "$": "s", "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}))
    leet_compact = re.sub(r"[^a-z0-9]", "", leet_text)
    if leet_compact in COMMON_PASSWORDS:
        return True

    candidates = (compact, leet_compact)
    return any(
        re.fullmatch(re.escape(root) + r"[0-9]{0,4}", candidate)
        for candidate in candidates
        for root in _COMMON_BASES
    )


def check_sequential_patterns(password: str, minimum_run: int = 4) -> bool:
    """Detect ascending/descending runs such as abcd, 1234, or 9876."""
    compact = re.sub(r"[^a-z0-9]", "", password.casefold())
    if len(compact) < minimum_run:
        return False

    run_length = 1
    previous_delta = 0
    for index in range(1, len(compact)):
        previous, current = compact[index - 1], compact[index]
        same_type = (previous.isalpha() and current.isalpha()) or (previous.isdigit() and current.isdigit())
        delta = ord(current) - ord(previous) if same_type else 0
        if same_type and delta in (-1, 1) and (previous_delta == 0 or delta == previous_delta):
            run_length += 1
        else:
            run_length = 1
        previous_delta = delta if same_type and delta in (-1, 1) else 0
        if run_length >= minimum_run:
            return True
    return False


def check_repeated_characters(password: str, minimum_run: int = 4) -> bool:
    """Detect a character repeated four or more times consecutively."""
    return bool(re.search(rf"(.)\1{{{minimum_run - 1},}}", password, flags=re.DOTALL))


def check_keyboard_patterns(password: str) -> bool:
    """Detect common keyboard walks independent of letter case and separators."""
    compact = re.sub(r"[^a-z0-9]", "", password.casefold())
    return any(pattern in compact for pattern in _KEYBOARD_PATTERNS)


def analyze_password(password: str) -> dict[str, bool]:
    """Return the core checks plus warnings for common and predictable patterns.

    The password is not trimmed or otherwise changed: whitespace can be part of
    a user's password and must not be silently removed by a checker.
    """
    sequential = check_sequential_patterns(password)
    repeated = check_repeated_characters(password)
    keyboard = check_keyboard_patterns(password)
    return {
        "length": check_length(password),
        "uppercase": check_uppercase(password),
        "lowercase": check_lowercase(password),
        "numbers": check_numbers(password),
        "special": check_special_characters(password),
        "common": check_common_passwords(password),
        "sequence": sequential,
        "repeated": repeated,
        "keyboard": keyboard,
        "predictable": sequential or repeated or keyboard,
    }


def calculate_strength_score(results: dict[str, Any]) -> tuple[str, int]:
    """Return (classification, core_score) using five visible core criteria.

    Common passwords are always Very Weak. Predictable sequences/repetition or
    keyboard walks cap the classification at Weak even if all core checks pass.
    The numeric score remains the count of the five core criteria; warning checks
    affect the classification, not the displayed denominator.
    """
    core_keys = ("length", "uppercase", "lowercase", "numbers", "special")
    score = sum(bool(results.get(key, False)) for key in core_keys)

    if results.get("common", False) or score <= 2:
        strength = "Very Weak"
    elif results.get("predictable", False):
        strength = "Weak"
    elif score == 3:
        strength = "Weak"
    elif score == 4:
        strength = "Medium"
    else:
        strength = "Strong"
    return strength, score


def display_analysis_report(password: str, results: dict[str, Any], strength: str, score: int) -> None:
    """Print an analysis report without revealing any part of the password."""
    print("\n" + "=" * 64)
    print("                 PASSWORD STRENGTH REPORT")
    print("=" * 64)
    print("\nPassword analyzed: [hidden for privacy]")
    print("\n--- Core checks (5-point score) ---")
    core_checks = (
        ("Minimum 12 characters", "length"),
        ("Uppercase letter (A-Z)", "uppercase"),
        ("Lowercase letter (a-z)", "lowercase"),
        ("At least one digit (0-9)", "numbers"),
        ("Punctuation or symbol", "special"),
    )
    for label, key in core_checks:
        print(f"  [{'PASS' if results.get(key, False) else 'FAIL'}] {label}")

    print(f"  [{'FAIL' if results.get('common', False) else 'PASS'}] Not a common password")
    print(f"  [{'WARN' if results.get('predictable', False) else 'PASS'}] No obvious sequence, keyboard walk, or repeated-character pattern")
    print("\n--- Assessment ---")
    print(f"  Strength: {strength}")
    print(f"  Core score: {score}/5 criteria")
    print("  Note: This is a heuristic educational assessment, not a guarantee of security.")
    print("=" * 64)


def display_suggestions(results: dict[str, Any], strength: str) -> None:
    """Print practical, non-invasive advice based on the analysis."""
    suggestions: list[str] = []
    if not results.get("length", False):
        suggestions.append(f"Use at least {MIN_PASSWORD_LENGTH} characters; 15+ is a better target for a password-only login.")
    if not results.get("uppercase", False):
        suggestions.append("Consider mixing uppercase and lowercase letters if the service allows it.")
    if not results.get("lowercase", False):
        suggestions.append("Consider including lowercase letters if the service allows it.")
    if not results.get("numbers", False):
        suggestions.append("Consider including a digit if the service allows it.")
    if not results.get("special", False):
        suggestions.append("Consider punctuation or symbols if the service allows them.")
    if results.get("common", False):
        suggestions.append("This resembles a common password or variant; choose a completely different one.")
    if results.get("predictable", False):
        suggestions.append("Avoid alphabetic/numeric runs, keyboard walks, and repeated characters.")

    if not suggestions and strength in ("Strong", "Medium"):
        print("\nAdvice: Use a unique password for every account and store it in a reputable password manager.")
        print("A long, randomly generated password or passphrase is generally preferable to predictable substitutions.")
        return

    print("\nSuggestions:")
    for suggestion in suggestions:
        print(f"  - {suggestion}")
    print("  - Never reuse a password across important accounts.")
    print("  - Prefer a password manager and a long, unique passphrase.")


def get_user_password() -> str | None:
    """Read password input without echoing it to the terminal."""
    print("\n" + "=" * 64)
    print("                 PASSWORD STRENGTH CHECKER")
    print("  Local-only educational tool — no network calls or password storage")
    print("=" * 64)
    try:
        # Turn getpass's echo-fallback warning into an error rather than allowing
        # a password to be typed visibly in terminals that cannot hide input.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("\nEnter a password to analyze (input hidden): ")
    except getpass.GetPassWarning:
        print("\nSecure hidden input is unavailable in this terminal. Open a real terminal and try again.")
        return None
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None


def main() -> None:
    """Run the CLI checker."""
    password = get_user_password()
    if password is None:
        return
    if password == "":
        print("\nNo password entered. Exiting without analysis.")
        return

    results = analyze_password(password)
    strength, score = calculate_strength_score(results)
    display_analysis_report(password, results, strength, score)
    display_suggestions(results, strength)
    print("\nReminder: do not enter a real password into tools you do not trust.\n")


if __name__ == "__main__":
    main()
