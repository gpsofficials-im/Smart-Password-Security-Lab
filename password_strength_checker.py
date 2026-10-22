"""Smart Password Security Lab - CLI Application & Compatibility Layer.

This module provides the command-line interface for Smart Password Security Lab,
supporting optional custom dictionary loading (--dictionary PATH) and
allowlisted JSON report export (--json-out PATH).
It also maintains full backward compatibility for legacy public check functions.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import warnings
from typing import Any

import password_analyzer as core

MIN_PASSWORD_LENGTH = 12
RECOMMENDED_PASSWORD_LENGTH = 15

# Exported for backward compatibility
COMMON_PASSWORDS = core.DEFAULT_BUNDLED_PASSWORDS
_COMMON_BASES = core.COMMON_BASES
_KEYBOARD_PATTERNS = core.KEYBOARD_WALK_PATTERNS


def check_length(password: str) -> bool:
    """Return whether the password reaches the 12-character target."""
    return core.count_code_points(password) >= MIN_PASSWORD_LENGTH


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
    """Flag common passwords and predictable transformations."""
    lowered = password.casefold()
    if lowered in core._BUNDLED_PASSWORDS:
        return True
    return core.detect_common_variant(password, core._BUNDLED_PASSWORDS)


def check_sequential_patterns(password: str, minimum_run: int = 4) -> bool:
    """Detect ascending/descending alphanumeric runs."""
    return core.detect_sequences(password, minimum_run=minimum_run) > 0


def check_repeated_characters(password: str, minimum_run: int = 4) -> bool:
    """Detect a character repeated four or more times consecutively."""
    return core.detect_repeated_runs(password, minimum_run=minimum_run)


def check_keyboard_patterns(password: str) -> bool:
    """Detect common keyboard walks in QWERTY layout."""
    return core.detect_keyboard_walks(password)


def analyze_password(password: str, custom_dict: frozenset[str] | None = None) -> dict[str, Any]:
    """Analyze password and return structured results with backward-compatible fields.

    Contains both legacy 5-point fields and v2.0 structured analysis data.
    Never stores or prints the password.
    """
    v2_result = core.analyze_password(password, custom_dict=custom_dict)

    length_pass = check_length(password)
    upper_pass = check_uppercase(password)
    lower_pass = check_lowercase(password)
    nums_pass = check_numbers(password)
    special_pass = check_special_characters(password)

    seq_pass = check_sequential_patterns(password)
    repeat_pass = check_repeated_characters(password)
    keyboard_pass = check_keyboard_patterns(password)
    common_pass = (password.casefold() in core._BUNDLED_PASSWORDS) or core.detect_common_variant(password, core._BUNDLED_PASSWORDS)
    if custom_dict and password.casefold() in custom_dict:
        common_pass = True

    predictable = seq_pass or repeat_pass or keyboard_pass

    # Merge legacy keys into result
    v2_result["length"] = length_pass
    v2_result["uppercase"] = upper_pass
    v2_result["lowercase"] = lower_pass
    v2_result["numbers"] = nums_pass
    v2_result["special"] = special_pass
    v2_result["common"] = common_pass
    v2_result["sequence"] = seq_pass
    v2_result["repeated"] = repeat_pass
    v2_result["keyboard"] = keyboard_pass
    v2_result["predictable"] = predictable

    return v2_result


def calculate_strength_score(results: dict[str, Any]) -> tuple[str, int]:
    """Return (classification, core_score) using visible core criteria.

    Compatible with legacy test assertions while integrating v2 classification.
    """
    core_keys = ("length", "uppercase", "lowercase", "numbers", "special")
    legacy_score = sum(bool(results.get(key, False)) for key in core_keys)

    if results.get("common", False) or legacy_score <= 2:
        strength = "Very Weak"
    elif results.get("predictable", False):
        strength = "Weak"
    elif legacy_score == 3:
        strength = "Weak"
    elif legacy_score == 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, legacy_score


def display_analysis_report(
    password: str,
    results: dict[str, Any],
    strength: str,
    score: int,
) -> None:
    """Print an analysis report without revealing any part of the candidate password."""
    score_100 = results.get("score", 0)
    classification_v2 = results.get("classification", strength)

    print("\n" + "=" * 68)
    print("            SMART PASSWORD SECURITY LAB — ANALYSIS REPORT")
    print("=" * 68)
    print("\nCandidate analyzed: [hidden for privacy]")
    print(f"Unicode code points: {results.get('length_code_points', len(password))}")
    print(f"Length guidance: {results.get('length_guidance', 'N/A')}")

    print("\n--- Core Composition Checks (5-point legacy score) ---")
    core_checks = (
        ("Minimum 12 characters", "length"),
        ("Uppercase letter (A-Z)", "uppercase"),
        ("Lowercase letter (a-z)", "lowercase"),
        ("At least one digit (0-9)", "numbers"),
        ("Punctuation or symbol", "special"),
    )
    for label, key in core_checks:
        status = "PASS" if results.get(key, False) else "FAIL"
        print(f"  [{status}] {label}")

    print(f"  [{'FAIL' if results.get('common', False) else 'PASS'}] Not in common passwords or variant")
    print(f"  [{'WARN' if results.get('predictable', False) else 'PASS'}] No predictable sequence, walk, or repeat")

    # Theoretical Entropy Section
    entropy_info = results.get("entropy_estimate", {})
    if entropy_info.get("status") == "CALCULATED":
        print("\n--- Theoretical Upper-Bound Entropy ---")
        print(f"  Estimated bit strength: ~{entropy_info.get('bits')} bits (Pool: {entropy_info.get('pool_size')} chars)")
        print("  Caveat: Assumes uniform random selection. Not human password entropy.")
    elif entropy_info.get("warning") == "ENTROPY_UNCALIBRATED_UNICODE":
        print("\n--- Theoretical Entropy ---")
        print("  Notice: Uncalibrated for non-ASCII characters; score weights renormalized.")

    # Patterns and Penalties
    penalties = results.get("pattern_penalties", [])
    if penalties:
        print("\n--- Pattern Findings & Penalties ---")
        for item in penalties:
            print(f"  - [{item.get('rule_id')}]: -{item.get('penalty')} pts ({item.get('description')})")

    print("\n--- Overall Assessment ---")
    print(f"  Classification: {classification_v2}")
    print(f"  Heuristic Score: {score_100}/100")
    print(f"  Core score: {score}/5 criteria")
    print("  Notice: Heuristic educational model — does not replace breached-password checking.")
    print("=" * 68)


def display_suggestions(results: dict[str, Any], strength: str) -> None:
    """Print practical, security-conscious recommendations based on findings."""
    warnings_list = results.get("warnings", [])
    recommendations = results.get("recommendation_ids", [])

    print("\n--- Security Advice & Recommendations ---")
    if warnings_list:
        for w in warnings_list:
            print(f"  [{w.get('severity', 'info').upper()}] {w.get('message')}")

    rec_descriptions = {
        "REC_INCREASE_LENGTH": "Increase password length to at least 12 characters (15+ for critical accounts).",
        "REC_CONSIDER_15_PLUS": "Consider reaching 15+ characters or adopting a multi-word passphrase.",
        "REC_CHOOSE_UNRELATED_PHRASE": "Avoid common dictionary words or predictable variants; use distinct words.",
        "REC_REMOVE_SEQUENCES": "Eliminate sequential characters (e.g. 1234, abcd) across keys.",
        "REC_REMOVE_REPEATS": "Avoid repeating identical characters consecutively.",
        "REC_REMOVE_KEYBOARD_WALK": "Avoid adjacent keyboard patterns (e.g. qwerty, asdf).",
        "REC_REMOVE_YEAR": "Avoid appending four-digit year numbers to base words.",
        "REC_DIVERSIFY_CASING": "Mix uppercase and lowercase characters where supported.",
        "REC_INCLUDE_DIGITS": "Include digits in unpredictable positions.",
        "REC_INCLUDE_SYMBOLS": "Include punctuation or symbols where supported.",
        "REC_USE_PASSWORD_MANAGER": "Store long, unique passwords in a reputable password manager.",
    }

    if recommendations:
        for rid in recommendations:
            if rid in rec_descriptions:
                print(f"  * {rec_descriptions[rid]}")
    else:
        print("  * Maintain unique passwords across all accounts and use a trusted password manager.")
    print("  * Enable multi-factor authentication (MFA/2FA) wherever available.\n")


def get_user_password() -> str | None:
    """Read password input without echoing to terminal or logging."""
    print("\n" + "=" * 68)
    print("                 SMART PASSWORD SECURITY LAB")
    print("   Privacy-first educational tool — zero network, zero persistence")
    print("=" * 68)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("\nEnter a password to analyze (input hidden): ")
    except getpass.GetPassWarning:
        print("\nSecure hidden input is unavailable in this terminal. Open a standard terminal session.")
        return None
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None


def main() -> None:
    """Parse CLI arguments, load optional dictionaries, and run analysis."""
    parser = argparse.ArgumentParser(
        description="Smart Password Security Lab — Privacy-First Password Analysis CLI",
        epilog="Educational tool only. Does not replace breached-password database checks.",
    )
    parser.add_argument(
        "--dictionary",
        dest="dictionary_path",
        help="Path to an optional custom dictionary file (.txt, max 1 MiB, max 10,000 entries).",
    )
    parser.add_argument(
        "--json-out",
        dest="json_out_path",
        help="Path to write a sanitized, password-free JSON analysis report.",
    )

    args = parser.parse_args()

    custom_dict: frozenset[str] | None = None
    if args.dictionary_path:
        try:
            custom_dict = core.load_custom_dictionary(args.dictionary_path)
            print(f"Loaded custom dictionary with {len(custom_dict)} unique entries.")
        except Exception as err:
            print(f"Error loading custom dictionary: {err}", file=sys.stderr)
            sys.exit(1)

    password = get_user_password()
    if password is None:
        return
    if password == "":
        print("\nNo password entered. Exiting without analysis.")
        return

    results = analyze_password(password, custom_dict=custom_dict)
    strength, score = calculate_strength_score(results)

    display_analysis_report(password, results, strength, score)
    display_suggestions(results, strength)

    if args.json_out_path:
        try:
            export_data = core.generate_allowlisted_export(results)
            with open(args.json_out_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            print(f"Sanitized password-free report exported to: {args.json_out_path}\n")
        except Exception as err:
            print(f"Error writing JSON export: {err}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
