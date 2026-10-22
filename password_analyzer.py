"""Smart Password Security Lab - Pure Analysis Engine.

This module provides an explainable, pure heuristic scoring and pattern
detection engine without any terminal I/O, file writing, or network calls.
It evaluates length, character pool entropy, pattern rules, and dictionary
matches against a centrally defined specification (security_spec.json).
"""

from __future__ import annotations

import math
import os
import re
from typing import Any

ANALYSIS_VERSION = "2.0.0"

# Fallback bundled common passwords in case data/common_passwords.txt is unavailable
DEFAULT_BUNDLED_PASSWORDS = frozenset({
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow",
    "ashley", "football", "jesus", "michael", "ninja", "mustang",
    "password1", "password123", "admin", "letmein", "monkey", "access",
    "hello", "charlie", "donald", "princess", "qwerty123", "admin123",
    "root", "toor", "pass", "test", "guest", "master123", "changeme",
    "orange", "secret", "123qwe", "zxcvbn", "1234567890", "password12",
    "login", "welcome1", "qwertyuiop", "testing123", "superman", "batman",
    "administrator", "passcode", "default", "operator", "service",
})

COMMON_BASES = (
    "password", "admin", "qwerty", "welcome", "letmein", "iloveyou",
    "monkey", "dragon", "login", "changeme", "master", "guest",
    "football", "baseball", "superman", "batman", "shadow", "sunshine",
    "access", "testing", "default", "orange", "secret", "charlie",
)

KEYBOARD_WALK_PATTERNS = (
    # QWERTY horizontal rows (forward and reverse)
    "qwertyuiop", "poiuytrewq",
    "asdfghjkl", "lkjhgfdsa",
    "zxcvbnm", "mnbvcxz",
    "1234567890", "0987654321",
    # Vertical/diagonal column walks
    "1qaz", "zaq1",
    "2wsx", "xsw2",
    "3edc", "cde3",
    "4rfv", "vfr4",
    "5tgb", "bgt5",
    "6yhn", "nhy6",
    "7ujm", "mju7",
    "8ik,", ",ki8",
    "9ol.", ".lo9",
    # Keypad and gaming clusters
    "wasd", "dsaw",
    "qwer", "rewq",
)

LEET_TABLE = str.maketrans({
    "@": "a",
    "$": "s",
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})

# Defensive dictionary limits
MAX_DICTIONARY_FILE_SIZE = 1024 * 1024  # 1 MiB
MAX_DICTIONARY_ENTRIES = 10000
MAX_DICTIONARY_ENTRY_LENGTH = 256


def load_bundled_dictionary() -> frozenset[str]:
    """Load bundled common passwords from data/common_passwords.txt if present."""
    data_path = os.path.join(os.path.dirname(__file__), "data", "common_passwords.txt")
    if os.path.isfile(data_path):
        try:
            with open(data_path, "r", encoding="utf-8", errors="replace") as f:
                entries = {
                    line.strip().casefold()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                }
                if entries:
                    return frozenset(entries)
        except Exception:
            pass
    return DEFAULT_BUNDLED_PASSWORDS


def load_custom_dictionary(path_or_content: str, is_content: bool = False) -> frozenset[str]:
    """Safely load and validate a custom dictionary with strict resource limits.

    Raises:
        ValueError: If file size exceeds 1 MiB or entry count exceeds 10,000.
    """
    if is_content:
        content = path_or_content
        if len(content.encode("utf-8")) > MAX_DICTIONARY_FILE_SIZE:
            raise ValueError("Custom dictionary exceeds maximum size limit (1 MiB).")
        lines = content.splitlines()
    else:
        if not os.path.isfile(path_or_content):
            raise ValueError("Custom dictionary file not found.")
        file_size = os.path.getsize(path_or_content)
        if file_size > MAX_DICTIONARY_FILE_SIZE:
            raise ValueError("Custom dictionary exceeds maximum size limit (1 MiB).")
        with open(path_or_content, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

    entries: set[str] = set()
    for line in lines:
        cleaned = line.strip().casefold()
        if not cleaned or cleaned.startswith("#"):
            continue
        if len(cleaned) <= MAX_DICTIONARY_ENTRY_LENGTH:
            entries.add(cleaned)
        if len(entries) > MAX_DICTIONARY_ENTRIES:
            raise ValueError(f"Custom dictionary exceeds maximum limit of {MAX_DICTIONARY_ENTRIES} entries.")

    return frozenset(entries)


# Bundled instance cached in memory
_BUNDLED_PASSWORDS = load_bundled_dictionary()


def count_code_points(text: str) -> int:
    """Return the number of Unicode code points in the candidate."""
    return len(text)


def detect_sequences(password: str, minimum_run: int = 4) -> int:
    """Count distinct, non-overlapping ascending/descending alphanumeric runs.

    Runs of length >= minimum_run in alphanumeric characters are detected.
    Example: 'abcd', '1234', '9876', 'dcba'.
    """
    compact = re.sub(r"[^a-zA-Z0-9]", "", password).casefold()
    if len(compact) < minimum_run:
        return 0

    runs_found = 0
    i = 0
    while i < len(compact):
        run_len = 1
        delta = 0
        j = i + 1
        while j < len(compact):
            prev, curr = compact[j - 1], compact[j]
            same_type = (prev.isalpha() and curr.isalpha()) or (prev.isdigit() and curr.isdigit())
            if not same_type:
                break
            d = ord(curr) - ord(prev)
            if d in (-1, 1):
                if run_len == 1:
                    delta = d
                    run_len += 1
                elif d == delta:
                    run_len += 1
                else:
                    break
            else:
                break
            j += 1

        if run_len >= minimum_run:
            runs_found += 1
            i += run_len
        else:
            i += 1

    return runs_found


def detect_repeated_runs(password: str, minimum_run: int = 4) -> bool:
    """Return True if any character repeats consecutively for minimum_run times."""
    return bool(re.search(rf"(.)\1{{{minimum_run - 1},}}", password, flags=re.DOTALL))


def detect_keyboard_walks(password: str, minimum_run: int = 4) -> bool:
    """Return True if any 4+ character QWERTY keyboard walk is present."""
    compact = re.sub(r"[^a-zA-Z0-9]", "", password).casefold()
    if len(compact) < minimum_run:
        return False

    for walk in KEYBOARD_WALK_PATTERNS:
        # Check all slices of length minimum_run in the keyboard pattern
        for k in range(len(walk) - minimum_run + 1):
            sub = walk[k:k + minimum_run]
            if sub in compact:
                return True
    return False


def detect_year_suffix(password: str) -> bool:
    """Detect a 4-digit year suffix (1900-2099) after a common base word."""
    lowered = password.casefold()
    # Check word + year pattern
    m = re.search(r"^([a-z]{3,})(19\d{2}|20\d{2})$", lowered)
    if m:
        base, _ = m.groups()
        if base in COMMON_BASES or base in _BUNDLED_PASSWORDS:
            return True
    return False


def detect_common_variant(password: str, bundled_dict: frozenset[str] = _BUNDLED_PASSWORDS) -> bool:
    """Detect predictable variants of common passwords (leetspeak, compact, 1-4 trailing digits)."""
    lowered = password.casefold()
    if lowered in bundled_dict:
        return True

    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if compact in bundled_dict:
        return True

    # Leetspeak translation
    leet_compact = re.sub(r"[^a-z0-9]", "", lowered.translate(LEET_TABLE))
    if leet_compact in bundled_dict:
        return True

    candidates = (compact, leet_compact)
    for cand in candidates:
        for root in COMMON_BASES:
            if re.fullmatch(re.escape(root) + r"[0-9]{1,4}", cand):
                return True
            if cand == root:
                return True

    return False


def calculate_entropy(password: str) -> dict[str, Any]:
    """Calculate theoretical upper-bound Shannon entropy for ASCII characters.

    H = length * log2(pool_size)
    E = min(100, H / 80 * 100)
    For non-ASCII candidates, returns status 'UNAVAILABLE_NON_ASCII'.
    """
    length = count_code_points(password)
    if length == 0:
        return {
            "bits": 0.0,
            "pool_size": 0,
            "normalized_score": 0.0,
            "status": "CALCULATED",
            "warning": None,
            "disclaimer": "Theoretical upper-bound based on uniform random selection.",
        }

    # Verify ASCII
    is_ascii = all(ord(c) < 128 for c in password)
    if not is_ascii:
        return {
            "bits": None,
            "pool_size": None,
            "normalized_score": None,
            "status": "UNAVAILABLE_NON_ASCII",
            "warning": "ENTROPY_UNCALIBRATED_UNICODE",
            "disclaimer": "Entropy calculation uncalibrated for non-ASCII Unicode code points.",
        }

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    # Printable ASCII punctuation (32 characters)
    if re.search(r"[!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]", password):
        pool_size += 32
    if " " in password:
        pool_size += 1

    if pool_size <= 1:
        bits = 0.0
    else:
        bits = round(length * math.log2(pool_size), 2)

    normalized_score = min(100.0, round((bits / 80.0) * 100.0, 2))

    return {
        "bits": bits,
        "pool_size": pool_size,
        "normalized_score": normalized_score,
        "status": "CALCULATED",
        "warning": None,
        "disclaimer": "Theoretical upper-bound assuming uniform random selection over character pool.",
    }


def analyze_password(
    password: str,
    custom_dict: frozenset[str] | None = None,
    bundled_dict: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Perform explainable hybrid security analysis and return a structured contract.

    Guarantees:
    - Never echoes, trims, or stores the original candidate.
    - Result contains zero secret-derived substrings or hashes.
    """
    if bundled_dict is None:
        bundled_dict = _BUNDLED_PASSWORDS

    length = count_code_points(password)
    lowered = password.casefold()

    # Core character composition
    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_digits = bool(re.search(r"[0-9]", password))
    has_symbols = bool(re.search(r"[^A-Za-z0-9\s]", password))
    length_target_met = length >= 12

    # Length guidance
    if length == 0:
        length_guidance = "Empty password"
    elif length < 8:
        length_guidance = f"Critically short ({length} code points; minimum 12 recommended)"
    elif length < 12:
        length_guidance = f"Below minimum recommendation ({length}/12 code points)"
    elif length < 15:
        length_guidance = f"Meets basic length target ({length}/12 code points); 15+ recommended for passphrases"
    else:
        length_guidance = f"Meets robust length target ({length} code points)"

    # Dictionary checks (exact whole-word matching)
    is_bundled_exact = (lowered in bundled_dict) if length > 0 else False
    is_custom_exact = (custom_dict is not None and lowered in custom_dict) if length > 0 else False

    # Pattern detectors
    sequence_count = detect_sequences(password) if length >= 4 else 0
    repeated_run = detect_repeated_runs(password) if length >= 4 else False
    keyboard_walk = detect_keyboard_walks(password) if length >= 4 else False
    year_suffix = detect_year_suffix(password) if length >= 5 else False
    common_variant = detect_common_variant(password, bundled_dict) if (length > 0 and not is_bundled_exact) else False

    # Build penalties
    pattern_penalties: list[dict[str, Any]] = []
    total_penalty = 0

    if sequence_count > 0:
        penalty = min(35, sequence_count * 25)
        pattern_penalties.append({
            "rule_id": "PATTERN_ASCENDING_SEQUENCE",
            "penalty": penalty,
            "description": f"Detected {sequence_count} sequential alphanumeric run(s) of 4+ characters."
        })
        total_penalty += penalty

    if repeated_run:
        pattern_penalties.append({
            "rule_id": "PATTERN_REPEATED_RUN",
            "penalty": 20,
            "description": "Detected 4 or more identical consecutive characters."
        })
        total_penalty += 20

    if keyboard_walk:
        pattern_penalties.append({
            "rule_id": "PATTERN_KEYBOARD_WALK",
            "penalty": 25,
            "description": "Detected 4 or more contiguous keys in a standard QWERTY keyboard walk."
        })
        total_penalty += 25

    if year_suffix:
        pattern_penalties.append({
            "rule_id": "PATTERN_YEAR_SUFFIX",
            "penalty": 10,
            "description": "Detected predictable four-digit year suffix (1900-2099) following a common base."
        })
        total_penalty += 10

    if common_variant:
        pattern_penalties.append({
            "rule_id": "PATTERN_COMMON_VARIANT",
            "penalty": 25,
            "description": "Resembles a common predictable password variant or substitution."
        })
        total_penalty += 25

    if is_bundled_exact:
        pattern_penalties.append({
            "rule_id": "DICT_BUNDLED_EXACT",
            "penalty": 90,
            "description": "Exact match against offline bundled common passwords list."
        })
        total_penalty += 90

    if is_custom_exact:
        pattern_penalties.append({
            "rule_id": "DICT_CUSTOM_EXACT",
            "penalty": 90,
            "description": "Exact match against user-provided custom dictionary."
        })
        total_penalty += 90

    # Components
    # L = min(100, 5 * length)
    length_component = min(100, 5 * length)

    # Entropy component
    entropy_info = calculate_entropy(password)

    # Pattern component P = max(0, 100 - total_penalty)
    pattern_component = max(0, 100 - total_penalty)

    # Base score
    if length == 0:
        base_score = 0
    elif entropy_info["status"] == "CALCULATED" and entropy_info["normalized_score"] is not None:
        e_score = entropy_info["normalized_score"]
        base_score = round(0.55 * length_component + 0.15 * e_score + 0.30 * pattern_component)
    else:
        # Non-ASCII or uncalibrated entropy: renormalize length (0.55) + pattern (0.30) / 0.85
        base_score = round((0.55 * length_component + 0.30 * pattern_component) / 0.85)

    base_score = max(0, min(100, base_score))

    # Apply severity caps in order
    score = base_score
    applied_cap: int | None = None

    if is_bundled_exact or is_custom_exact:
        applied_cap = 9
    elif common_variant:
        applied_cap = 29
    elif length < 8:
        applied_cap = 19
    elif length < 12:
        applied_cap = 49
    elif length < 15:
        applied_cap = 69

    if applied_cap is not None:
        score = min(score, applied_cap)

    # Map to classification bands:
    # 0–19: Very Weak
    # 20–39: Weak
    # 40–59: Moderate
    # 60–79: Strong
    # 80–100: Very Strong
    if score <= 19:
        classification = "Very Weak"
    elif score <= 39:
        classification = "Weak"
    elif score <= 59:
        classification = "Moderate"
    elif score <= 79:
        classification = "Strong"
    else:
        classification = "Very Strong"

    # Strict cap rule: common_variant cannot exceed Weak
    if common_variant and classification in ("Moderate", "Strong", "Very Strong"):
        classification = "Weak"

    # Warnings collection
    warnings: list[dict[str, Any]] = []
    if is_bundled_exact:
        warnings.append({
            "id": "WARN_COMMON_PASSWORD",
            "severity": "critical",
            "message": "This password appears verbatim in standard lists of common credentials."
        })
    if is_custom_exact:
        warnings.append({
            "id": "WARN_CUSTOM_DICTIONARY_MATCH",
            "severity": "critical",
            "message": "This password matches an entry in your specified custom dictionary."
        })
    if common_variant:
        warnings.append({
            "id": "WARN_COMMON_VARIANT",
            "severity": "high",
            "message": "This password is an easily guessed variant of a common password."
        })
    if length > 0 and length < 8:
        warnings.append({
            "id": "WARN_CRITICALLY_SHORT",
            "severity": "high",
            "message": "Password is critically short and can be cracked rapidly via brute-force."
        })
    elif length > 0 and length < 12:
        warnings.append({
            "id": "WARN_SUB_RECOMMENDED_LENGTH",
            "severity": "medium",
            "message": "Password length is below the 12-character baseline target."
        })
    if sequence_count > 0 or repeated_run or keyboard_walk:
        warnings.append({
            "id": "WARN_PREDICTABLE_PATTERN",
            "severity": "medium",
            "message": "Predictable patterns (sequences, repeats, or keyboard walks) reduce practical resistance."
        })
    if year_suffix:
        warnings.append({
            "id": "WARN_YEAR_SUFFIX",
            "severity": "low",
            "message": "Four-digit year patterns are routinely prioritized by credential attack tools."
        })
    if entropy_info["warning"] == "ENTROPY_UNCALIBRATED_UNICODE":
        warnings.append({
            "id": "WARN_ENTROPY_UNCALIBRATED_UNICODE",
            "severity": "info",
            "message": "Theoretical entropy calculation is uncalibrated for non-ASCII Unicode characters."
        })

    # Recommendation IDs
    recommendation_ids: list[str] = []
    if length < 12:
        recommendation_ids.append("REC_INCREASE_LENGTH")
    elif length < 15:
        recommendation_ids.append("REC_CONSIDER_15_PLUS")
    if is_bundled_exact or common_variant or is_custom_exact:
        recommendation_ids.append("REC_CHOOSE_UNRELATED_PHRASE")
    if sequence_count > 0:
        recommendation_ids.append("REC_REMOVE_SEQUENCES")
    if repeated_run:
        recommendation_ids.append("REC_REMOVE_REPEATS")
    if keyboard_walk:
        recommendation_ids.append("REC_REMOVE_KEYBOARD_WALK")
    if year_suffix:
        recommendation_ids.append("REC_REMOVE_YEAR")
    if not has_uppercase or not has_lowercase:
        recommendation_ids.append("REC_DIVERSIFY_CASING")
    if not has_digits:
        recommendation_ids.append("REC_INCLUDE_DIGITS")
    if not has_symbols:
        recommendation_ids.append("REC_INCLUDE_SYMBOLS")
    recommendation_ids.append("REC_USE_PASSWORD_MANAGER")

    return {
        "analysis_version": ANALYSIS_VERSION,
        "score": score,
        "classification": classification,
        "length_code_points": length,
        "length_guidance": length_guidance,
        "criteria": {
            "length_target_met": length_target_met,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_digits": has_digits,
            "has_symbols": has_symbols,
        },
        "warnings": warnings,
        "pattern_penalties": pattern_penalties,
        "entropy_estimate": entropy_info,
        "recommendation_ids": recommendation_ids,
    }


def generate_allowlisted_export(analysis_result: dict[str, Any], include_timestamp: bool = True) -> dict[str, Any]:
    """Build a sanitized JSON export matching the report allowlist.

    Explicitly excludes any secret-derived values, fingerprints, or internal debug data.
    """
    allowlist = (
        "report_schema_version",
        "analysis_version",
        "generated_at",
        "score",
        "classification",
        "length_code_points",
        "criteria",
        "warnings",
        "recommendation_ids",
        "entropy_estimate",
    )
    import datetime
    export: dict[str, Any] = {
        "report_schema_version": "2.0.0",
        "analysis_version": analysis_result.get("analysis_version", ANALYSIS_VERSION),
    }
    if include_timestamp:
        export["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for field in allowlist:
        if field in analysis_result:
            export[field] = analysis_result[field]
    return export
