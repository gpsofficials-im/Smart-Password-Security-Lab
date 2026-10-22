# Smart Password Security Lab

[![Python Tests](https://github.com/gpsofficials-im/password_strength_checker/actions/workflows/tests.yml/badge.svg)](https://github.com/gpsofficials-im/password_strength_checker/actions/workflows/tests.yml)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](security_spec.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)

A professional, privacy-first cybersecurity educational application and laboratory for evaluating password security, detecting predictable keyboard and dictionary patterns, estimating theoretical entropy, and learning defense principles.

---

## Key Capabilities

- **Explainable Hybrid Scoring (0–100):** Combines Unicode code-point length ($L$), theoretical character-pool entropy ($E$), and pattern quality ($P$) under strict, hierarchical severity caps.
- **Deterministic Pattern Detectors:** Flags ascending/descending alphanumeric runs, repeated-character runs, standard QWERTY keyboard walks, four-digit year suffixes, and common-password variants.
- **Offline & Bundled Dictionaries:** Curated offline dictionary (`data/common_passwords.txt`) matching whole candidates (long passphrases with dictionary substrings are never penalized).
- **Custom Wordlists:** Supports user-supplied custom dictionaries in both the Python CLI (`--dictionary PATH`) and browser (in-memory File API) with defensive limits (1 MiB max, 10,000 entries max).
- **100% Cross-Language Parity:** Verified identical scoring, penalties, and classifications between the Python engine (`password_analyzer.py`) and JavaScript engine (`assets/js/analyzer.js`) via shared golden vectors (`tests/golden_vectors.json`).
- **Zero-Storage Privacy Model:** Local processing only. Zero network requests, zero telemetry, zero cookies, zero `localStorage`. Input is masked by default with accessible Show/Hide and Clear/Clear All controls.
- **Sanitized JSON & PDF Export:** Strict allowlist report export omitting all passwords, masks, hashes, or candidate-derived secrets. Includes `@media print` styling for clean browser Print → Save as PDF.
- **Interactive Learning Mode:** Explore security concepts with pre-configured synthetic demonstration examples.
- **Benchmark Evaluation Lab:** Built-in synthetic test laboratory measuring precision, recall, false-positive, and false-negative rates.

---

## Architecture Overview

```text
password_strength_checker/
├── index.html                      # Standalone responsive web dashboard (GitHub Pages compatible)
├── assets/
│   ├── css/
│   │   └── app.css                 # Dark theme styling, accessible focus, @media print PDF layout
│   └── js/
│       ├── analyzer.js             # Pure JavaScript analysis engine (ES module & browser script)
│       └── app.js                  # UI controller, debounced input, File API, JSON export
├── password_analyzer.py            # Pure Python analysis engine (0-100 hybrid score, entropy, patterns)
├── password_strength_checker.py    # CLI application (--dictionary, --json-out) & compatibility layer
├── security_spec.json              # Central single-source-of-truth specification for rules & scoring
├── data/
│   ├── common_passwords.txt        # Curated offline predictable credentials collection
│   └── dictionary_provenance.md    # Ethical provenance and review documentation
├── tests/
│   ├── test_analyzer.py            # Core engine and Unicode tests
│   ├── test_patterns.py            # Sequence, repeat, walk, year, variant rule tests
│   ├── test_exports.py             # Export privacy allowlist and non-leakage verification
│   ├── test_web_parity.mjs         # Node.js test runner verifying 100% JS/Python parity
│   ├── golden_vectors.json         # Shared vector dataset consumed across languages
│   └── test_password_checker.py    # Regression coverage for legacy public APIs
├── benchmarks/
│   ├── synthetic_cases.json        # Labeled synthetic test cases across all categories
│   └── evaluate.py                 # Precision, recall, FPR, and FNR measurement script
└── docs/
    ├── architecture.md             # Detailed system architecture and design invariants
    ├── scoring-methodology.md      # Mathematical formula derivations and severity caps
    └── privacy.md                  # Threat model, DOM safety, and zero-storage guarantees
```

---

## Quick Start

### 1. Web Application (Standalone Browser)

Open `index.html` in any modern web browser (no local web server or build step required):

```powershell
start index.html
```

Or open directly in Chrome, Firefox, Safari, or Edge.

### 2. Python CLI

Run the interactive CLI in any standard terminal:

```powershell
python password_strength_checker.py
```

#### Optional CLI Flags:
```powershell
# Analyze with a custom proprietary wordlist
python password_strength_checker.py --dictionary my_team_words.txt

# Export a sanitized, password-free JSON report
python password_strength_checker.py --json-out report.json
```

---

## Automated Test Suites

Smart Password Security Lab requires **zero external dependencies** — tests run using standard libraries:

### Run Python Unit & Regression Tests:
```powershell
python -m unittest discover -s tests -v
python -m unittest test_password_checker.py -v
```

### Run Cross-Language Parity Suite (Node.js):
```powershell
node --test tests/test_web_parity.mjs
```

### Run Quality Benchmark Evaluation:
```powershell
python benchmarks/evaluate.py
```

---

## Benchmark Results

Evaluated against the authored synthetic test suite (`benchmarks/synthetic_cases.json`):

| Metric | Target | Result | Status |
|---|---|---|---|
| **Overall Pattern Recall** | $\ge 90.0\%$ | **100.0%** | :white_check_mark: PASSED |
| **Benign False-Positive Rate** | $\le 5.0\%$ | **0.0% (0/20)** | :white_check_mark: PASSED |
| **Golden Vector Parity Rate** | $100.0\%$ | **100.0% (32/32)** | :white_check_mark: PASSED |
| **Regression Suite Pass Rate** | $100.0\%$ | **100.0% (30/30)** | :white_check_mark: PASSED |

---

## Security & Limitations

This tool is an **educational heuristic estimator**, not an authentication service or cryptographic guarantee:
- It does **not** query live breached-password databases (e.g. HaveIBeenPwned API).
- It does not calculate exact GPU attack costs against customized hash algorithms (e.g. Argon2id, bcrypt, scrypt).
- Character complexity alone does not make a password secure; length and uniqueness are paramount.
- For all production systems, generate randomized passphrases using a reputable password manager and enable Multi-Factor Authentication (MFA).

See [SECURITY.md](SECURITY.md) and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for full disclosure details.
