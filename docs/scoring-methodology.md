# Scoring Methodology & Heuristic Formulation

**Specification:** `security_spec.json` (v2.0.0)  
**Engines:** `password_analyzer.py` & `assets/js/analyzer.js`

---

## 1. Components

### 1.1 Length Component ($L$)
$$L = \min(100, 5 \times \text{length}_{\text{Unicode}})$$
Unicode code points are counted accurately across both implementations (Python `len()`, JavaScript `Array.from().length`).

### 1.2 Theoretical Upper-Bound Entropy ($E$)
For ASCII candidates, the character pool is the union of detected character sets:
- Lowercase (`a-z`): 26
- Uppercase (`A-Z`): 26
- Digits (`0-9`): 10
- Printable ASCII Punctuation: 32
- Space: 1

$$H = \text{length} \times \log_2(\text{Pool Size})$$
$$E = \min\left(100, \frac{H}{80} \times 100\right)$$

> **Important Caveat:** Theoretical Shannon entropy under uniform-random selection represents an absolute upper bound for an idealized attacker without prior knowledge. Empirical human passwords follow severe zipfian distributions, dictionary substitutions, and predictable patterns, yielding drastically lower actual resistance. For non-ASCII inputs, entropy is omitted with `ENTROPY_UNCALIBRATED_UNICODE` and weights are renormalized.

### 1.3 Pattern Quality Component ($P$)
$$P = \max(0, 100 - \sum \text{penalties})$$

### 1.4 Base Score Formula
- When entropy is available:
  $$\text{base\_score} = \text{round}(0.55 \times L + 0.15 \times E + 0.30 \times P)$$
- When entropy is uncalibrated / unavailable:
  $$\text{base\_score} = \text{round}\left(\frac{0.55 \times L + 0.30 \times P}{0.85}\right)$$

---

## 2. Deterministic Pattern Detectors & Penalties

| Rule ID | Detection Logic | Penalty |
|---|---|---|
| `PATTERN_ASCENDING_SEQUENCE` | Alphanumeric runs of length $\ge 4$ (e.g. `abcd`, `1234`, `9876`) | 25 per run (max 35) |
| `PATTERN_REPEATED_RUN` | Same character repeated $\ge 4$ times consecutively (e.g. `aaaa`, `1111`) | 20 |
| `PATTERN_KEYBOARD_WALK` | $\ge 4$ consecutive keys in QWERTY row, column, or diagonal | 25 |
| `PATTERN_YEAR_SUFFIX` | Common base word followed by 4-digit year ($1900..2099$) | 10 |
| `PATTERN_COMMON_VARIANT` | Common base word with leetspeak or $1..4$ trailing digits | 25 (capped at max 29) |
| `DICT_BUNDLED_EXACT` | Exact match against offline bundled dictionary | 90 (capped at max 9) |
| `DICT_CUSTOM_EXACT` | Exact match against user-supplied custom dictionary | 90 (capped at max 9) |

---

## 3. Severity Caps & Classification Bands

Severity caps are evaluated hierarchically after the base score:
1. Exact bundled dictionary match: max 9 (`Very Weak`)
2. Exact custom dictionary match: max 9 (`Very Weak`)
3. Recognizable common-password variant: max 29 (classification cannot exceed `Weak`)
4. Length $< 8$ code points: max 19
5. Length $8..11$ code points: max 49
6. Length $12..14$ code points: max 69
7. Length $\ge 15$ code points: No length-based cap

| Heuristic Score | Classification |
|---|---|
| $0 - 19$ | Very Weak |
| $20 - 39$ | Weak |
| $40 - 59$ | Moderate |
| $60 - 79$ | Strong |
| $80 - 100$ | Very Strong |
