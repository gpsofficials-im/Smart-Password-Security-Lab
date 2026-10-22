# Architecture & System Design — Smart Password Security Lab

**Version:** 2.0.0  
**Repository:** `gpsofficials-im/password_strength_checker`

---

## 1. Overview

Smart Password Security Lab is an educational, privacy-first cybersecurity utility providing deterministic, explainable password analysis across two equivalent runtime environments:
1. **Interactive Standalone Browser Dashboard** (`index.html`, `assets/css/app.css`, `assets/js/analyzer.js`, `assets/js/app.js`)
2. **Interactive & Scriptable Python CLI** (`password_strength_checker.py`, `password_analyzer.py`)

Both platforms evaluate candidates against a shared, centrally defined security specification (`security_spec.json`) and shared test vectors (`tests/golden_vectors.json`).

```
+-------------------------------------------------------------------------------+
|                             security_spec.json                                |
|        (Centralized Scoring Weights, Penalties, Caps, & Allowlist)            |
+---------------------------------------+---------------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
     [ password_analyzer.py ]                         [ assets/js/analyzer.js ]
   (Pure Python Analysis Core)                      (Pure JS Analysis Engine)
                 |                                             |
                 v                                             v
  [ password_strength_checker.py ]                    [ assets/js/app.js ]
     (CLI & Backwards Compat)                           (DOM UI Controller)
                 |                                             |
                 v                                             v
        Terminal Interface                                Browser UI
      (--dictionary, --json-out)                   (Live debounce, File API)
```

---

## 2. Component Separation & Invariants

### 2.1 Pure Analysis Engines (`password_analyzer.py` & `assets/js/analyzer.js`)
- **Zero I/O:** Neither engine performs terminal printing, DOM queries, file writing, or network requests.
- **Contract Return:** Both engines return an identical schema object containing heuristic scores, classifications, criteria diagnostics, pattern penalties, theoretical entropy estimates, and recommendations.
- **Privacy Guarantee:** The returned analysis result object never contains the raw candidate, a masked candidate, a hash, a fingerprint, or any derived secret substring.

### 2.2 Presentation Layers (`password_strength_checker.py` & `assets/js/app.js`)
- **CLI (`password_strength_checker.py`):**
  - Uses `getpass.getpass()` for hidden interactive terminal entry.
  - Converts terminal echo warnings into errors rather than exposing characters visibly.
  - Supports `--dictionary PATH` for bounded custom wordlists.
  - Supports `--json-out PATH` for sanitized allowlisted export.
  - Preserves 100% backward compatibility for legacy public function signatures (`check_length`, `calculate_strength_score`, etc.).
- **Browser Controller (`assets/js/app.js`):**
  - Manages live input debounced at 150 ms.
  - Implements the browser File API for local custom wordlists (1 MiB max, 10,000 entries max) in volatile memory only.
  - Enforces DOM safety: user content is strictly assigned via `textContent` or DOM elements; never via `innerHTML`.
  - Provides responsive, print-to-PDF `@media print` layout and client-side JSON export.

---

## 3. GitHub Pages Compatibility

`index.html` resides at the repository root. All assets reside in relative paths (`assets/css/app.css`, `assets/js/analyzer.js`, `assets/js/app.js`), allowing instant, zero-build deployment on GitHub Pages or local static file viewing (`start index.html`).
