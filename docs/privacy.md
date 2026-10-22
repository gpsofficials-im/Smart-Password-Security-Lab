# Privacy Threat Model & Data Handling Architecture

**Application:** Smart Password Security Lab  
**Policy:** Zero Network Transmission · Zero Persistent Storage · Allowlisted Exports

---

## 1. Threat Model & Boundaries

Password analysis tools inherently handle sensitive authentication secrets. Submitting a real password into an untrusted or cloud-connected service poses severe risks of credential harvesting, transit interception, or log exfiltration.

Smart Password Security Lab is architected with a strict privacy boundary:
- **No Network Egress:** The application makes **zero** outbound HTTP/fetch requests, WebSockets, DNS lookups, or analytics pings. Content Security Policy (`connect-src 'none'`) enforces this in the browser.
- **No Local Persistence:** The candidate password and custom wordlists are **never** written to `localStorage`, `sessionStorage`, `IndexedDB`, cookies, document URL query strings, or browser history.
- **Volatile In-Memory Lifecycle:** Candidate characters exist only in the input element value and call frames during evaluation. Calling `Clear` or `Clear All` flushes the input and resets state immediately.

---

## 2. Safe DOM Handling

- **No `innerHTML` for Dynamic Strings:** All results, rule descriptions, and error statuses are injected using `textContent` or `document.createElement()`.
- **Masked by Default:** The input defaults to `type="password"`. The `Show` toggle is an explicit user action.
- **No Sensitive Diagnostic Echoes:** The UI results card never prints the analyzed password or reveals which specific letters triggered a pattern warning.

---

## 3. Allowlisted JSON & PDF Export Guarantee

Exporting reports (via CLI `--json-out` or browser download) builds payloads strictly from an explicit allowlist of non-sensitive metadata:
- `report_schema_version`
- `analysis_version`
- `generated_at`
- `score`
- `classification`
- `length_code_points`
- `criteria`
- `warnings`
- `recommendation_ids`
- `entropy_estimate`

Raw passwords, masked strings, hash digests, or custom dictionary entries are strictly forbidden from export files. Automated tests in `tests/test_exports.py` verify this invariant recursively.
