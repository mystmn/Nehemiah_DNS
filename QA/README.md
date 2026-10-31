# Nehemiah_DNS: QA & Proof-of-Concept (POC) Test Suite

This folder contains throwaway QA verification scripts and a live end-to-end Proof of Concept (POC) for Nehemiah_DNS.

---

## Files in this Directory

1. **`test_file_by_file_audit.py`**:
   - Performs a static AST audit across every Python module in `nehemiah_dns/`.
   - Validates that every function/method adheres to the `# --- DATA ---`, `# --- CONDITIONS ---`, `# --- RETURNS ---` three-block invariant.
   - Enforces that every function docstring contains explicit `Complexity: Time O(...) | Space O(...)` declarations.
   - Runs unit contract verifications for domain parsing, blocklist indexing, SQLite WAL database persistence, policy evaluation, and security tokens.

2. **`poc_live_e2e_test.py`**:
   - A self-contained, live end-to-end simulation:
     - Bootstraps an isolated SQLite database and mock blocklists in a temporary directory.
     - Boots a real UDP DNS forwarder listening on `127.0.0.1:15353`.
     - Sends live DNS wire-protocol queries for blocked root domains (`doubleclick.net`), deep subdomains (`deep.analytics.doubleclick.net`), and clean domains (`kernel.org`).
     - Verifies asynchronous hit buffering and aggregated review queue updates in SQLite.
     - Performs a live zero-downtime admin policy override (`doubleclick.net` -> `ALLOW`) and verifies instant re-resolution without DNS restart.
     - Tests Flask web control plane authentication, CSRF tokens, and the `/api/v1/check` endpoint.

---

## How to Run

### 1. Run the File-by-File Invariant & Unit Audit
```bash
python -m pytest QA/test_file_by_file_audit.py -v
```

### 2. Run the Live End-to-End POC
```bash
python QA/poc_live_e2e_test.py
```

### 3. Run the Full Project Test Suite
```bash
python -m pytest
```

---

## Easy Removal / Teardown

All code in this `QA/` folder is designed to be completely throwaway and decoupled from the production application. When consumption/review is complete, remove this folder at any time:

**On Linux / macOS:**
```bash
rm -rf QA
```

**On Windows PowerShell:**
```powershell
Remove-Item -Recurse -Force QA
```
