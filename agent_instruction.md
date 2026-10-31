# AI Agent Instructions: Build, Test & Deploy (SentinelDNS)

This document is the authoritative specification for AI agents, CI/CD runners, and autonomous automation scripts working on or deploying **SentinelDNS**.

---

## 1. Coding Invariants (Strict Enforcement)

Every Python function and method in this repository MUST strictly follow the three-block structure and complexity contract:

1. **`# --- DATA ---`**:
   - Declare and initialize all local variables, SQL strings, constants, and data structures at the very top of the function body.
   - Do not perform I/O, heavy branching, or external calls in this block.
2. **`# --- CONDITIONS ---`**:
   - Perform all guard clauses, validation, business logic, sorting, iterations, and database/network operations.
   - Fail-fast pattern: early returns are permitted strictly for parameter validation/guards.
3. **`# --- RETURNS ---`**:
   - Return the calculated outcome explicitly at the bottom of the function.
4. **Complexity Annotation**:
   - Every function docstring MUST declare explicit Big-O notation for time and space:
     ```python
     """
     Brief function summary.
     Complexity: Time O(...) | Space O(...)
     """
     ```

---

## 2. Environment & Dependency Specifications

- **Python Version**: Python 3.11+ required (utilizes `datetime.UTC`, modern type syntax, and stdlib enhancements).
- **Core Dependencies**:
  - `flask >= 3.0, < 4` (Control plane, templates, secure session cookies)
  - `dnslib >= 0.9.24, < 1` (DNS wire protocol encoding/decoding)
- **Production Dependencies**:
  - `gunicorn >= 22` (WSGI server for Flask admin plane)
- **Development & Verification Toolchain**:
  - `pytest >= 8` (Unit and performance regression test harness)
  - `ruff >= 0.6` (Linter and formatter)
  - `bandit >= 1.7.9` (AST security vulnerability analyzer)

---

## 3. Local Build & Test Pipeline

Execute commands sequentially from the project root:

```bash
# 1. Virtual Environment Initialization
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# 2. Dependency Installation
python -m pip install --upgrade pip
pip install -e ".[dev,prod]"

# 3. Code Quality & Security Audits
ruff check .
bandit -r sentineldns/ -c pyproject.toml

# 4. Automated Test Suite (Functional + Big-O Performance Budgets)
pytest -v
```

### Test Suite Layout
- `tests/test_domains.py`: Normalization, RFC validation, subdomain suffix candidate generation, and injection prevention.
- `tests/test_blocklist.py`: Remote fetch validation, cache fallback, TimSort ordering, binary search (`bisect`), and Big-O lookup latency budget tests.
- `tests/test_policy_db.py`: SQLite WAL persistence, admin rule evaluation precedence, alert cooldown throttling, and hit recording.
- `tests/test_dns.py`: Offline UDP/TCP DNS protocol interception, sinkholing, and upstream resolution behavior.
- `tests/test_web.py`: Authentication, CSRF tokens, strict Content-Security-Policy (CSP), and admin management workflows.

---

## 4. OCI (Oracle Cloud Infrastructure) & OIC Deployment Direction

### 4.1 Compute Architecture
- **Target OS**: Ubuntu 22.04 LTS or 24.04 LTS (x86_64 or AArch64 Ampere A1).
- **Network Ingress (OCI Security List / NSG)**:
  - Port 53 UDP & TCP: Inbound from authorized DNS client subnets / VPN CIDRs.
  - Port 8080 TCP (or 443 via reverse proxy): Admin control plane restricted to management IPs / Bastion hosts.
  - Port 22 TCP: SSH key authentication only.

### 4.2 Systemd Service Units
Deploy two isolated systemd units: one for the DNS data plane and one for the Flask WSGI control plane.

#### Unit 1: DNS Forwarder (`/etc/systemd/system/sentineldns.service`)
```ini
[Unit]
Description=SentinelDNS Filtering Data Plane
After=network.target

[Service]
Type=simple
User=sentineldns
Group=sentineldns
WorkingDirectory=/opt/sentineldns
EnvironmentFile=/etc/sentineldns/sentineldns.env
ExecStart=/opt/sentineldns/.venv/bin/python -m sentineldns dns
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

#### Unit 2: Admin Control Plane (`/etc/systemd/system/sentineldns-web.service`)
```ini
[Unit]
Description=SentinelDNS Flask Control Plane
After=network.target sentineldns.service

[Service]
Type=simple
User=sentineldns
Group=sentineldns
WorkingDirectory=/opt/sentineldns
EnvironmentFile=/etc/sentineldns/sentineldns.env
ExecStart=/opt/sentineldns/.venv/bin/gunicorn -w 2 --threads 4 -b 127.0.0.1:8080 wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 5. Automated CI/CD Pipeline (GitHub Actions)

When configuring `.github/workflows/ci.yml`, AI agents should enforce the following continuous integration matrix:

```yaml
name: CI Pipeline

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  verify:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: "pip"

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Code Linting
        run: ruff check .

      - name: Static Security Analysis
        run: bandit -r sentineldns/ -c pyproject.toml

      - name: Run Pytest Suite
        run: pytest -v --durations=10
```

---

## 6. Oracle Integration Cloud (OIC) Hook Architecture
When deployed in enterprise environments pairing OCI Compute with OIC:
1. Set `ALERT_EMAIL` or configure the outbound webhook trigger to hit the OIC REST Trigger endpoint.
2. Ensure OIC ingress OAuth2 / basic tokens are stored securely in `/etc/sentineldns/sentineldns.env` with file permissions `0600` owned by `sentineldns:sentineldns`.
3. Never log raw API credentials or tokens in SQLite audit logs or application standard output.
