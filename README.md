# Nehemiah_DNS ◈

> High-throughput, category-based DNS and domain traffic filtering microservice with an embedded Flask & SQLite control plane.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

---

## Overview

**Nehemiah_DNS** provides lightweight, deterministic, and privacy-preserving DNS filtering designed to run efficiently on edge nodes, local servers, or cloud virtual machines (including Oracle Cloud Infrastructure Always Free Compute). It ingests flat `.txt` blocklists hosted on GitHub, indexes them in memory using optimal Big-O data structures, resolves queries with sub-millisecond latency, and buffers reviewable hits for human administrative oversight.

### Key Features

- **Blazing Fast In-Memory Lookups**: Hybrid hash table ($O(1)$) and binary search over reversed-label tuples ($O(M \log N)$), eliminating slow disk/database queries on the DNS resolution path.
- **Strict Separation of Concerns**: DNS data plane (`dnslib` UDP/TCP forwarder) runs independently from the administrative control plane (Flask + SQLite in WAL mode).
- **Asynchronous Review & Anti-Storm Alerting**: Domain hits are recorded in an in-memory queue, batched to SQLite, and dispatched via SMTP/OIC alerts with per-domain TTL cooldowns to prevent notification storms.
- **Production-Hardened Admin Dashboard**: Built-in dark glass web UI with strict Content-Security-Policy (CSP), zero external CDN font/script dependencies, CSRF protection, and rate-limited authentication.
- **GitHub Blocklist Ingestion**: Pulls domain lists directly from GitHub raw repositories with local cache fallback and SSRF protection.
- **Strict Code Structure**: Every internal function is implemented with the deterministic `# --- DATA ---`, `# --- CONDITIONS ---`, `# --- RETURNS ---` pattern with explicit Big-O complexity documentation.

---

## Algorithmic Performance (Big-O Summary)

| Operation | Complexity (Time) | Complexity (Space) | Mechanism |
| :--- | :--- | :--- | :--- |
| **List Ingestion & Sort** | $O(N \log N)$ worst, $O(N)$ best | $O(N)$ | Python Timsort exploiting natural runs in GitHub lists |
| **Direct Domain Lookup** | $O(M)$ average | $O(N)$ | Hash table (`dict[str, str]`) across domain label depth $M$ |
| **Reversed-Label Suffix Search** | $O(M \log N)$ | $O(M)$ | Binary search (`bisect_left`) over reversed label tuples |
| **Subtree Wildcard Matching** | $O(\log N + K)$ | $O(K)$ | Bisect range slice across contiguous matching subdomains |
| **Hit Submission (Hot Path)** | $O(1)$ | $O(1)$ | Non-blocking bounded queue push (`queue.Queue.put_nowait`) |

---

## Quickstart

### 1. Installation

```bash
git clone https://github.com/mystmn/Nehemiah_DNS.git
cd Nehemiah_DNS
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev,prod]"
```

### 2. Configuration & Initialization

```bash
cp .env.example .env
python -m nehemiah_dns gen-secret
python -m nehemiah_dns hash-password
# Add generated keys to .env, then bootstrap:
python -m nehemiah_dns init
python -m nehemiah_dns sync
```

### 3. Launching Services

```bash
# Terminal 1: Admin Control Plane (Web UI)
gunicorn -w 2 --threads 4 -b 127.0.0.1:8080 wsgi:app

# Terminal 2: DNS Filtering Server (binds to port 5353 for local testing)
NEHEMIAH_DNS_PORT=5353 python -m nehemiah_dns dns
```

Visit the Admin Dashboard at **`http://127.0.0.1:8080/admin`**.

---

## Documentation Directory

- **[System Architecture & Design (design.md)](file:///c:/git/SaaS/Valley%20of%20Despair%20-%20Home%20monitor/design.md)**: In-depth technical architecture, data structures, concurrency, and security posture.
- **[Installation & Operations Guide (install.md)](file:///c:/git/SaaS/Valley%20of%20Despair%20-%20Home%20monitor/install.md)**: Deployment steps for Ubuntu, OCI Compute, systemd units, and firewall configurations.
- **[AI Build, Test & Deploy Instructions (agent_instruction.md)](file:///c:/git/SaaS/Valley%20of%20Despair%20-%20Home%20monitor/agent_instruction.md)**: Machine-readable specifications and coding invariants for AI coding agents and CI pipelines.
- **[Future Enhancements Roadmap (future enhancements.md)](file:///c:/git/SaaS/Valley%20of%20Despair%20-%20Home%20monitor/future%20enhancements.md)**: Roadmap including DoH/DoT, Radix Tries, OIC Webhook Dispatchers, and Prometheus Metrics.
- **[Production Hardening Considerations (production_hardening_architecture_considerations.md)](file:///c:/git/SaaS/Valley%20of%20Despair%20-%20Home%20monitor/production_hardening_architecture_considerations.md)**: Technical analysis of alert storm mitigation and allowlist overrides.

---

## Running Tests & Verifications

```bash
# Run unit and performance budget tests
pytest -v

# Run linter
ruff check .

# Run static security analysis
bandit -r nehemiah_dns/ -c pyproject.toml
```

---

## License

This project is open-source under the [MIT License](LICENSE).
