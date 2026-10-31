# SentinelDNS: System Architecture & Design Specification

Welcome to the architectural design guide for **SentinelDNS**. This document explains the internal mechanisms, algorithmic trade-offs, security model, and data flow of this open-source category-based DNS and traffic filter.

---

## 1. System Vision & Guiding Principles

SentinelDNS is built to deliver fast, deterministic domain-level traffic control without requiring heavy external dependencies (such as Redis or Elasticsearch). It is split into two coordinated planes:

1. **DNS Data Plane**: A high-throughput UDP/TCP DNS forwarder built on `dnslib` that evaluates lookups in memory with sub-millisecond response latency ($<1\text{ms}$).
2. **Flask Control Plane**: A lightweight, hardened web dashboard and REST API backed by an embedded SQLite database running in WAL mode for administrative rule management, list curation, and human audit review.

```
                    +------------------------------------+
                    |  Inbound DNS Query (UDP/TCP: 53)   |
                    +-----------------+------------------+
                                      |
                                      v
                        +----------------------------+
                        |   Normalize & Candidate    |
                        |      Label Extraction      |
                        +--------------+-------------+
                                      |
                        +-------------v--------------+
                        |  Policy Engine Evaluation  |
                        |  (1. Rules -> 2. Category) |
                        +-------+------------+-------+
                                |            |
                  [ALLOW / PASS]|            |[BLOCK / MONITOR]
                                |            |
             +------------------+            +-------------------+
             |                                                   |
             v                                                   v
+--------------------------+                      +-------------------------------+
| Forward Upstream DNS     |                      | Non-Blocking Hit Recorder     |
| (1.1.1.1, 8.8.8.8)       |                      | (O(1) Memory Queue -> SQLite) |
+------------+-------------+                      +---------------+---------------+
             |                                                    |
             |                                      +-------------v---------------+
             |                                      | Alert Cooldown Filter       |
             |                                      | (Dispatches SMTP / OIC)     |
             |                                      +-----------------------------+
             v
+--------------------------+
| Client Receives Response |
| (Clean IP or 0.0.0.0/NX) |
+--------------------------+
```

---

## 2. In-Memory Search Algorithms & Big-O Complexity

Evaluating millions of domain rules on every DNS lookup requires strict performance guarantees. SentinelDNS avoids unpredictable hash-table memory bloat and hash-collision vulnerabilities by combining two deterministic lookup patterns:

| Step | Operation | Data Structure / Algorithm | Time Complexity | Space Complexity | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Domain Ingestion** | Python Timsort (`list.sort()`) | $O(N \log N)$ worst<br>$O(N)$ best | $O(N)$ | Upstream blocklists from GitHub are often alphabetically sorted or partially sorted; Timsort exploits natural runs. |
| **2** | **Direct Domain Match** | Hash Map (`dict[str, str]`) | $O(M)$ avg<br>$O(M \cdot N)$ worst | $O(N)$ | Fast $O(1)$ amortized membership per candidate label depth $M$ ($2 \le M \le 5$). |
| **3** | **Reversed Suffix Match** | Binary Search (`bisect_left`) | $O(M \log N)$ | $O(M)$ | Searching a sorted tuple of reversed domain labels (e.g. `['com', 'example', 'malicious']`) allows instant parent/subdomain matching with zero recursion. |
| **4** | **Subtree Range Query** | Bisect Range Slicing | $O(\log N + K)$ | $O(K)$ | Efficiently finds all $K$ active subdomains listed under a root domain for dashboard inspection. |

### Why Reversed Labels for Binary Search?
When domains are stored in natural order (`a.example.com`, `b.example.com`, `example.com`), prefix matching cannot identify common roots because the top-level domain is at the end. By storing domains with reversed labels (`('com', 'example', 'a')`), all subdomains of `example.com` share a common contiguous prefix. A single `bisect_left` identifies the start of the subtree in $O(\log N)$ time.

---

## 3. Data Plane vs. Control Plane Isolation

To guarantee that web traffic or slow background tasks never compromise real-time DNS resolution:

1. **Immutable State Swapping**: The policy state (`PolicyState`) containing the active rules, category actions, and domain index is completely immutable. Updates are loaded into a new object and swapped atomically via a single reference assignment (`self._state = new_state`), eliminating reader lock contention.
2. **Asynchronous Bounded Hit Recording**: When a domain triggers a `BLOCK` or `MONITOR` condition, the DNS worker pushes the hit into an in-memory `queue.Queue(maxsize=10000)`. If the queue is saturated, excessive hits are safely dropped with an atomic counter drop to protect the DNS thread from blocking.
3. **Dedicated Batch Persistence**: A background thread drains the queue in batches and executes atomic parameterized bulk inserts into SQLite:
   ```sql
   INSERT INTO reviews (domain, matched, category, client_ip, hit_count)
   VALUES (?, ?, ?, ?, ?)
   ON CONFLICT(matched) DO UPDATE SET
       hit_count = hit_count + excluded.hit_count,
       last_seen = CURRENT_TIMESTAMP;
   ```

---

## 4. Notification & Anti-Storm Alerting

A recurring failure mode in network monitoring is alert fatigue and thread exhaustion caused by repetitive DNS query retries (e.g., infected hosts querying a C2 domain 50 times per second).

### Anti-Storm Defense Architecture:
- **Per-Domain TTL Cooldown**: An in-memory cache records the timestamp of the last dispatched alert for each domain. If an incoming hit occurs within `ALERT_COOLDOWN` (default: 3600 seconds / 1 hour), the notification is suppressed while SQLite hit counts continue incrementing.
- **Single Bounded Dispatcher Worker**: Outbound SMTP and OIC webhook requests execute on a dedicated worker thread with strict timeouts (`timeout=5.0s`), ensuring external network latency never impacts local operations.

---

## 5. Security Architecture

SentinelDNS enforces strict defense-in-depth across the web and network boundaries:

1. **SSRF Hardening**: Remote blocklist downloads are restricted to pre-approved hostnames (`SENTINEL_ALLOWED_SOURCE_HOSTS`, e.g., `raw.githubusercontent.com`). Private IP addresses, non-HTTPS protocols, and internal network ranges are rejected before issuing HTTP requests.
2. **Content-Security-Policy (CSP)**: The Flask administration dashboard enforces a zero-inline CSP:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none';
   ```
   All styles and scripts are hosted locally; no third-party CDNs or font servers are contacted, preventing admin IP leakage.
3. **Session Security & Timing Attacks**:
   - Passwords use hardened PBKDF2/scrypt hashes via Werkzeug.
   - Login attempts employ constant-time hash comparisons against dummy hashes on failed username lookups to prevent user enumeration via timing analysis.
   - In-memory rate limiting throttles brute-force authentication attempts per client IP.
4. **Parameterized SQL Everywhere**: Zero dynamic SQL string concatenation. All database operations strictly utilize parameterized queries (`?` markers).
