# Production Hardening & Architecture Considerations

This document outlines the critical architectural enhancements required to scale the DNS filtering microservice for production traffic, high concurrency, and open-source adoption. All reference implementations strictly enforce the **Data $\rightarrow$ Conditions $\rightarrow$ Returns** pattern and specify Big O complexity.

---

## 1. Alert Deduplication & Rate-Limiting (Anti-Storm Protection)

### The Risk
A single browser tab loading a blocked domain or an infected host stuck in a retry loop can generate hundreds of DNS queries per second. Launching a background thread and dispatching an SMTP email on every single hit will exhaust local threads, cause SQLite lock contention, and trigger upstream SMTP rate limits.

### The Architecture Fix
Introduce an in-memory cooldown cache (`ALERT_COOLDOWN: dict[str, float]`) with an $O(1)$ lookup before spawning the email thread. Only dispatch a review email if the domain has not triggered an alert within the configured cooldown window (e.g., `3600` seconds), while still incrementing a hit counter in SQLite (`INSERT ... ON CONFLICT(domain) DO UPDATE SET hit_count = hit_count + 1`).

```python
import time
import threading

ALERT_COOLDOWN: dict[str, float] = {}
COOLDOWN_LOCK = threading.RLock()


def should_dispatch_alert(domain: str, cooldown_seconds: int = 3600) -> bool:
    """
    Evaluates whether a blocked domain hit should trigger an external email alert
    based on an in-memory TTL cooldown dictionary.
    Complexity: Time O(1) average | Space O(U) where U is unique blocked domains hit
    """
    # --- DATA ---
    normalized = domain.strip().lower()
    now = time.time()
    last_sent = 0.0
    allow_alert = False

    # --- CONDITIONS ---
    if not normalized or cooldown_seconds < 0:
        return False

    with COOLDOWN_LOCK:
        last_sent = ALERT_COOLDOWN.get(normalized, 0.0)
        if (now - last_sent) >= cooldown_seconds:
            ALERT_COOLDOWN[normalized] = now
            allow_alert = True

    # --- RETURNS ---
    return allow_alert
```

---

## 2. Local Allowlist Override & One-Click Admin Review

### The Risk
Public GitHub blocklists frequently contain false positives. When a blocked domain triggers a review email, an administrator needs a mechanism to immediately allow the domain locally without forking and editing the upstream `.txt` file.

### The Architecture Fix
Before executing `lookup_domain_binary()` ($O(M \log N)$) against the GitHub blocklist, evaluate an in-memory `ALLOW_SET: set[str]` synchronized with the local SQLite `domain_rules` table for $O(1)$ overrides. Expose a signed endpoint in the Flask `/admin` UI to transition a domain from `BLOCK` to `ALLOW` and reload the in-memory set immediately.

```python
import sqlite3
import threading

ALLOW_SET: set[str] = set()
ALLOW_LOCK = threading.RLock()


def reload_allowlist_cache(db_path: str) -> int:
    """
    Loads locally approved domains from SQLite into an in-memory set for O(1) overrides.
    Complexity: Time O(A) where A is allowed rules | Space O(A)
    """
    # --- DATA ---
    global ALLOW_SET
    conn = None
    temp_set: set[str] = set()
    loaded_count = 0
    query_sql = "SELECT domain FROM domain_rules WHERE action = 'ALLOW'"

    # --- CONDITIONS ---
    if not db_path:
        return 0

    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        cursor = conn.execute(query_sql)
        for row in cursor.fetchall():
            temp_set.add(row[0].strip().lower())

        with ALLOW_LOCK:
            ALLOW_SET = temp_set
            loaded_count = len(ALLOW_SET)
    except sqlite3.Error:
        loaded_count = -1
    finally:
        if conn:
            conn.close()

    # --- RETURNS ---
    return loaded_count


def is_domain_allowed(target_domain: str) -> bool:
    """
    Checks if a domain or any of its parent labels exist in the O(1) local allowlist.
    Complexity: Time O(M) where M is label depth | Space O(M)
    """
    # --- DATA ---
    normalized = target_domain.strip().lower().rstrip(".")
    labels = normalized.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    allowed = False

    # --- CONDITIONS ---
    if not normalized or not ALLOW_SET:
        return False

    with ALLOW_LOCK:
        for candidate in candidates:
            if candidate in ALLOW_SET:
                allowed = True
                break

    # --- RETURNS ---
    return allowed
```

---

## 3. Upstream Response Caching with TTL Expiration

### The Risk
Forwarding every clean DNS query (`google.com`, `github.com`) over the wire to an upstream resolver adds $10\text{--}30\text{ms}$ of network latency on every request.

### The Architecture Fix
Implement a bounded in-memory LRU cache (`OrderedDict`) for clean upstream DNS wire responses keyed by `(qname, qtype)`. Respecting the upstream record's minimum TTL drops repeat resolution latency from $\sim 20\text{ms}$ to $<0.1\text{ms}$ in $O(1)$ time.

---

## 4. Lock-Free Pointer Swap & ETag Conditional Sync

### The Risk
Periodic background refreshes of a $500,000$-line GitHub blocklist require network I/O and sorting CPU cycles. Holding `STATE_LOCK` during network downloads or Timsort execution will stall live port 53 DNS queries.

### The Architecture Fix
* **ETag Caching**: Store the HTTP `ETag` or `Last-Modified` header from GitHub/Cloudflare and send `If-None-Match` on scheduled syncs. If the upstream list is unchanged (`HTTP 304 Not Modified`), bypass parsing and sorting entirely in $O(1)$ time.
* **Atomic Pointer Swap**: Perform all downloading, parsing, and $O(N \log N)$ Timsort operations on local temporary variables outside the lock. Acquire `STATE_LOCK` only for the sub-microsecond reference reassignment (`SORTED_BLOCKLIST = parsed_domains`).

---

## 5. Cloudflare Free-Tier Middleman Integrations

To maximize reliability without hosting the core microservice on Cloudflare, utilize two free-tier edge capabilities:

1. **Cloudflare Workers + KV as an Edge Blocklist Cache**:
   * **Pattern**: Deploy a Cloudflare Worker scheduled via Cron Triggers to fetch the raw GitHub `.txt` blocklist hourly and store it in Workers KV.
   * **Benefit**: Protects your microservice instances from GitHub raw rate limits and serves the pre-validated list from Cloudflare's nearest edge PoP in $<50\text{ms}$.
2. **Cloudflare DNS-over-HTTPS (DoH) Upstream Fallback**:
   * **Pattern**: When raw UDP port 53 outbound traffic to `1.1.1.1` is throttled or filtered by a cloud/enterprise firewall, fall back to querying `https://cloudflare-dns.com/dns-query` using `application/dns-message` over HTTPS port 443.

---

## 6. Control Plane Authentication & EDNS0 Protocol Hardening

* **Admin Plane Authentication**: Protect `/admin` and rule-modification endpoints using an `X-API-Key` header or HTTP Basic Auth verified via constant-time comparison (`secrets.compare_digest`), and bind the Flask listener to `127.0.0.1` or an internal management VCN subnet.
* **EDNS0 Buffer & TCP Fallback**: Increase the UDP socket buffer in `forward_upstream_dns()` from `4096` to `65535` bytes to support large DNSSEC/TXT payloads, and inspect the DNS header `tc` (Truncated) bit (`reply.header.tc == 1`) so the proxy automatically retries truncated upstream packets over TCP.