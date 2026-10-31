# SentinelDNS: Future Enhancements & Roadmap

This document outlines architectural and functional enhancements planned for upcoming iterations of **SentinelDNS**, structured by feature area, complexity trade-offs, and implementation strategies.

---

## 1. Encrypted DNS Data Plane (DoH / DoT)

### Objective
Support incoming **DNS-over-HTTPS (DoH, RFC 8484)** and **DNS-over-TLS (DoT, RFC 7858)** alongside plain UDP/TCP port 53.

### Implementation & Complexity
- **DoT (Port 853)**: Terminate TLS using Python's standard `ssl.SSLContext` wrapping a TCP server socket. Reuse the existing dnslib decoder and `FilteringResolver`.
  - *Time Complexity*: $O(1)$ SSL handshake overhead amortized over TLS connection reuse.
  - *Space Complexity*: $O(C)$ where $C$ is the number of concurrent TLS streams.
- **DoH (Port 443 / `/dns-query`)**: Expose a dedicated HTTP/2 binary wireformat endpoint (`application/dns-message`) mounted directly on the web control plane or an upstream reverse proxy (Envoy / Caddy / Nginx).
  - *Client Compatibility*: Native iOS, macOS, Windows 11, and Android Private DNS support without custom client-side proxy software.

---

## 2. Reversed-Label Radix Trie for Wildcard and Prefix Rules

### Objective
Upgrade the in-memory lookup index from the current hybrid Hash + Binary Search to an explicit **Reversed-Label Trie (Radix Tree)** to support arbitrary wildcards, suffix exclusions, and CIDR-style hierarchy checks.

### Algorithmic Comparison
| Data Structure | Lookup Time | Subtree Match | Memory Footprint |
| :--- | :--- | :--- | :--- |
| **Current (Hash + Bisect)** | $O(M)$ hash / $O(M \log N)$ bisect | $O(\log N + K)$ | Low (~45 MB per 1M domains) |
| **Reversed-Label Radix Trie** | $O(L)$ where $L = \text{length of FQDN}$ | $O(L + K)$ | Moderate (~70 MB per 1M domains with node compression) |

### Key Benefits
- Allows regex-free glob patterns (e.g., `*.telemetry.*.microsoft.com`).
- Eliminates the need for multiple label-slicing iterations during candidate matching.

---

## 3. OIC (Oracle Integration Cloud) REST Webhook Dispatcher

### Objective
In addition to native direct SMTP alerts, provide first-class integration with **Oracle Integration Cloud (OIC)** and enterprise webhook targets (Slack, Microsoft Teams, PagerDuty, Splunk).

### Implementation Pattern
- Follow the `# --- DATA ---`, `# --- CONDITIONS ---`, `# --- RETURNS ---` convention.
- Bounded background worker queue (`OIC_WEBHOOK_QUEUE`) using standard library `urllib.request` or connection-pooled sessions.
- Configurable HMAC-SHA256 signature header (`X-Sentinel-Signature`) to guarantee authenticity of the webhook payload sent to the OIC inbound trigger.

```python
def dispatch_oic_webhook(payload: dict, webhook_url: str, signing_secret: str) -> bool:
    """
    Dispatches a structured JSON incident report to an OIC integration flow.
    Complexity: Time O(1) network bound | Space O(P) where P is payload size
    """
    # --- DATA ---
    import hmac
    import hashlib
    import json
    from urllib.request import Request, urlopen

    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(signing_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    req = Request(
        webhook_url,
        data=body_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Signature": f"sha256={signature}",
            "User-Agent": "SentinelDNS-AlertWorker/1.0",
        },
        method="POST",
    )
    success = False

    # --- CONDITIONS ---
    if not webhook_url.startswith("https://"):
        return False

    try:
        with urlopen(req, timeout=5.0) as resp:
            success = 200 <= resp.status < 300
    except Exception:
        success = False

    # --- RETURNS ---
    return success
```

---

## 4. Distributed Multi-Node Sync via SQLite LiteStream / Raft

### Objective
Enable running redundant SentinelDNS instances across multiple OCI availability domains or edge locations with synchronized rule administration.

### Architecture Options
1. **LiteStream / LiteFS**: Continuous background streaming of SQLite WAL frames to an OCI Object Storage bucket. Read-only replicas continuously hydrate from object storage.
2. **Control-Plane Split**: Centralized admin node publishing signed rule snapshots (e.g., signed JSON or SQLite DB artifacts) to GitHub or an internal S3/OCI bucket; DNS worker instances poll the signed manifest every 60 seconds.

---

## 5. Prometheus Metrics & Observability

### Objective
Expose real-time telemetry at `/metrics` compliant with OpenTelemetry and Prometheus standards.

### Core Metrics to Export
- `sentineldns_queries_total{protocol="udp|tcp", rcode="NOERROR|NXDOMAIN"}`
- `sentineldns_blocklist_size{category="..."}`
- `sentineldns_lookup_latency_seconds_bucket` (Histogram with sub-millisecond buckets: `[0.0001, 0.0005, 0.001, 0.005]`)
- `sentineldns_policy_evaluations_total{action="BLOCK|ALLOW|MONITOR|PASS"}`
- `sentineldns_alert_queue_depth`

---

## 6. Dynamic Machine Learning & Heuristic Domain Scoring

### Objective
Integrate lightweight heuristic classifiers to detect algorithmically generated domains (DGA) and brand impersonation homoglyphs without external cloud dependency.

### Capabilities
- **Shannon Entropy Scoring**: Calculate the character entropy of domain labels. High entropy (e.g., `x89afq918zaq.biz`) automatically triggers `MONITOR` or `BLOCK` policy.
  - *Time Complexity*: $O(K)$ where $K$ is domain string length.
- **Levenshtein Distance / Punycode Inspection**: Compare inbound lookups against high-value internal or financial domains (e.g., `paypal`, `google`, `chase`) to identify typosquatting and Unicode confusable attacks.

---

## 7. Multi-User Role-Based Access Control (RBAC) & Audit Trails

### Objective
Extend the single-admin model to support granular enterprise roles:
- **Viewer**: Read-only access to `/admin` dashboard and audit statistics.
- **Auditor**: Ability to review hits, mark resolved, and download compliance audit logs.
- **SecOps Admin**: Full rule management, blocklist source manipulation, and policy changes.
- **MFA / WebAuthn**: Native FIDO2 / Passkey authentication via standard browser credentials API.

