# SentinelDNS: Installation & Operations Guide

Welcome to **SentinelDNS**! This guide covers local developer setup, production deployment to an Oracle Cloud Infrastructure (OCI) Compute instance or Ubuntu VM, and operational management.

---

## 1. Quickstart (Local Development)

### Prerequisites
- Python 3.11+
- Git & SQLite3

### Step-by-Step Local Setup

1. **Clone the Repository & Enter Workspace**:
   ```bash
   git clone https://github.com/your-org/sentineldns.git
   cd sentineldns
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate       # Linux/macOS
   # On Windows PowerShell: .venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev,prod]"
   ```

4. **Initialize Environment Variables**:
   ```bash
   cp .env.example .env
   ```
   Generate a secure secret key and admin password hash:
   ```bash
   python -m sentineldns gen-secret
   python -m sentineldns hash-password
   ```
   Paste the generated values into `.env`:
   - `SENTINEL_SECRET_KEY`
   - `SENTINEL_ADMIN_PASSWORD_HASH`

5. **Initialize Database & Load Initial Lists**:
   ```bash
   python -m sentineldns init
   python -m sentineldns sync
   ```

6. **Start the Control Plane & DNS Server**:
   ```bash
   # Terminal 1: Admin Control Plane
   gunicorn -w 2 --threads 4 -b 127.0.0.1:8080 wsgi:app

   # Terminal 2: DNS Filtering Server (binds to 127.0.0.1:5353 for testing without root)
   SENTINEL_DNS_PORT=5353 python -m sentineldns dns
   ```

7. **Test Resolution & Admin Dashboard**:
   - Web UI: Navigate to `http://127.0.0.1:8080/admin` and log in with your configured admin credentials.
   - Test Query (Blocked):
     ```bash
     dig @127.0.0.1 -p 5353 doubleclick.net
     ```
     You will receive `NXDOMAIN` (or `0.0.0.0` depending on configuration) and the hit will appear in the Review Queue.
   - Test Query (Allowed):
     ```bash
     dig @127.0.0.1 -p 5353 google.com
     ```
     Resolves cleanly via upstream DNS forwarders.

---

## 2. Production Deployment on Oracle Cloud (OCI) Compute

This section walks through deploying SentinelDNS onto an **OCI Always Free Ampere A1 (AArch64)** or **Standard AMD (x86_64)** Compute instance running Ubuntu 22.04 LTS / 24.04 LTS.

### 2.1 OCI VCN Security List & Ingress Rules
In the OCI Console (Networking -> Virtual Cloud Networks -> Security Lists):
1. Add Ingress Rule:
   - **Source CIDR**: Your authorized client subnets / VPN CIDR (or `0.0.0.0/0` if offering public resolver)
   - **IP Protocol**: UDP, Destination Port: `53`
2. Add Ingress Rule:
   - **Source CIDR**: Same as above
   - **IP Protocol**: TCP, Destination Port: `53`
3. Add Ingress Rule:
   - **Source CIDR**: Admin bastion or management IP CIDR
   - **IP Protocol**: TCP, Destination Port: `8080` (or `443` via reverse proxy)

### 2.2 Host Firewall (iptables / ufw) Configuration
Ubuntu on OCI defaults to restrictive `iptables` rules. Update them:
```bash
sudo iptables -I INPUT 6 -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT 6 -p tcp --dport 53 -j ACCEPT
sudo netfilter-persistent save
```

### 2.3 System User and Directory Structure
```bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/sentineldns sentineldns
sudo mkdir -p /opt/sentineldns /etc/sentineldns /var/lib/sentineldns /var/cache/sentineldns
sudo chown -R sentineldns:sentineldns /opt/sentineldns /var/lib/sentineldns /var/cache/sentineldns
```

### 2.4 Application Code Installation
```bash
cd /opt/sentineldns
sudo -u sentineldns git clone https://github.com/your-org/sentineldns.git .
sudo -u sentineldns python3 -m venv .venv
sudo -u sentineldns .venv/bin/pip install --upgrade pip
sudo -u sentineldns .venv/bin/pip install -e ".[prod]"
```

### 2.5 Production Environment File (`/etc/sentineldns/sentineldns.env`)
Create `/etc/sentineldns/sentineldns.env` with restricted permissions:
```ini
SENTINEL_DB=/var/lib/sentineldns/sentinel.db
SENTINEL_CACHE_DIR=/var/cache/sentineldns
SENTINEL_LOCAL_LISTS=/opt/sentineldns/lists

SENTINEL_DNS_HOST=0.0.0.0
SENTINEL_DNS_PORT=53
SENTINEL_DNS_UPSTREAM=1.1.1.1
SENTINEL_DNS_UPSTREAM_PORT=53
SENTINEL_DNS_BLOCK_MODE=nxdomain

SENTINEL_ADMIN_USER=secops
SENTINEL_ADMIN_PASSWORD_HASH=scrypt:32768:8:1$...
SENTINEL_SECRET_KEY=your-generated-random-secret-key-at-least-32-chars
SENTINEL_COOKIE_SECURE=1

SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@yourdomain.com
SMTP_PASS=your-smtp-password
ALERT_EMAIL=secops-team@yourdomain.com
ALERT_COOLDOWN_SECONDS=3600
```
Set strict permissions:
```bash
sudo chown root:sentineldns /etc/sentineldns/sentineldns.env
sudo chmod 640 /etc/sentineldns/sentineldns.env
```

### 2.6 Granting Low-Port Binding to Python (`CAP_NET_BIND_SERVICE`)
To allow the DNS daemon running as non-root user `sentineldns` to bind to port 53:
```bash
sudo setcap 'cap_net_bind_service=+ep' /opt/sentineldns/.venv/bin/python3
```

### 2.7 Systemd Service Units

#### Service 1: DNS Forwarder (`/etc/systemd/system/sentineldns.service`)
```ini
[Unit]
Description=SentinelDNS Filtering Forwarder
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

#### Service 2: Flask Control Plane (`/etc/systemd/system/sentineldns-web.service`)
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

#### Enable and Start Services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentineldns.service
sudo systemctl enable --now sentineldns-web.service
sudo systemctl status sentineldns.service sentineldns-web.service
```

---

## 3. GitHub Blocklist Management & Syncing

SentinelDNS pulls raw `.txt` domain lists hosted in GitHub repositories:

### File Format:
Lists can contain plain domains, hosts format, or optional comma-delimited category annotations:
```text
# Comments and blank lines are ignored
doubleclick.net
ads.example.com,ads
0.0.0.0 malicious-tracker.info,malware
```

### Adding a Remote Source via CLI:
```bash
sudo -u sentineldns /opt/sentineldns/.venv/bin/python -m sentineldns sync
```
Or use the **Blocklist Sources** section in the Web Dashboard (`/admin/sources`) with one-click **"Sync now"**.

---

## 4. Verification & Health Monitoring

1. **Check Live DNS Filtering**:
   ```bash
   dig @<OCI_INSTANCE_IP> doubleclick.net
   ```
2. **Review Query Performance**:
   Lookups take sub-millisecond in memory. Verify query latency with:
   ```bash
   dig @<OCI_INSTANCE_IP> cloudflare.com | grep "Query time"
   ```
3. **Inspect Application Logs**:
   ```bash
   journalctl -u sentineldns.service -f
   journalctl -u sentineldns-web.service -f
   ```
