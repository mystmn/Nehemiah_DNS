"""Flask control plane: admin UI + HTTP check API.

Security posture: session auth (scrypt/pbkdf2 hash), CSRF on every POST, login
throttling, strict CSP, SameSite=Strict cookies, bearer-token API, no inline JS.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import timedelta
from functools import wraps

from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from . import __version__, db
from .alerts import AlertDispatcher
from .blocklist import lookup_bisect, subtree, validate_source_url
from .config import VALID_ACTIONS, Settings, load_settings
from .domains import is_listable, normalize_category, normalize_domain
from .policy import PolicyEngine
from .recorder import HitRecorder
from .security import SECURITY_HEADERS, LoginThrottle, new_token, tokens_match
from .service import bootstrap, run_sync_async

LOG = logging.getLogger(__name__)
bp = Blueprint("nehemiah", __name__)
LOOPBACK = frozenset({"127.0.0.1", "::1"})
# Dummy hash so login timing is identical whether or not the username exists.
_DUMMY_HASH = generate_password_hash(new_token())


@dataclass
class Services:
    """Per-process singletons attached to the Flask app."""

    settings: Settings
    engine: PolicyEngine
    recorder: HitRecorder
    dispatcher: AlertDispatcher
    throttle: LoginThrottle


def services() -> Services:
    """
    Returns the Services container for the current app.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    container = current_app.extensions["nehemiah_dns"]

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return container


# =====================================================================
# APP FACTORY
# =====================================================================
def create_app(settings: Settings | None = None, *, start_workers: bool = True) -> Flask:
    """
    Builds the Flask app, refusing to start without a secret key and admin hash.
    Complexity: Time O(N log N) initial index build | Space O(N)
    """
    # --- DATA ---
    cfg = settings or load_settings()
    app = Flask(__name__)
    dispatcher = AlertDispatcher(cfg)
    engine = PolicyEngine(cfg)
    container = Services(cfg, engine, HitRecorder(cfg, dispatcher), dispatcher, LoginThrottle())

    # --- CONDITIONS ---
    if len(cfg.secret_key) < 32:
        raise RuntimeError("NEHEMIAH_SECRET_KEY must be set (>= 32 chars). See docs/INSTALL.md")
    if not cfg.admin_password_hash:
        raise RuntimeError(
            "NEHEMIAH_ADMIN_PASSWORD_HASH must be set. Run: python -m nehemiah_dns hash-password"
        )
    if not bootstrap(cfg):
        raise RuntimeError(f"Cannot initialize database at {cfg.db_path}")

    app.config.update(
        SECRET_KEY=cfg.secret_key,
        SESSION_COOKIE_NAME="nehemiah_session",
        SESSION_COOKIE_SECURE=cfg.cookie_secure,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if cfg.trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

    engine.reload(force=True)
    if start_workers:
        engine.start_watcher()
        dispatcher.start()
        container.recorder.start()

    app.extensions["nehemiah_dns"] = container
    app.register_blueprint(bp)
    app.before_request(_csrf_protect)
    app.after_request(_apply_security_headers)
    app.context_processor(lambda: {"csrf_token": _csrf_token, "version": __version__})

    # --- RETURNS ---
    return app


# =====================================================================
# REQUEST HOOKS & HELPERS
# =====================================================================
def _csrf_token() -> str:
    """
    Returns (creating if needed) the session CSRF token for templates.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    token = session.get("csrf_token")

    # --- CONDITIONS ---
    if not token:
        token = new_token()
        session["csrf_token"] = token

    # --- RETURNS ---
    return token


def _csrf_protect() -> None:
    """
    Rejects state-changing requests without a valid CSRF token (API uses bearer auth).
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    unsafe = request.method in ("POST", "PUT", "PATCH", "DELETE")
    is_api = request.path.startswith("/api/")

    # --- CONDITIONS ---
    if unsafe and not is_api:
        if not tokens_match(session.get("csrf_token"), request.form.get("csrf_token")):
            abort(400, description="Invalid CSRF token")

    # --- RETURNS ---
    return None


def _apply_security_headers(response):  # noqa: ANN001, ANN202
    """
    Adds CSP and hardening headers to every response.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    headers = dict(SECURITY_HEADERS)

    # --- CONDITIONS ---
    if services().settings.cookie_secure:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    for name, value in headers.items():
        response.headers.setdefault(name, value)

    # --- RETURNS ---
    return response


def login_required(view):  # noqa: ANN001, ANN201
    """
    Decorator enforcing an authenticated admin session.
    Complexity: Time O(1) | Space O(1)
    """

    @wraps(view)
    def wrapper(*args, **kwargs):  # noqa: ANN202
        # --- DATA ---
        user = session.get("user")

        # --- CONDITIONS ---
        if not user:
            return redirect(url_for("nehemiah.login"))

        # --- RETURNS ---
        return view(*args, **kwargs)

    return wrapper


def _client_ip() -> str:
    """
    Resolves the caller IP (honours ProxyFix when NEHEMIAH_TRUST_PROXY=1).
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    address = request.remote_addr or "unknown"

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return address


def _api_authorized() -> bool:
    """
    Bearer token if configured; otherwise only direct (non-proxied) loopback callers.
    Complexity: Time O(L) | Space O(1)
    """
    # --- DATA ---
    settings = services().settings
    header = request.headers.get("Authorization", "")
    provided = header[7:] if header.startswith("Bearer ") else ""
    authorized = False

    # --- CONDITIONS ---
    if settings.api_token:
        authorized = tokens_match(settings.api_token, provided)
    else:
        direct = "X-Forwarded-For" not in request.headers
        authorized = direct and _client_ip() in LOOPBACK

    # --- RETURNS ---
    return authorized


def _valid_ip(raw: str) -> str:
    """
    Returns a normalized IP string or '' if invalid.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    value = ""

    # --- CONDITIONS ---
    try:
        value = str(ipaddress.ip_address((raw or "").strip()))
    except ValueError:
        value = ""

    # --- RETURNS ---
    return value


def _changed(key: str) -> None:
    """
    Bumps a version counter and reloads this process immediately.
    Complexity: Time O(R + C) | Space O(R + C)
    """
    # --- DATA ---
    svc = services()

    # --- CONDITIONS ---
    conn = db.connect(svc.settings.db_path)
    try:
        db.bump_version(conn, key)
    finally:
        conn.close()
    svc.engine.reload()

    # --- RETURNS ---
    return None


# =====================================================================
# PUBLIC ENDPOINTS
# =====================================================================
@bp.get("/healthz")
def healthz():  # noqa: ANN201
    """
    Liveness probe (no sensitive data).
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    size = services().engine.state.snapshot.size

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return jsonify({"status": "ok", "domains": size})


@bp.get("/api/v1/check")
def check_domain_endpoint():  # noqa: ANN201
    """
    Checks a domain. 200 = allowed/monitored, 403 = blocked, 400 = bad input, 401 = auth.
    Optional ?client=<ip> lets an upstream proxy attribute the original client.
    Complexity: Time O(M) | Space O(M)
    """
    # --- DATA ---
    svc = services()
    raw_domain = request.args.get("domain", "")
    client_ip = _valid_ip(request.args.get("client", "")) or _client_ip()
    status_code = 200
    payload: dict = {}

    # --- CONDITIONS ---
    if not _api_authorized():
        return jsonify({"error": "unauthorized"}), 401

    domain = normalize_domain(raw_domain)
    if not domain:
        status_code = 400
        payload = {"error": "Missing or invalid domain parameter"}
    else:
        decision = svc.engine.decide(domain)
        svc.recorder.submit(decision, client_ip, "api")
        status_code = 403 if decision.is_blocked else 200
        payload = {
            "domain": domain,
            "blocked": decision.is_blocked,
            "action": decision.action,
            "category": decision.category,
            "matched": decision.matched,
            "origin": decision.origin,
        }

    # --- RETURNS ---
    return jsonify(payload), status_code


# =====================================================================
# AUTH
# =====================================================================
@bp.route("/login", methods=["GET", "POST"])
def login():  # noqa: ANN201
    """
    Admin login with constant-time checks and per-IP throttling.
    Complexity: Time O(1) + password KDF cost | Space O(1)
    """
    # --- DATA ---
    svc = services()
    settings = svc.settings
    ip = _client_ip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    response = None

    # --- CONDITIONS ---
    if request.method == "GET":
        return render_template("login.html")

    if svc.throttle.is_blocked(ip):
        flash("Too many failed attempts. Try again later.", "error")
        response = (render_template("login.html"), 429)
    else:
        user_ok = tokens_match(settings.admin_user, username)
        hash_to_check = settings.admin_password_hash if user_ok else _DUMMY_HASH
        try:
            password_ok = check_password_hash(hash_to_check, password)
        except ValueError:
            password_ok = False
        if user_ok and password_ok:
            svc.throttle.reset(ip)
            session.clear()
            session.permanent = True
            session["user"] = settings.admin_user
            session["csrf_token"] = new_token()
            LOG.info("Admin login from %s", ip)
            response = redirect(url_for("nehemiah.dashboard"))
        else:
            svc.throttle.record_failure(ip)
            LOG.warning("Failed admin login from %s", ip)
            flash("Invalid credentials.", "error")
            response = (render_template("login.html"), 401)

    # --- RETURNS ---
    return response


@bp.post("/logout")
def logout():  # noqa: ANN201
    """
    Clears the session.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    target = url_for("nehemiah.login")

    # --- CONDITIONS ---
    session.clear()

    # --- RETURNS ---
    return redirect(target)


# =====================================================================
# ADMIN UI
# =====================================================================
@bp.get("/")
def index():  # noqa: ANN201
    """
    Redirects to the dashboard.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    target = url_for("nehemiah.dashboard")

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return redirect(target)


@bp.get("/admin")
@login_required
def dashboard():  # noqa: ANN201
    """
    Dashboard: counters, pending review queue, recent hits.
    Complexity: Time O(k) bounded page sizes | Space O(k)
    """
    # --- DATA ---
    svc = services()
    status = request.args.get("status", "PENDING").upper()
    conn = db.connect(svc.settings.db_path)

    # --- CONDITIONS ---
    if status not in db.REVIEW_STATUSES:
        status = "PENDING"
    try:
        stats = db.dashboard_stats(conn)
        reviews = db.list_reviews(conn, status, 100)
        events = db.recent_events(conn, 25)
    finally:
        conn.close()

    # --- RETURNS ---
    return render_template(
        "dashboard.html",
        stats=stats,
        reviews=reviews,
        events=events,
        status=status,
        statuses=db.REVIEW_STATUSES,
        domain_count=svc.engine.state.snapshot.size,
        dropped=svc.recorder.dropped,
        alerts_enabled=svc.dispatcher.enabled,
    )


@bp.post("/admin/reviews")
@login_required
def review_action():  # noqa: ANN201
    """
    Applies a review decision: confirm -> BLOCK rule, allow -> ALLOW rule, dismiss.
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    svc = services()
    matched = normalize_domain(request.form.get("matched", ""))
    action = request.form.get("action", "")
    outcome = {"confirm": ("CONFIRMED", "BLOCK"), "allow": ("ALLOWED", "ALLOW"),
               "dismiss": ("DISMISSED", None)}

    # --- CONDITIONS ---
    if not matched or action not in outcome:
        abort(400)

    status, rule_action = outcome[action]
    conn = db.connect(svc.settings.db_path)
    try:
        row = conn.execute("SELECT category FROM reviews WHERE matched = ?", (matched,)).fetchone()
        if row is None:
            abort(404)
        db.set_review_status(conn, matched, status)
        if rule_action:
            db.upsert_rule(conn, matched, row["category"], rule_action, f"review:{action}")
    finally:
        conn.close()
    if rule_action:
        _changed(db.POLICY_VERSION)
    flash(f"{matched}: {status.lower()}", "success")

    # --- RETURNS ---
    return redirect(url_for("nehemiah.dashboard"))


@bp.route("/admin/rules", methods=["GET", "POST"])
@login_required
def rules():  # noqa: ANN201
    """
    Lists and creates admin override rules.
    Complexity: Time O(R) | Space O(R)
    """
    # --- DATA ---
    svc = services()
    domain = normalize_domain(request.form.get("domain", ""))
    action = request.form.get("action", "").upper()
    category = normalize_category(request.form.get("category", ""), "custom")
    note = request.form.get("note", "").strip()

    # --- CONDITIONS ---
    if request.method == "POST":
        if not is_listable(domain) or action not in VALID_ACTIONS:
            flash("Enter a valid domain (e.g. ads.example.com) and action.", "error")
        else:
            conn = db.connect(svc.settings.db_path)
            try:
                db.upsert_rule(conn, domain, category, action, note)
            finally:
                conn.close()
            _changed(db.POLICY_VERSION)
            flash(f"Rule saved: {action} {domain}", "success")
        return redirect(url_for("nehemiah.rules"))

    conn = db.connect(svc.settings.db_path)
    try:
        rows = db.list_rules(conn)
    finally:
        conn.close()

    # --- RETURNS ---
    return render_template("rules.html", rules=rows, actions=VALID_ACTIONS)


@bp.post("/admin/rules/delete")
@login_required
def delete_rule():  # noqa: ANN201
    """
    Deletes an admin rule.
    Complexity: Time O(log R) | Space O(1)
    """
    # --- DATA ---
    svc = services()
    domain = normalize_domain(request.form.get("domain", ""))

    # --- CONDITIONS ---
    if not domain:
        abort(400)
    conn = db.connect(svc.settings.db_path)
    try:
        db.delete_rule(conn, domain)
    finally:
        conn.close()
    _changed(db.POLICY_VERSION)
    flash(f"Rule removed: {domain}", "success")

    # --- RETURNS ---
    return redirect(url_for("nehemiah.rules"))


@bp.route("/admin/categories", methods=["GET", "POST"])
@login_required
def categories():  # noqa: ANN201
    """
    Lists categories and sets per-category actions.
    Complexity: Time O(C) | Space O(C)
    """
    # --- DATA ---
    svc = services()
    name = normalize_category(request.form.get("name", ""), "")
    action = request.form.get("action", "").upper()
    counts: dict[str, int] = {}

    # --- CONDITIONS ---
    if request.method == "POST":
        if not name or action not in VALID_ACTIONS:
            abort(400)
        conn = db.connect(svc.settings.db_path)
        try:
            db.set_category_action(conn, name, action)
        finally:
            conn.close()
        _changed(db.POLICY_VERSION)
        flash(f"Category '{name}' -> {action}", "success")
        return redirect(url_for("nehemiah.categories"))

    for category in svc.engine.state.snapshot.categories.values():
        counts[category] = counts.get(category, 0) + 1
    conn = db.connect(svc.settings.db_path)
    try:
        mapping = db.category_actions(conn)
    finally:
        conn.close()

    # --- RETURNS ---
    return render_template(
        "categories.html", categories=mapping, counts=counts, actions=VALID_ACTIONS
    )


@bp.route("/admin/sources", methods=["GET", "POST"])
@login_required
def sources():  # noqa: ANN201
    """
    Lists and adds remote (GitHub raw) list sources.
    Complexity: Time O(S) | Space O(S)
    """
    # --- DATA ---
    svc = services()
    settings = svc.settings
    url = request.form.get("url", "").strip()
    category = normalize_category(request.form.get("category", ""), "uncategorized")

    # --- CONDITIONS ---
    if request.method == "POST":
        error = validate_source_url(url, settings.allowed_source_hosts)
        if error:
            flash(error, "error")
        else:
            conn = db.connect(settings.db_path)
            try:
                added = db.add_source(conn, url, category)
            finally:
                conn.close()
            flash("Source added. Run Sync to fetch it." if added else "Source already exists.",
                  "success" if added else "error")
        return redirect(url_for("nehemiah.sources"))

    conn = db.connect(settings.db_path)
    try:
        rows = db.list_sources(conn)
    finally:
        conn.close()

    # --- RETURNS ---
    return render_template(
        "sources.html", sources=rows, allowed_hosts=settings.allowed_source_hosts,
        local_dir=settings.local_lists_dir,
    )


@bp.post("/admin/sources/<int:source_id>/<string:op>")
@login_required
def source_op(source_id: int, op: str):  # noqa: ANN201
    """
    Enables, disables or deletes a source.
    Complexity: Time O(log S) | Space O(1)
    """
    # --- DATA ---
    svc = services()

    # --- CONDITIONS ---
    if op not in ("enable", "disable", "delete"):
        abort(400)
    conn = db.connect(svc.settings.db_path)
    try:
        if op == "delete":
            db.delete_source(conn, source_id)
        else:
            db.set_source_enabled(conn, source_id, op == "enable")
    finally:
        conn.close()
    _changed(db.LIST_VERSION)
    flash(f"Source {op}d.", "success")

    # --- RETURNS ---
    return redirect(url_for("nehemiah.sources"))


@bp.post("/admin/sync")
@login_required
def sync_now():  # noqa: ANN201
    """
    Triggers a background sync of all enabled sources.
    Complexity: Time O(1) request; sync runs async | Space O(1)
    """
    # --- DATA ---
    started = run_sync_async(services().settings)

    # --- CONDITIONS ---
    flash("Sync started - refresh in a few seconds." if started else "Sync already running.",
          "success" if started else "error")

    # --- RETURNS ---
    return redirect(url_for("nehemiah.sources"))


@bp.get("/admin/lookup")
@login_required
def lookup():  # noqa: ANN201
    """
    Diagnostic lookup: decision, bisect cross-check and listed subdomains.
    Complexity: Time O(M log N + k) | Space O(k)
    """
    # --- DATA ---
    svc = services()
    raw = request.args.get("q", "")
    domain = normalize_domain(raw)
    decision = None
    bisect_match = None
    children: list[str] = []

    # --- CONDITIONS ---
    if raw and not domain:
        flash("Invalid domain.", "error")
    elif domain:
        state = svc.engine.state
        decision = svc.engine.decide(domain)
        bisect_match = lookup_bisect(state.snapshot, domain)
        children = subtree(state.snapshot, domain, 100)

    # --- RETURNS ---
    return render_template(
        "lookup.html", query=raw, decision=decision, bisect_match=bisect_match, children=children
    )
