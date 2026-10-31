"""DNS data plane: a filtering forwarder built on dnslib (UDP + TCP).

BLOCK  -> NXDOMAIN (default) or 0.0.0.0 / :: sinkhole answers
MONITOR-> forwarded upstream, hit recorded for review
ALLOW / PASS -> forwarded upstream
"""

from __future__ import annotations

import logging
import signal
import threading

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSError, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .alerts import AlertDispatcher
from .config import Settings
from .policy import PolicyEngine
from .recorder import HitRecorder
from .service import bootstrap

LOG = logging.getLogger(__name__)
SINKHOLE_TTL = 60


def build_block_reply(request: DNSRecord, mode: str) -> DNSRecord:
    """
    Builds a blocking response for the request.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    reply = request.reply()
    qname = request.q.qname
    qtype = request.q.qtype

    # --- CONDITIONS ---
    if mode == "zero" and qtype == QTYPE.A:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=SINKHOLE_TTL))  # nosec B104 # noqa: S104
    elif mode == "zero" and qtype == QTYPE.AAAA:
        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=SINKHOLE_TTL))
    elif mode != "zero":
        reply.header.rcode = RCODE.NXDOMAIN

    # --- RETURNS ---
    return reply


def forward_query(
    request: DNSRecord, upstream: str, port: int, timeout: float, tcp: bool
) -> DNSRecord:
    """
    Forwards a query upstream; returns SERVFAIL on timeout, parse error or ID mismatch.
    Complexity: Time O(1) network bound | Space O(P) packet size
    """
    # --- DATA ---
    reply = request.reply()
    reply.header.rcode = RCODE.SERVFAIL

    # --- CONDITIONS ---
    try:
        raw = request.send(upstream, port, tcp=tcp, timeout=timeout)
        upstream_reply = DNSRecord.parse(raw)
        if upstream_reply.header.id == request.header.id:
            reply = upstream_reply
        else:
            LOG.warning("Upstream reply ID mismatch for %s", request.q.qname)
    except (TimeoutError, OSError, DNSError) as exc:
        LOG.warning("Upstream failure for %s: %s", request.q.qname, exc)

    # --- RETURNS ---
    return reply


class FilteringResolver(BaseResolver):
    """dnslib resolver that consults the PolicyEngine before forwarding."""

    def __init__(
        self,
        settings: Settings,
        engine: PolicyEngine,
        recorder: HitRecorder,
        forwarder=forward_query,  # noqa: ANN001
    ) -> None:
        # --- DATA ---
        self._settings = settings
        self._engine = engine
        self._recorder = recorder
        self._forward = forwarder

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:  # noqa: ANN001
        """
        Decides, records, then blocks or forwards.
        Complexity: Time O(M) decision + upstream RTT | Space O(M)
        """
        # --- DATA ---
        settings = self._settings
        qname = str(request.q.qname)
        client_ip = handler.client_address[0] if handler is not None else "unknown"
        use_tcp = getattr(handler, "protocol", "udp") == "tcp"
        decision = self._engine.decide(qname)

        # --- CONDITIONS ---
        if decision.should_record:
            self._recorder.submit(decision, client_ip, "dns")

        if decision.is_blocked:
            reply = build_block_reply(request, settings.dns_block_mode)
        else:
            reply = self._forward(
                request,
                settings.dns_upstream,
                settings.dns_upstream_port,
                settings.dns_timeout,
                use_tcp,
            )

        # --- RETURNS ---
        return reply


def run_dns_server(settings: Settings) -> int:
    """
    Boots the engine, recorder and alert worker, then serves DNS until SIGINT/SIGTERM.
    Complexity: Time O(N log N) initial index build | Space O(N)
    """
    # --- DATA ---
    stop_event = threading.Event()
    dispatcher = AlertDispatcher(settings)
    engine = PolicyEngine(settings)
    recorder = HitRecorder(settings, dispatcher)
    resolver = FilteringResolver(settings, engine, recorder)
    quiet_logger = DNSLogger("error", prefix=False)
    servers: list[DNSServer] = []

    # --- CONDITIONS ---
    if not bootstrap(settings):
        LOG.error("Database initialization failed: %s", settings.db_path)
        return 1

    engine.reload(force=True)
    engine.start_watcher()
    dispatcher.start()
    recorder.start()

    for use_tcp in (False, True):
        server = DNSServer(
            resolver,
            port=settings.dns_port,
            address=settings.dns_host,
            tcp=use_tcp,
            logger=quiet_logger,
        )
        server.start_thread()
        servers.append(server)

    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    LOG.info(
        "SentinelDNS DNS listening on %s:%d (udp+tcp), upstream %s:%d",
        settings.dns_host,
        settings.dns_port,
        settings.dns_upstream,
        settings.dns_upstream_port,
    )
    while not stop_event.wait(1.0):
        pass

    for server in servers:
        server.stop()
    engine.stop()
    recorder.stop()

    # --- RETURNS ---
    return 0
