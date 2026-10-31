from dataclasses import replace

from dnslib import QTYPE, RCODE, DNSRecord

from nehemiah_dns.alerts import AlertDispatcher
from nehemiah_dns.dns_server import FilteringResolver, build_block_reply
from nehemiah_dns.policy import PolicyEngine
from nehemiah_dns.recorder import HitRecorder


class FakeHandler:
    client_address = ("192.168.1.20", 50000)
    protocol = "udp"


def _resolver(settings, forwarded):
    engine = PolicyEngine(settings)
    engine.reload(force=True)
    recorder = HitRecorder(settings, AlertDispatcher(settings))

    def fake_forward(request, *_):
        forwarded.append(str(request.q.qname))
        return request.reply()

    return FilteringResolver(settings, engine, recorder, forwarder=fake_forward), recorder


def test_blocked_query_gets_nxdomain_and_is_recorded(settings):
    forwarded = []
    resolver, recorder = _resolver(settings, forwarded)
    reply = resolver.resolve(DNSRecord.question("ads.doubleclick.net"), FakeHandler())
    assert reply.header.rcode == RCODE.NXDOMAIN
    assert forwarded == []
    assert recorder.drain() == 1


def test_clean_query_is_forwarded(settings):
    forwarded = []
    resolver, recorder = _resolver(settings, forwarded)
    reply = resolver.resolve(DNSRecord.question("example.com"), FakeHandler())
    assert reply.header.rcode == RCODE.NOERROR
    assert forwarded == ["example.com."]
    assert recorder.drain() == 0


def test_zero_mode_sinkhole(settings):
    reply = build_block_reply(DNSRecord.question("x.com", "A"), "zero")
    assert str(reply.rr[0].rdata) == "0.0.0.0"
    reply6 = build_block_reply(DNSRecord.question("x.com", "AAAA"), "zero")
    assert reply6.rr[0].rtype == QTYPE.AAAA
    assert replace(settings, dns_block_mode="zero").dns_block_mode == "zero"
