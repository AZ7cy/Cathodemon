"""Tests for Cathodemon's own DNS code: wire format, resolver, sinkhole.
Talks to the real DNS hierarchy (root servers and down). Stdlib only."""
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cathodemon.core import dnswire as w

ok = True


def check(label, cond, extra=""):
    global ok
    ok = ok and bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {label}{(' - ' + extra) if extra else ''}")


print("== wire format ==")
qid, packet = w.build_query("example.com", w.A, rd=True, edns_payload=1232)
q = w.parse_message(packet)
check("query round-trips", q.id == qid and q.questions[0][0] == "example.com" and q.edns_payload == 1232)
resp = w.build_response(q, w.NOERROR, [w.make_rr("example.com", w.A, 60, "0.0.0.0")], max_size=512)
r = w.parse_message(resp)
check("response round-trips", r.is_response and r.answers[0].value == "0.0.0.0" and r.answers[0].ttl == 60)
big = [w.make_rr("example.com", w.A, 60, f"10.0.{i // 250}.{i % 250}") for i in range(60)]
tr = w.parse_message(w.build_response(q, w.NOERROR, big, max_size=512))
check("oversize UDP reply is truncated", tr.truncated and not tr.answers)

print("\n== live: ask a root server directly ==")
qid, packet = w.build_query("com", w.NS, rd=False, edns_payload=1232)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(4)
    s.connect(("198.41.0.4", 53))  # a.root-servers.net
    s.send(packet)
    data = s.recv(65535)
m = w.parse_message(data)
ns = [rr.value for rr in m.authority + m.answers if rr.rtype == w.NS]
glue = [rr for rr in m.additional if rr.rtype == w.A]
check("root answered", m.is_response and m.id == qid, f"rcode={w.RCODE_NAMES.get(m.rcode)}")
check("root lists .com servers", any(n.endswith("gtld-servers.net") for n in ns), f"{len(ns)} NS, e.g. {ns[:1]}")
check("root sends glue addresses", len(glue) > 0, f"{len(glue)} A records, e.g. {glue[0].name}={glue[0].value}" if glue else "")

print("\n== live: our own resolver, starting at the root ==")
import time
from cathodemon.core.resolver import Resolver

res = Resolver()


def values(ans, rtype):
    return [rr.value for rr in ans.records if rr.rtype == rtype]


t0 = time.time()
a = res.resolve("github.com", w.A)
first = time.time() - t0
check("github.com A", a.rcode == w.NOERROR and values(a, w.A), f"{values(a, w.A)} in {first:.2f}s")
t0 = time.time()
a2 = res.resolve("github.com", w.A)
check("second lookup comes from cache", values(a2, w.A) and time.time() - t0 < 0.05,
      f"{(time.time() - t0) * 1000:.1f} ms")
www = res.resolve("www.github.com", w.A)
check("alias chain followed", values(www, w.CNAME) and values(www, w.A),
      f"CNAME {values(www, w.CNAME)} -> {values(www, w.A)}")
mx = res.resolve("github.com", w.MX)
check("MX records", values(mx, w.MX), str(values(mx, w.MX)[:1]))
txt = res.resolve("github.com", w.TXT)
check("TXT records (large reply)", len(values(txt, w.TXT)) >= 5, f"{len(values(txt, w.TXT))} records")
caa = res.resolve("google.com", w.CAA)
check("CAA records", values(caa, w.CAA), str(values(caa, w.CAA)[:1]))
aaaa = res.resolve("google.com", w.AAAA)
check("AAAA records", values(aaaa, w.AAAA), str(values(aaaa, w.AAAA)[:1]))
nx = res.resolve("this-name-does-not-exist-cathodemon-test.com", w.A)
check("missing name gives NXDOMAIN", nx.rcode == w.NXDOMAIN, w.RCODE_NAMES.get(nx.rcode))
wiki = res.resolve("wikipedia.org", w.A)
check("another TLD (.org)", values(wiki, w.A), str(values(wiki, w.A)))

print("\n== live: DNS Shield server on 127.0.0.1 ==")
import struct
from cathodemon.core.blocklist import load_rules
from cathodemon.core.sinkhole import Shield

shield = Shield(load_rules(), res, host="127.0.0.1", port=0)
shield.start()
port = shield.port


def ask_udp(name, qtype, edns=1232):
    qid, pkt = w.build_query(name, qtype, edns_payload=edns)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.sendto(pkt, ("127.0.0.1", port))
        return w.parse_message(s.recv(65535))


def ask_tcp(name, qtype):
    qid, pkt = w.build_query(name, qtype)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        n = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < n:
            data += s.recv(n - len(data))
        return w.parse_message(data)


def vals(m, rtype):
    return [rr.value for rr in m.answers if rr.rtype == rtype]


m = ask_udp("ads.doubleclick.net", w.A)
check("ad domain -> 0.0.0.0", vals(m, w.A) == ["0.0.0.0"])
m = ask_udp("ads.doubleclick.net", w.AAAA)
check("ad domain IPv6 -> ::", vals(m, w.AAAA) == ["::"])
m = ask_udp("ads.doubleclick.net", w.HTTPS)
check("ad domain other types -> empty answer", m.rcode == w.NOERROR and not m.answers)
m = ask_udp("g00gle.com", w.A)
check("look-alike phishing domain -> 0.0.0.0", vals(m, w.A) == ["0.0.0.0"])
m = ask_udp("github.com", w.A)
check("normal site resolved by our resolver", vals(m, w.A) and vals(m, w.A) != ["0.0.0.0"], str(vals(m, w.A)))
m = ask_udp("www.github.com", w.A)
check("alias chain passed through", vals(m, w.CNAME) and vals(m, w.A), f"{vals(m, w.CNAME)} {vals(m, w.A)}")
m = ask_udp("printer", w.A)
check("local name -> NXDOMAIN (not sent out)", m.rcode == w.NXDOMAIN)
m = ask_udp("use-application-dns.net", w.A)
check("Firefox canary -> NXDOMAIN", m.rcode == w.NXDOMAIN)
m = ask_udp("localhost", w.A)
check("localhost -> 127.0.0.1", vals(m, w.A) == ["127.0.0.1"])
m = ask_udp("this-name-does-not-exist-cathodemon-test.com", w.A)
check("missing name -> NXDOMAIN", m.rcode == w.NXDOMAIN)
m = ask_udp("github.com", w.TXT, edns=None)
check("big reply over plain UDP is truncated", m.truncated and not m.answers)
m = ask_tcp("github.com", w.TXT)
check("same query over TCP gets everything", len(vals(m, w.TXT)) >= 5, f"{len(vals(m, w.TXT))} TXT records")
_qid, pkt = w.build_query("github.com", w.A)
refused = w.parse_message(shield.handle(pkt, "8.8.8.8", "udp"))
check("client outside the local network refused", refused.rcode == w.REFUSED)
st = shield.stats()
check("stats counted", st["queries"] >= 12 and st["blocked"] >= 4 and st["local"] >= 3,
      f"queries={st['queries']} blocked={st['blocked']} local={st['local']} refused={st['refused']}")
check("query log kept", st["recent"] and st["recent"][0]["name"] == "github.com")
shield.stop()
check("server stopped", not shield.running)

print("\n" + ("ALL DNS CHECKS PASSED" if ok else "SOME DNS CHECKS FAILED"))
sys.exit(0 if ok else 1)
