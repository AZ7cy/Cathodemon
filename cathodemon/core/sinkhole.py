"""Cathodemon DNS Shield: a DNS server for the home network that blocks ads,
trackers and look-alike phishing domains.

Blocked names get 0.0.0.0 (or :: for IPv6). Local names are answered here.
Everything else is looked up by Cathodemon's own resolver, which walks the DNS
hierarchy from the root, so no third-party DNS service is involved.
Listens on UDP and TCP. Standard library only.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import socketserver
import struct
import threading
import time
from collections import Counter, deque

from . import dnswire as w
from .resolver import Resolver, shared_resolver

BLOCK_TTL = 10       # seconds; short so unblocking takes effect quickly
LOCAL_TTL = 60
_UDP_LIMIT = 1232    # largest UDP reply we send, even if a client offers more


def lan_ip() -> str:
    """This machine's address on the local network (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("198.41.0.4", 53))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return True
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return addr.is_global


class Shield:
    def __init__(self, rules, resolver: Resolver | None = None, host: str = "0.0.0.0",
                 port: int = 53, local_only: bool = True, log_size: int = 500):
        self.rules = rules                 # swap in new Rules at any time
        self.resolver = resolver or shared_resolver()
        self.host = host
        self.port = port
        self.local_only = local_only       # refuse clients outside the local network
        self._udp = None
        self._tcp = None
        self._threads = []
        self._lock = threading.Lock()
        self.reset_stats()
        self.recent = deque(maxlen=log_size)

    # ------------------------------------------------------------------ stats
    def reset_stats(self):
        with self._lock:
            self.counts = Counter()
            self.top_blocked = Counter()
            self.started_at = None

    def stats(self) -> dict:
        with self._lock:
            c = dict(self.counts)
            top = self.top_blocked.most_common(10)
            recent = list(self.recent)[::-1]
        total = c.get("queries", 0)
        return {"queries": total, "blocked": c.get("blocked", 0), "allowed": c.get("allowed", 0),
                "local": c.get("local", 0), "refused": c.get("refused", 0),
                "failed": c.get("failed", 0),
                "blocked_pct": (100.0 * c.get("blocked", 0) / total) if total else 0.0,
                "uptime": (time.time() - self.started_at) if self.started_at else 0,
                "top_blocked": top, "recent": recent}

    def _record(self, client, name, qtype, action, reason, rcode):
        entry = {"time": time.time(), "client": client, "name": name,
                 "type": w.type_name(qtype), "action": action, "reason": reason,
                 "rcode": w.RCODE_NAMES.get(rcode, str(rcode))}
        with self._lock:
            self.counts["queries"] += 1
            self.counts[action] += 1
            if action == "allowed" and rcode == w.SERVFAIL:
                self.counts["failed"] += 1
            if action == "blocked":
                self.top_blocked[name] += 1
                if len(self.top_blocked) > 5000:
                    self.top_blocked = Counter(dict(self.top_blocked.most_common(1000)))
            self.recent.append(entry)

    # ------------------------------------------------------------------ core
    def handle(self, data: bytes, client_ip: str, transport: str = "udp"):
        """Answer one DNS query packet. Returns reply bytes, or None to stay silent."""
        try:
            query = w.parse_message(data)
        except ValueError:
            return None
        if query.is_response or len(query.questions) != 1:
            return None
        limit = 65535 if transport == "tcp" else min(max(query.edns_payload or 512, 512), _UDP_LIMIT)
        name, qtype, _qclass = query.questions[0]
        lname = w.normalize_name(name)

        if self.local_only and _is_public(client_ip):
            self._record(client_ip, lname, qtype, "refused", "client is outside the local network", w.REFUSED)
            return w.build_response(query, w.REFUSED, max_size=limit)
        if query.opcode != 0:
            return w.build_response(query, w.NOTIMP, max_size=limit)

        try:
            action, reason = self.rules.decide(lname)
        except Exception:  # noqa: BLE001 - a bad rule must not take DNS down
            action, reason = "allow", ""

        if action == "block":
            answers = []
            if qtype == w.A:
                answers = [w.make_rr(lname, w.A, BLOCK_TTL, "0.0.0.0")]
            elif qtype == w.AAAA:
                answers = [w.make_rr(lname, w.AAAA, BLOCK_TTL, "::")]
            self._record(client_ip, lname, qtype, "blocked", reason, w.NOERROR)
            return w.build_response(query, w.NOERROR, answers, max_size=limit)

        if action == "local":
            if lname == "localhost" or lname.endswith(".localhost"):
                answers = []
                if qtype == w.A:
                    answers = [w.make_rr(lname, w.A, LOCAL_TTL, "127.0.0.1")]
                elif qtype == w.AAAA:
                    answers = [w.make_rr(lname, w.AAAA, LOCAL_TTL, "::1")]
                rcode = w.NOERROR
            else:
                answers, rcode = [], w.NXDOMAIN
            self._record(client_ip, lname, qtype, "local", reason, rcode)
            return w.build_response(query, rcode, answers, max_size=limit)

        result = self.resolver.resolve(lname, qtype)
        authority = [rr for rr in result.authority if rr.rtype == w.SOA] if not result.records else []
        self._record(client_ip, lname, qtype, "allowed", reason, result.rcode)
        return w.build_response(query, result.rcode, result.records, authority, max_size=limit)

    # ------------------------------------------------------------------ server
    @property
    def running(self) -> bool:
        return self._udp is not None

    def start(self):
        """Start listening. Raises OSError if the address/port can't be used."""
        if self.running:
            return
        shield = self

        class UDPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                reply = shield.handle(data, self.client_address[0], "udp")
                if reply:
                    sock.sendto(reply, self.client_address)

        class TCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                conn = self.request
                conn.settimeout(10)
                try:
                    while True:
                        head = _recv_exact(conn, 2)
                        if head is None:
                            return
                        data = _recv_exact(conn, struct.unpack(">H", head)[0])
                        if data is None:
                            return
                        reply = shield.handle(data, self.client_address[0], "tcp")
                        if not reply:
                            return
                        conn.sendall(struct.pack(">H", len(reply)) + reply)
                except OSError:
                    return

        udp = _UDPServer((self.host, self.port), UDPHandler)
        port = udp.server_address[1]        # port 0 means "pick a free one"
        try:
            tcp = _TCPServer((self.host, port), TCPHandler)
        except OSError:
            udp.server_close()
            raise
        self._udp, self._tcp, self.port = udp, tcp, port
        with self._lock:
            self.started_at = time.time()
        self._threads = [threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5},
                                          daemon=True) for srv in (udp, tcp)]
        for t in self._threads:
            t.start()

    def stop(self):
        for srv in (self._udp, self._tcp):
            if srv is not None:
                srv.shutdown()
                srv.server_close()
        self._udp = self._tcp = None
        self._threads = []
        with self._lock:
            self.started_at = None


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class _UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    block_on_close = False
    # On Windows SO_REUSEADDR lets another program grab the same port, so only use it elsewhere.
    allow_reuse_address = os.name != "nt"
