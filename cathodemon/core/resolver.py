"""Cathodemon's own recursive DNS resolver.

It walks the DNS hierarchy itself: a root server says which servers handle
".com", those say which servers handle "example.com", and those give the
answer. No third-party resolver service (Cloudflare, Google, Quad9...) is
involved. Answers are cached for their TTL. Standard library only.

Defences: random query IDs and source ports, replies must match the question,
and only records inside the zone being asked about are trusted (bailiwick).
DNSSEC is not validated.
"""
from __future__ import annotations

import random
import socket
import struct
import threading
import time

from . import dnswire as w

# The 13 root server addresses (IANA root hints).
ROOT_SERVERS = (
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
)

_MAX_CNAME = 12        # aliases followed per lookup
_MAX_DEPTH = 6         # nested lookups needed to find name-server addresses
_MAX_QUERIES = 80      # network queries allowed per lookup
_MAX_STEPS = 24        # referrals followed per name
_MAX_SECONDS = 8.0     # give up on one lookup after this long
_NEG_TTL = 300
_MAX_TTL = 86400
_CACHE_LIMIT = 20000


def in_zone(name: str, zone: str) -> bool:
    return zone == "" or name == zone or name.endswith("." + zone)


class Answer:
    __slots__ = ("rcode", "records", "authority")

    def __init__(self, rcode, records=(), authority=()):
        self.rcode = rcode
        self.records = list(records)
        self.authority = list(authority)


class _OutOfBudget(Exception):
    pass


class _Budget:
    """Caps both the number of network queries and the wall-clock time of one lookup."""

    def __init__(self, n, seconds):
        self.left = n
        self.deadline = time.monotonic() + seconds

    def spend(self):
        self.left -= 1
        if self.left < 0 or time.monotonic() > self.deadline:
            raise _OutOfBudget()


def _udp(ip, packet, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect((ip, 53))
        s.send(packet)
        return s.recv(65535)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def _tcp(ip, packet, timeout):
    with socket.create_connection((ip, 53), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(packet)) + packet)
        length = struct.unpack(">H", _recv_exact(s, 2))[0]
        return _recv_exact(s, length)


def _matches(msg, qid, name, qtype):
    return (msg.is_response and msg.id == qid and msg.questions
            and w.normalize_name(msg.questions[0][0]) == name and msg.questions[0][1] == qtype)


class Resolver:
    def __init__(self, timeout: float = 2.0, attempts: int = 3):
        self.timeout = timeout
        self.attempts = attempts          # servers tried per step
        self._answers = {}                # (name, qtype) -> (expires_at, Answer)
        self._zones = {}                  # zone -> (expires_at, [ipv4, ...])
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- public
    def resolve(self, name: str, qtype: int) -> Answer:
        name = w.normalize_name(name)
        try:
            return self._resolve(name, qtype, 0, _Budget(_MAX_QUERIES, _MAX_SECONDS))
        except _OutOfBudget:
            return Answer(w.SERVFAIL)

    def cache_size(self) -> int:
        with self._lock:
            return len(self._answers)

    # ---------------------------------------------------------------- cache
    def _cache_get(self, key):
        now = time.time()
        with self._lock:
            hit = self._answers.get(key)
            if not hit:
                return None
            expires, ans = hit
            if expires <= now:
                del self._answers[key]
                return None
        left = max(1, int(expires - now))
        return Answer(ans.rcode, [rr.with_ttl(left) for rr in ans.records],
                      [rr.with_ttl(left) for rr in ans.authority])

    def _cache_put(self, key, ans):
        if ans.rcode == w.NOERROR and ans.records:
            ttl = min(rr.ttl for rr in ans.records)
        elif ans.rcode in (w.NOERROR, w.NXDOMAIN):
            soa = next((rr for rr in ans.authority if rr.rtype == w.SOA), None)
            ttl = min(soa.ttl, soa.value["minimum"]) if soa and soa.value else _NEG_TTL
            ttl = min(ttl, 3600)
        else:
            return  # never cache failures
        ttl = max(0, min(ttl, _MAX_TTL))
        if ttl == 0:
            return
        with self._lock:
            if len(self._answers) >= _CACHE_LIMIT:
                self._prune()
            self._answers[key] = (time.time() + ttl, ans)

    def _prune(self):
        now = time.time()
        for key in [k for k, (exp, _a) in self._answers.items() if exp <= now]:
            del self._answers[key]
        if len(self._answers) >= _CACHE_LIMIT:  # still full: drop the oldest half
            for key in list(self._answers)[: len(self._answers) // 2]:
                del self._answers[key]

    def _closest_zone(self, name):
        labels = name.split(".") if name else []
        now = time.time()
        with self._lock:
            for i in range(len(labels)):
                zone = ".".join(labels[i:])
                hit = self._zones.get(zone)
                if hit and hit[0] > now:
                    return zone, list(hit[1])
        return "", list(ROOT_SERVERS)

    # ---------------------------------------------------------------- lookup
    def _resolve(self, name, qtype, depth, budget):
        key = (name, qtype)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        chain, seen, current = [], {name}, name
        ans = Answer(w.SERVFAIL)
        for _ in range(_MAX_CNAME):
            rcode, records, authority = self._iterate(current, qtype, depth, budget)
            if rcode != w.NOERROR:
                ans = Answer(rcode, chain, authority)
                break
            link, final = current, []
            while True:  # follow aliases that this reply already answers
                final = [rr for rr in records if rr.name == link and rr.rtype == qtype]
                if final:
                    break
                alias = next((rr for rr in records if rr.name == link and rr.rtype == w.CNAME), None)
                if alias is None:
                    break
                chain.append(alias)
                link = alias.value
                if link in seen:
                    return Answer(w.SERVFAIL)  # alias loop
                seen.add(link)
            if final:
                ans = Answer(w.NOERROR, chain + final)
                break
            if link != current:  # alias points outside this reply: ask its own servers
                current = link
                continue
            ans = Answer(w.NOERROR, chain, authority)  # the name exists, no records of this type
            break
        self._cache_put(key, ans)
        return ans

    def _iterate(self, name, qtype, depth, budget):
        """Walk referrals for one name. Returns (rcode, records, authority)."""
        zone, servers = self._closest_zone(name)
        for _ in range(_MAX_STEPS):
            msg = self._ask(servers, name, qtype, budget)
            if msg is None:
                return w.SERVFAIL, [], []
            soa = [rr for rr in msg.authority if rr.rtype == w.SOA and in_zone(rr.name, zone)]
            if msg.rcode == w.NXDOMAIN:
                return w.NXDOMAIN, [], soa
            answers = [rr for rr in msg.answers if in_zone(rr.name, zone)]
            if answers:
                return w.NOERROR, answers, []
            referral = self._referral(msg, name, zone)
            if referral is None:
                return w.NOERROR, [], soa
            child, ns_names, glue, ttl = referral
            ips = glue or self._addresses_of(ns_names, depth, budget)
            if not ips:
                return w.SERVFAIL, [], []
            with self._lock:
                self._zones[child] = (time.time() + min(max(ttl, 60), _MAX_TTL), ips)
            zone, servers = child, ips
        return w.SERVFAIL, [], []

    @staticmethod
    def _referral(msg, name, zone):
        ns = [rr for rr in msg.authority if rr.rtype == w.NS and rr.name != zone
              and in_zone(rr.name, zone) and in_zone(name, rr.name)]
        if not ns:
            return None
        child = max((rr.name for rr in ns), key=len)
        ns = [rr for rr in ns if rr.name == child]
        names = [rr.value for rr in ns if rr.value]
        glue = [rr.value for rr in msg.additional
                if rr.rtype == w.A and rr.value and rr.name in names and in_zone(rr.name, zone)]
        return child, names, glue, min(rr.ttl for rr in ns)

    def _addresses_of(self, ns_names, depth, budget):
        if depth >= _MAX_DEPTH:
            return []
        names = list(ns_names)
        random.shuffle(names)
        for ns_name in names[:4]:
            ans = self._resolve(ns_name, w.A, depth + 1, budget)
            ips = [rr.value for rr in ans.records if rr.rtype == w.A and rr.value]
            if ips:
                return ips
        return []

    def _ask(self, servers, name, qtype, budget):
        pool = list(dict.fromkeys(servers))
        random.shuffle(pool)
        for ip in pool[: self.attempts]:
            budget.spend()
            msg = self._exchange(ip, name, qtype)
            if msg is not None and msg.rcode in (w.NOERROR, w.NXDOMAIN):
                return msg
        return None

    def _exchange(self, ip, name, qtype, edns=True):
        qid, packet = w.build_query(name, qtype, rd=False, edns_payload=1232 if edns else None)
        try:
            msg = w.parse_message(_udp(ip, packet, self.timeout))
            if not _matches(msg, qid, name, qtype):
                return None
            if msg.truncated:
                msg = w.parse_message(_tcp(ip, packet, self.timeout + 1.0))
                if not _matches(msg, qid, name, qtype):
                    return None
            if msg.rcode == w.FORMERR and edns:  # very old server: retry without EDNS
                return self._exchange(ip, name, qtype, edns=False)
            return msg
        except (OSError, ValueError, struct.error):
            return None


_shared = None
_shared_lock = threading.Lock()


def shared_resolver() -> Resolver:
    """One resolver (and cache) per process."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = Resolver()
        return _shared
