"""DNS wire format (RFC 1035): build and parse DNS messages.

Shared by Cathodemon's resolver and its DNS sinkhole server. Names inside record
data are decompressed when parsed, so records can be copied into new messages
safely. Standard library only.
"""
from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass, field, replace

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV = 1, 2, 5, 6, 12, 15, 16, 28, 33
DNAME, OPT, HTTPS, CAA = 39, 41, 65, 257
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", MX: "MX",
              TXT: "TXT", AAAA: "AAAA", SRV: "SRV", DNAME: "DNAME", OPT: "OPT",
              43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB",
              HTTPS: "HTTPS", 255: "ANY", CAA: "CAA"}
TYPES = {v: k for k, v in TYPE_NAMES.items()}

NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}

_NAME_TYPES = (NS, CNAME, PTR, DNAME)


def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"TYPE{t}")


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


@dataclass
class RR:
    name: str          # lowercase, no trailing dot
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes       # never contains compression pointers
    value: object = None

    def with_ttl(self, ttl: int) -> "RR":
        return replace(self, ttl=max(0, int(ttl)))


@dataclass
class Message:
    id: int
    flags: int
    questions: list = field(default_factory=list)   # [(name, qtype, qclass)], name as sent
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    edns_payload: int | None = None

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF


# ------------------------------------------------------------------ names
def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("latin-1")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"bad DNS label in {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > 255:
        raise ValueError("DNS name too long")
    return bytes(out)


def read_name(data: bytes, off: int):
    """Read a (possibly compressed) name. Returns (name, offset after the name)."""
    labels = []
    end = None
    jumps = 0
    total = 0
    while True:
        if off >= len(data):
            raise ValueError("name runs past end of message")
        length = data[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 64 or pointer >= len(data):
                raise ValueError("bad compression pointer")
            off = pointer
            continue
        if length & 0xC0:
            raise ValueError("unsupported label type")
        off += 1
        if length == 0:
            break
        if off + length > len(data):
            raise ValueError("label runs past end of message")
        labels.append(data[off:off + length].decode("latin-1"))
        total += length + 1
        if total > 255:
            raise ValueError("name too long")
        off += length
    return ".".join(labels), (end if end is not None else off)


# ------------------------------------------------------------------ records
def _decode_rdata(rtype: int, data: bytes, off: int, rdlen: int):
    raw = data[off:off + rdlen]
    if rtype in _NAME_TYPES:
        target = read_name(data, off)[0].lower()
        return encode_name(target), target
    if rtype == MX:
        pref = struct.unpack(">H", raw[:2])[0]
        exchange = read_name(data, off + 2)[0].lower()
        return raw[:2] + encode_name(exchange), (pref, exchange)
    if rtype == SOA:
        mname, p = read_name(data, off)
        rname, p = read_name(data, p)
        if p + 20 > len(data):
            raise ValueError("short SOA record")
        nums = struct.unpack(">IIIII", data[p:p + 20])
        value = {"mname": mname.lower(), "rname": rname.lower(), "serial": nums[0],
                 "refresh": nums[1], "retry": nums[2], "expire": nums[3], "minimum": nums[4]}
        return encode_name(mname) + encode_name(rname) + data[p:p + 20], value
    if rtype == SRV:
        prio, weight, port = struct.unpack(">HHH", raw[:6])
        target = read_name(data, off + 6)[0].lower()
        return raw[:6] + encode_name(target), (prio, weight, port, target)
    # Types below never contain compressed names, so the raw bytes are safe to copy.
    value = None
    try:
        if rtype == A and rdlen == 4:
            value = socket.inet_ntoa(raw)
        elif rtype == AAAA and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, raw)
        elif rtype == TXT:
            parts, i = [], 0
            while i < len(raw):
                n = raw[i]
                parts.append(raw[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            value = "".join(parts)
        elif rtype == CAA and rdlen >= 2:
            taglen = raw[1]
            value = {"flags": raw[0], "tag": raw[2:2 + taglen].decode("ascii", "replace"),
                     "value": raw[2 + taglen:].decode("utf-8", "replace")}
    except (ValueError, OSError, IndexError):
        value = None
    return raw, value


def _read_rr(data: bytes, off: int):
    name, off = read_name(data, off)
    if off + 10 > len(data):
        raise ValueError("truncated record header")
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
    off += 10
    if off + rdlen > len(data):
        raise ValueError("record data runs past end of message")
    try:
        rdata, value = _decode_rdata(rtype, data, off, rdlen)
    except struct.error as exc:
        raise ValueError("malformed record data") from exc
    if ttl >= 2 ** 31:  # RFC 2181: treat as zero
        ttl = 0
    return RR(name.lower(), rtype, rclass, ttl, rdata, value), off + rdlen


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise ValueError("message shorter than a DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off = read_name(data, off)
        if off + 4 > len(data):
            raise ValueError("truncated question")
        qtype, qclass = struct.unpack(">HH", data[off:off + 4])
        off += 4
        questions.append((name, qtype, qclass))
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            rr, off = _read_rr(data, off)
            records.append(rr)
        sections.append(records)
    answers, authority, additional = sections
    edns = next((rr.rclass for rr in additional if rr.rtype == OPT), None)
    return Message(qid, flags, questions, answers, authority, additional, edns)


# ------------------------------------------------------------------ building
def _opt_rr(payload: int) -> bytes:
    return b"\x00" + struct.pack(">HHIH", OPT, payload, 0, 0)


def build_query(name: str, qtype: int, rd: bool = True, edns_payload: int | None = None):
    """Return (id, packet)."""
    qid = secrets.randbelow(65536)
    flags = 0x0100 if rd else 0
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns_payload else 0)
    packet = header + encode_name(name) + struct.pack(">HH", qtype, 1)
    if edns_payload:
        packet += _opt_rr(edns_payload)
    return qid, packet


def encode_rr(rr: RR, owner: str | None = None) -> bytes:
    return (encode_name(owner if owner is not None else rr.name)
            + struct.pack(">HHIH", rr.rtype, rr.rclass, max(0, int(rr.ttl)), len(rr.rdata))
            + rr.rdata)


def build_response(query: Message, rcode: int, answers=(), authority=(),
                   max_size: int = 512, aa: bool = False) -> bytes:
    """Answer `query`. If the result is bigger than max_size, send an empty,
    truncated (TC) reply so the client retries over TCP."""
    flags = (0x8000 | (query.opcode << 11) | (0x0400 if aa else 0)
             | (query.flags & 0x0100) | 0x0080 | (rcode & 0xF))
    q_bytes = b""
    qname = ""
    if query.questions:
        qname, qtype, qclass = query.questions[0]
        q_bytes = encode_name(qname) + struct.pack(">HH", qtype, qclass)
    lower_q = normalize_name(qname)

    def owner(rr):  # keep the client's spelling of its own question name
        return qname.rstrip(".") if rr.name == lower_q else rr.name

    body = (b"".join(encode_rr(rr, owner(rr)) for rr in answers)
            + b"".join(encode_rr(rr) for rr in authority))
    opt = _opt_rr(1232) if query.edns_payload is not None else b""
    qd = 1 if query.questions else 0
    header = struct.pack(">HHHHHH", query.id, flags, qd, len(answers), len(authority), 1 if opt else 0)
    message = header + q_bytes + body + opt
    if len(message) > max_size:
        header = struct.pack(">HHHHHH", query.id, flags | 0x0200, qd, 0, 0, 1 if opt else 0)
        message = header + q_bytes + opt
    return message


def make_rr(name: str, rtype: int, ttl: int, value) -> RR:
    """Build a record from a Python value (used for sinkhole answers)."""
    if rtype == A:
        rdata = socket.inet_aton(value)
    elif rtype == AAAA:
        rdata = socket.inet_pton(socket.AF_INET6, value)
    else:
        raise ValueError(f"make_rr does not support {type_name(rtype)}")
    return RR(normalize_name(name), rtype, 1, ttl, rdata, value)
