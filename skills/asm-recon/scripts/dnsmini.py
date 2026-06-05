#!/usr/bin/env python3
"""
dnsmini — a tiny, dependency-free DNS client (pure Python standard library).

Provides just enough of a resolver for asm-recon so the skill needs no pip
packages. Supports the record types the collector uses:

    A, AAAA, CNAME, NS, SOA, MX, TXT, CAA

over UDP with automatic TCP fallback when a response is truncated, plus an
AXFR (zone transfer) client over TCP.

This is intentionally minimal — enough to read public records and attempt a
zone transfer, not a general-purpose resolver. It does not implement EDNS,
DNSSEC validation, retries beyond trying each configured nameserver once, or
caching. Every public function raises DNSError on hard failure; callers in
recon.py already wrap each lookup in try/except.

Design notes:
  * Recursive lookups set the RD (recursion-desired) bit and are sent to the
    system resolvers from /etc/resolv.conf (falling back to public resolvers
    if none can be read). For owned-domain public-record lookups this is a
    passive, no-impact operation.
  * Name decompression is bounded to prevent infinite loops on a malformed or
    hostile pointer chain (relevant for AXFR data from an untrusted server).
"""

import os
import random
import socket
import struct
import time

CLASS_IN = 1

TYPE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257, "AXFR": 252,
}

# Compression pointers and label chains are capped so a cyclic or hostile
# pointer can never spin the decoder forever.
_MAX_NAME_HOPS = 128

DEFAULT_TIMEOUT = 3      # per-server, per-transport socket timeout (seconds)
# Total budget across all servers for one query. Must comfortably exceed
# TIMEOUT * 2 (a dead first server can burn one UDP + one TCP timeout) so the
# public fallback tier in system_nameservers() still gets its turn.
DEFAULT_LIFETIME = 20
_FALLBACK_SERVERS = ("1.1.1.1", "9.9.9.9", "8.8.8.8")


class DNSError(Exception):
    """Raised when a query cannot be answered by any configured server."""


# --------------------------------------------------------------------------- #
# Nameserver discovery
# --------------------------------------------------------------------------- #

def system_nameservers():
    """
    Return resolver IPs to try, in order: those from /etc/resolv.conf first,
    then public resolvers as a fallback tier.

    The public fallbacks matter because a common desktop/server setup points
    resolv.conf at a single local stub resolver (systemd-resolved on
    127.0.0.53), which silently drops some oversized UDP answers (large TXT/SPF
    records) over both UDP and TCP. Without a second server to fall through to,
    those lookups would fail outright. query() only advances to a fallback when
    the preceding server gives no usable answer, so this adds no latency when
    the local resolver works.
    """
    servers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except Exception:
        pass
    for fb in _FALLBACK_SERVERS:
        if fb not in servers:
            servers.append(fb)
    return servers


# --------------------------------------------------------------------------- #
# Wire encoding / decoding
# --------------------------------------------------------------------------- #

def _encode_name(name):
    out = b""
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            try:
                lb = label.encode("idna") if any(ord(c) > 127 for c in label) \
                    else label.encode("ascii")
            except Exception:
                lb = label.encode("ascii", "ignore")
            if len(lb) > 63:
                raise DNSError(f"label too long: {label!r}")
            out += bytes([len(lb)]) + lb
    return out + b"\x00"


def _decode_name(msg, off):
    """Decode a (possibly compressed) name. Returns (name, next_offset)."""
    labels = []
    next_off = None
    hops = 0
    while True:
        hops += 1
        if hops > _MAX_NAME_HOPS:
            raise DNSError("name decompression exceeded hop limit")
        if off >= len(msg):
            raise DNSError("truncated name")
        length = msg[off]
        if (length & 0xC0) == 0xC0:                 # compression pointer
            if off + 1 >= len(msg):
                raise DNSError("truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | msg[off + 1]
            if next_off is None:
                next_off = off + 2
            off = ptr
            continue
        if length == 0:
            off += 1
            break
        off += 1
        labels.append(msg[off:off + length].decode("ascii", "ignore"))
        off += length
    if next_off is None:
        next_off = off
    return ".".join(labels), next_off


def _build_query(qname, qtype, want_recursion=True):
    txid = random.randint(0, 0xFFFF)
    flags = 0x0100 if want_recursion else 0x0000   # RD bit
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
    return txid, header + question


def _parse_rdata(rtype, msg, rdoff, rdlen):
    if rtype == TYPE["A"]:
        return socket.inet_ntop(socket.AF_INET, msg[rdoff:rdoff + 4])
    if rtype == TYPE["AAAA"]:
        return socket.inet_ntop(socket.AF_INET6, msg[rdoff:rdoff + 16])
    if rtype in (TYPE["CNAME"], TYPE["NS"], TYPE["PTR"]):
        name, _ = _decode_name(msg, rdoff)
        return name
    if rtype == TYPE["MX"]:
        pref = struct.unpack(">H", msg[rdoff:rdoff + 2])[0]
        exch, _ = _decode_name(msg, rdoff + 2)
        return (pref, exch)
    if rtype == TYPE["TXT"]:
        # One or more length-prefixed character-strings; per RFC 1035 they are
        # concatenated to form the record value.
        out, p, end = [], rdoff, rdoff + rdlen
        while p < end:
            slen = msg[p]
            p += 1
            out.append(msg[p:p + slen].decode("utf-8", "ignore"))
            p += slen
        return "".join(out)
    if rtype == TYPE["SOA"]:
        mname, p = _decode_name(msg, rdoff)
        rname, p = _decode_name(msg, p)
        serial, refresh, retry, expire, minimum = struct.unpack(
            ">IIIII", msg[p:p + 20])
        return (mname, rname, serial, refresh, retry, expire, minimum)
    if rtype == TYPE["CAA"]:
        flags = msg[rdoff]
        taglen = msg[rdoff + 1]
        tag = msg[rdoff + 2:rdoff + 2 + taglen].decode("ascii", "ignore")
        val = msg[rdoff + 2 + taglen:rdoff + rdlen].decode("utf-8", "ignore")
        return (flags, tag, val)
    return msg[rdoff:rdoff + rdlen]            # unknown type: raw bytes


def _rcode(msg):
    return struct.unpack(">H", msg[2:4])[0] & 0x000F


def _is_truncated(msg):
    return bool(struct.unpack(">H", msg[2:4])[0] & 0x0200)   # TC bit


def _parse_answers(msg):
    """Parse the ANSWER section. Returns list of (name, rtype, rdata)."""
    if len(msg) < 12:
        raise DNSError("short response")
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):                        # skip questions
        _, off = _decode_name(msg, off)
        off += 4
    records = []
    for _ in range(an):
        name, off = _decode_name(msg, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        records.append((name, rtype, _parse_rdata(rtype, msg, off, rdlen)))
        off += rdlen
    return records


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #

def _udp_exchange(server, packet, txid, timeout):
    af = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (server, 53))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data, _ = s.recvfrom(65535)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == txid:
                return data
        raise DNSError("no matching UDP response")
    finally:
        s.close()


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSError("connection closed")
        buf += chunk
    return buf


def _read_tcp_message(sock):
    (mlen,) = struct.unpack(">H", _recv_exactly(sock, 2))
    return _recv_exactly(sock, mlen)


def _tcp_exchange(server, packet, timeout):
    af = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(packet)) + packet)
        return _read_tcp_message(s)
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def query(qname, qtype_name, servers=None,
          timeout=DEFAULT_TIMEOUT, lifetime=DEFAULT_LIFETIME):
    """
    Resolve qname/qtype recursively. Returns a list of rdata values for
    answers whose type matches the request:

        A/AAAA  -> "1.2.3.4" / "::1"
        CNAME/NS-> "target.example."  (trailing dot as returned by server)
        MX      -> (preference:int, exchange:str)
        TXT     -> "concatenated string"
        CAA     -> (flags:int, tag:str, value:str)
        SOA     -> (mname, rname, serial, refresh, retry, expire, minimum)

    An empty list means the server answered with no matching records
    (e.g. NXDOMAIN or NODATA). Raises DNSError only if no server could be
    reached / parsed.
    """
    qtype = TYPE[qtype_name]
    server_list = servers if servers else system_nameservers()
    txid, packet = _build_query(qname, qtype)
    deadline = time.monotonic() + lifetime
    last = None
    for srv in server_list:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        per = min(timeout, remaining)
        try:
            try:
                resp = _udp_exchange(srv, packet, txid, per)
                if _is_truncated(resp):
                    resp = _tcp_exchange(srv, packet, min(timeout, remaining))
            except (socket.timeout, OSError):
                # No usable UDP reply (lost packet, or a stub resolver that
                # silently drops oversized answers, e.g. systemd-resolved).
                # Retry the same server over TCP before giving up on it.
                resp = _tcp_exchange(srv, packet, min(timeout, remaining))
            return [rd for (_n, rt, rd) in _parse_answers(resp) if rt == qtype]
        except Exception as e:        # try the next configured server
            last = e
            continue
    raise DNSError(f"{qname}/{qtype_name}: no usable response ({last})")


def axfr(server_ip, zone, timeout=10):
    """
    Attempt a zone transfer (AXFR) of `zone` from `server_ip` over TCP.

    Returns a de-duplicated, sorted list of fully-qualified owner names in the
    zone (as the server reported them). Raises DNSError if the transfer is
    refused, fails, or the connection drops before the closing SOA.

    A successful return is itself the finding: AXFR should be restricted to
    authorized secondaries.
    """
    txid, packet = _build_query(zone, TYPE["AXFR"], want_recursion=False)
    af = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(timeout)
    names = set()
    soa_seen = 0
    try:
        s.connect((server_ip, 53))
        s.sendall(struct.pack(">H", len(packet)) + packet)
        # The zone is bracketed by SOA records: it begins and ends with one.
        # Read messages until we have seen the second SOA.
        while soa_seen < 2:
            msg = _read_tcp_message(s)
            rc = _rcode(msg)
            if rc != 0:
                raise DNSError(f"AXFR refused (rcode {rc})")
            for (name, rtype, _rd) in _parse_answers(msg):
                names.add(name.rstrip(".").lower())
                if rtype == TYPE["SOA"]:
                    soa_seen += 1
    finally:
        s.close()
    return sorted(names)


# --------------------------------------------------------------------------- #
# Tiny manual test harness:  python3 dnsmini.py <name> <TYPE>
#                            python3 dnsmini.py axfr <ns-ip> <zone>
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 4 and sys.argv[1] == "axfr":
        for n in axfr(sys.argv[2], sys.argv[3]):
            print(n)
    elif len(sys.argv) >= 3:
        for rd in query(sys.argv[1], sys.argv[2].upper()):
            print(rd)
    else:
        print("usage: dnsmini.py <name> <TYPE> | dnsmini.py axfr <ns-ip> <zone>",
              file=sys.stderr)
        sys.exit(2)
