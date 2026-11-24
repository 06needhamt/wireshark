#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate MASQUE requests over HTTP/3 between an in-process aioquic client and
proxy: connect-udp (RFC 9298) carrying a DNS query in an HTTP Datagram and
its response in a DATAGRAM capsule, with QUIC-aware proxying capsules; bound
connect-udp (draft-ietf-masque-connect-udp-listen-16) with compression
contexts; connect-ip (RFC 9484) with address, route, DNS_ASSIGN and PREF64
capsules and an IP packet; and connect-ethernet with an Ethernet frame. The
TLS secrets are embedded in a Decryption Secrets Block so that the capture
decrypts without a keylog file.

Requires: pip install aioquic
Usage: generate-masque-capture.py OUTPUT.pcapng.gz
"""

import argparse
import datetime
import gzip
import io
import socket
import struct

from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CLIENT = ("192.0.2.1", 50000)
SERVER = ("192.0.2.2", 4443)


def qv(value):
    """QUIC variable-length integer."""
    for length, prefix in ((1, 0x00), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if value < 1 << (8 * length - 2):
            raw = bytearray(value.to_bytes(length, "big"))
            raw[0] |= prefix
            return bytes(raw)
    raise ValueError(value)


def vi(value):
    """MOQT vi64: leading 1 bits of the first byte give the length."""
    for length in range(1, 9):
        if value < 1 << (7 * length):
            prefix = (0xFF00 >> (length - 1)) & 0xFF
            raw = value.to_bytes(length, "big")
            return bytes([raw[0] | prefix]) + raw[1:]
    return b"\xff" + value.to_bytes(8, "big")


def moqt_msg(mtype, body):
    """A draft-23 control message: Type and Length are vi64."""
    return vi(mtype) + vi(len(body)) + body


def moqt_lp(data):
    return vi(len(data)) + data


def capsule(ctype, value):
    return qv(ctype) + qv(len(value)) + value


def lite_msg(body):
    return qv(len(body)) + body


def lite_s(text):
    return qv(len(text)) + text.encode()


class Session:
    def __init__(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy.example")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("proxy.example")]), False)
                .sign(key, hashes.SHA256()))
        self.keylog = io.StringIO()
        ccfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=65536,
                                 server_name="proxy.example", secrets_log_file=self.keylog)
        ccfg.verify_mode = 0
        scfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_datagram_frame_size=65536)
        scfg.certificate, scfg.private_key = cert, key
        self.now = 1790000000.0
        self.client = QuicConnection(configuration=ccfg)
        self.server = QuicConnection(configuration=scfg,
                                     original_destination_connection_id=self.client.original_destination_connection_id)
        self.packets = []
        self.client.connect(SERVER, now=self.now)
        self.flush()
        self.h3c = H3Connection(self.client, enable_datagrams=True)
        self.h3s = H3Connection(self.server, enable_datagrams=True)
        self.flush()

    def pump(self, quic, h3):
        while (event := quic.next_event()) is not None:
            if h3 is not None:
                h3.handle_event(event)

    def flush(self):
        """Exchange datagrams until both sides go quiet."""
        while True:
            moved = False
            for src, dst, src_addr, dst_addr in ((self.client, self.server, CLIENT, SERVER),
                                                 (self.server, self.client, SERVER, CLIENT)):
                for data, _ in src.datagrams_to_send(now=self.now):
                    self.now += 0.001
                    self.packets.append((self.now, src_addr, dst_addr, data))
                    dst.receive_datagram(data, src_addr, now=self.now)
                    moved = True
            self.pump(self.client, getattr(self, "h3c", None))
            self.pump(self.server, getattr(self, "h3s", None))
            if not moved:
                break

    def send(self, quic, stream_id, data, end=False):
        quic.send_stream_data(stream_id, data, end)
        self.flush()


def write_pcapng(path, packets, keylog):
    def block(block_type, body):
        body += b"\0" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    def ip_checksum(header):
        total = sum(struct.unpack("!10H", header))
        total = (total & 0xFFFF) + (total >> 16)
        return ~((total & 0xFFFF) + (total >> 16)) & 0xFFFF

    def frame(src, dst, payload):
        udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                         bytes(map(int, src[0].split("."))), bytes(map(int, dst[0].split("."))))
        ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
        macs = {CLIENT: b"\x02\0\0\0\0\x01", SERVER: b"\x02\0\0\0\0\x02"}
        return macs[dst] + macs[src] + b"\x08\x00" + ip + udp

    secrets = keylog.encode()
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", 1, 0, 0))
    out += block(0x0000000A, struct.pack("<II", 0x544C534B, len(secrets)) + secrets)
    for ts, src, dst, payload in packets:
        data = frame(src, dst, payload)
        usec = int(ts * 1e6)
        out += block(0x00000006, struct.pack("<IIIII", 0, usec >> 32, usec & 0xFFFFFFFF, len(data), len(data)) + data)
    with gzip.GzipFile(path, "wb", mtime=0) as f:
        f.write(out)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    return ~((total & 0xFFFF) + (total >> 16)) & 0xFFFF


def ipv4_icmp_echo(src, dst):
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


def dns_query(qid, name, response=False):
    flags = 0x8180 if response else 0x0100
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    out = struct.pack("!HHHHHH", qid, flags, 1, 1 if response else 0, 0, 0) + question + struct.pack("!HH", 1, 1)
    if response:
        out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("192.0.2.80")
    return out


def request(ses, protocol, path, extra=()):
    sid = ses.client.get_next_available_stream_id()
    ses.h3c.send_headers(sid, [
        (b":method", b"CONNECT"), (b":protocol", protocol.encode()), (b":scheme", b"https"),
        (b":authority", b"proxy.example"), (b":path", path.encode()),
        (b"capsule-protocol", b"?1"), *extra])
    ses.flush()
    ses.h3s.send_headers(sid, [(b":status", b"200"), (b"capsule-protocol", b"?1")])
    ses.flush()
    return sid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    ses = Session()

    # connect-udp to a DNS server, with QUIC-aware proxying capsules.
    udp = request(ses, "connect-udp", "/.well-known/masque/udp/192.0.2.53/53/")
    ses.h3c.send_datagram(udp, qv(0) + dns_query(0x1234, "www.example"))
    ses.flush()
    ses.h3s.send_data(udp, capsule(0x00, qv(0) + dns_query(0x1234, "www.example", True)), False)
    ses.flush()
    ses.h3c.send_data(udp, capsule(0xFFE900, qv(0) + bytes.fromhex("c1c2c3c4")), False)
    ses.flush()
    ses.h3s.send_data(udp, capsule(0xFFE902, qv(0)) + capsule(0xFFE809, qv(4)), False)
    ses.flush()

    # Bound UDP proxying with an uncompressed and a compressed context.
    bound = request(ses, "connect-udp", "/.well-known/masque/udp/%2A/%2A/",
                    [(b"connect-udp-bind", b"?1")])
    ses.h3c.send_data(bound, capsule(0x11, qv(2) + bytes([0])) +
                      capsule(0x11, qv(4) + bytes([4]) + socket.inet_aton("198.51.100.7") +
                              struct.pack("!H", 4000)), False)
    ses.flush()
    ses.h3s.send_data(bound, capsule(0x12, qv(2)) + capsule(0x12, qv(4)), False)
    ses.flush()
    ses.h3c.send_datagram(bound, qv(2) + bytes([4]) + socket.inet_aton("203.0.113.9") +
                          struct.pack("!H", 5000) + b"uncompressed")
    ses.h3c.send_datagram(bound, qv(4) + b"compressed")
    ses.h3c.send_datagram(bound, qv(0) + b"not allowed")
    ses.h3c.send_datagram(bound, qv(6) + b"unknown context")
    ses.flush()
    ses.h3c.send_data(bound, capsule(0x13, qv(4)), False)
    ses.flush()

    # connect-ip with its configuration capsules and one IP packet.
    ip = request(ses, "connect-ip", "/.well-known/masque/ip/*/*/")
    ses.h3c.send_data(ip, capsule(0x02, qv(1) + bytes([4]) + socket.inet_aton("0.0.0.0") + bytes([32])), False)
    ses.flush()
    assign = (qv(1) + bytes([4]) + socket.inet_aton("192.0.2.10") + bytes([32]) +
              qv(2) + bytes([6]) + socket.inet_pton(socket.AF_INET6, "2001:db8::10") + bytes([128]))
    route = bytes([4]) + socket.inet_aton("0.0.0.0") + socket.inet_aton("255.255.255.255") + bytes([0])
    nameserver = (struct.pack("!H", 1) + qv(1) + socket.inet_aton("192.0.2.53") + qv(0) +
                  qv(11) + b"dns.example" + qv(0))
    dns = qv(1) + nameserver + qv(1) + qv(12) + b"corp.example" + qv(1) + qv(7) + b"example"
    pref64 = bytes([96]) + socket.inet_pton(socket.AF_INET6, "64:ff9b::")[:12]
    ses.h3s.send_data(ip, capsule(0x01, assign) + capsule(0x03, route) +
                      capsule(0x1ACE79EC, dns) + capsule(0x274C0FBC, pref64), False)
    ses.flush()
    ses.h3c.send_datagram(ip, qv(0) + ipv4_icmp_echo("192.0.2.10", "198.51.100.1"))
    ses.flush()

    # connect-ethernet with an ARP request.
    eth = request(ses, "connect-ethernet", "/.well-known/masque/ethernet/")
    arp = (b"\xff" * 6 + bytes.fromhex("020000000010") + b"\x08\x06" +
           struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("020000000010") +
           socket.inet_aton("192.0.2.10") + bytes(6) + socket.inet_aton("192.0.2.1"))
    ses.h3c.send_datagram(eth, qv(0) + arp)
    ses.flush()

    ses.client.close(error_code=0)
    ses.flush()
    write_pcapng(args.output, ses.packets, ses.keylog.getvalue())
    print(f"{len(ses.packets)} packets")


if __name__ == "__main__":
    main()
