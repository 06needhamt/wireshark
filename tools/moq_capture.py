# moq_capture.py
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Shared helpers for the generate-moq-*-capture.py scripts: QUIC and MOQT
integer encodings, an in-process aioquic client/server pair, and a pcapng
writer that embeds the TLS secrets in a Decryption Secrets Block.
"""

import datetime
import gzip
import io
import struct

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SERVER = ("192.0.2.2", 4443)

# A minimal H.264 baseline SPS and PPS, an IDR slice and a non-IDR slice.
SPS = bytes.fromhex("6742000af841a2")
PPS = bytes.fromhex("68ce3880")
IDR = bytes.fromhex("65888040") + b"\x00" * 12
SLICE = bytes.fromhex("419a0204") + b"\x00" * 8
AVCC = bytes([1, 0x42, 0x00, 0x0A, 0xFF, 0xE1]) + struct.pack("!H", len(SPS)) + SPS + \
    bytes([1]) + struct.pack("!H", len(PPS)) + PPS


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
    return vi(mtype) + vi(len(body)) + body


def moqt_lp(data):
    return vi(len(data)) + data


def moqt_props(props):
    """Delta-typed MOQT properties, ascending: (type, int or bytes)."""
    out, previous = b"", 0
    for ptype, value in sorted(props, key=lambda p: p[0]):
        out += vi(ptype - previous)
        previous = ptype
        out += vi(value) if ptype % 2 == 0 else moqt_lp(value)
    return out


def loc_frame(props, payload):
    """libloc loc_encode(): count, absolute IDs, QUIC varints, payload."""
    out = qv(len(props))
    for pid, value in props:
        out += qv(pid)
        out += qv(value) if pid % 2 == 0 else qv(len(value)) + value
    return out + payload


def nal_units(*nals):
    return b"".join(struct.pack("!I", len(n)) + n for n in nals)


class Connection:
    def __init__(self, alpn, client_addr, start):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "moq.example")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .sign(key, hashes.SHA256()))
        self.keylog = io.StringIO()
        ccfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn], max_datagram_frame_size=65536,
                                 server_name="moq.example", secrets_log_file=self.keylog)
        ccfg.verify_mode = 0
        scfg = QuicConfiguration(is_client=False, alpn_protocols=[alpn], max_datagram_frame_size=65536)
        scfg.certificate, scfg.private_key = cert, key
        self.addr = client_addr
        self.now = start
        self.client = QuicConnection(configuration=ccfg)
        self.server = QuicConnection(configuration=scfg,
                                     original_destination_connection_id=self.client.original_destination_connection_id)
        self.packets = []
        self.client.connect(SERVER, now=self.now)
        self.flush()

    def flush(self):
        while True:
            moved = False
            for src, dst, src_addr, dst_addr in ((self.client, self.server, self.addr, SERVER),
                                                 (self.server, self.client, SERVER, self.addr)):
                for data, _ in src.datagrams_to_send(now=self.now):
                    self.now += 0.001
                    self.packets.append((self.now, src_addr, dst_addr, data))
                    dst.receive_datagram(data, src_addr, now=self.now)
                    moved = True
            for quic in (self.client, self.server):
                while quic.next_event() is not None:
                    pass
            if not moved:
                break

    def send(self, quic, stream_id, data, end=False):
        quic.send_stream_data(stream_id, data, end)
        self.flush()


def moqt_subscriber(conn, namespace):
    """Return subscribe(name) and objects(name, payloads, props) for one session."""
    c, sv = conn.client, conn.server
    ctl = c.get_next_available_stream_id(is_unidirectional=True)
    conn.send(c, ctl, moqt_msg(0x2F00, vi(0x01) + moqt_lp(b"/moq")))
    aliases = {}

    def subscribe(name):
        alias = len(aliases) + 1
        sid = c.get_next_available_stream_id()
        conn.send(c, sid, moqt_msg(0x03, vi(2 * (alias - 1)) + vi(1) + moqt_lp(namespace) +
                                   moqt_lp(name.encode()) + vi(0)))
        conn.send(sv, sid, moqt_msg(0x04, vi(alias) + vi(0)))
        aliases[name] = alias

    def objects(name, payloads, props=b""):
        """One subgroup stream: type 0x31 (properties, zero subgroup, default priority)."""
        sid = sv.get_next_available_stream_id(is_unidirectional=True)
        data = vi(0x31) + vi(aliases[name]) + vi(0)
        for payload in payloads:
            data += vi(0) + moqt_lp(props) + moqt_lp(payload)
        conn.send(sv, sid, data, end=True)

    return subscribe, objects


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
        mac = {True: b"\x02\0\0\0\0\x02", False: b"\x02\0\0\0\0\x01"}
        return mac[dst == SERVER] + mac[src == SERVER] + b"\x08\x00" + ip + udp

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
