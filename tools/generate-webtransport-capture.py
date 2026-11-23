#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate WebTransport over HTTP/3 sessions between an in-process aioquic
client and server. The first session negotiates MOQT draft 23 with
WT-Protocol; the second offers only moq-lite-06 in WT-Available-Protocols.
Both carry unidirectional and bidirectional WebTransport streams opened by
either side and HTTP Datagrams; the MOQT session also splits a message
across two QUIC packets and ends with WT_MAX_DATA, WT_DRAIN_SESSION and
WT_CLOSE_SESSION capsules. The TLS secrets are embedded in a Decryption
Secrets Block so that the capture decrypts without a keylog file.

Requires: pip install aioquic
Usage: generate-webtransport-capture.py OUTPUT.pcapng.gz
"""

import argparse
import datetime
import gzip
import io
import struct

from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted
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
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wt.example")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("wt.example")]), False)
                .sign(key, hashes.SHA256()))
        self.keylog = io.StringIO()
        ccfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=65536,
                                 server_name="wt.example", secrets_log_file=self.keylog)
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
        self.h3c = H3Connection(self.client, enable_webtransport=True)
        self.h3s = H3Connection(self.server, enable_webtransport=True)
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


def connect(ses, path, offered, selected):
    """Open a WebTransport session; returns its Session ID (the CONNECT stream)."""
    sid = ses.client.get_next_available_stream_id()
    ses.h3c.send_headers(sid, [
        (b":method", b"CONNECT"), (b":protocol", b"webtransport-h3"), (b":scheme", b"https"),
        (b":authority", b"wt.example"), (b":path", path.encode()),
        (b"wt-available-protocols", offered.encode())])
    ses.flush()
    response = [(b":status", b"200")]
    if selected:
        response.append((b"wt-protocol", selected.encode()))
    ses.h3s.send_headers(sid, response)
    ses.flush()
    return sid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    ses = Session()
    c, sv = ses.client, ses.server

    # Session 1: MOQT draft 23, selected by WT-Protocol.
    moqt = connect(ses, "/moqt", '"moqt-23", "moqt-22"', '"moqt-23"')
    ctl = ses.h3c.create_webtransport_stream(moqt, is_unidirectional=True)
    ses.send(c, ctl, moqt_msg(0x2F00, vi(0x01) + moqt_lp(b"/moqt")))
    sub = ses.h3c.create_webtransport_stream(moqt)
    subscribe = moqt_msg(0x03, vi(0) + vi(1) + moqt_lp(b"live") + moqt_lp(b"video") + vi(0))
    # Split the SUBSCRIBE across two QUIC packets to exercise reassembly.
    ses.send(c, sub, subscribe[:4])
    ses.send(c, sub, subscribe[4:])
    ses.send(sv, sub, moqt_msg(0x04, vi(1) + vi(0)))
    grp = ses.h3s.create_webtransport_stream(moqt, is_unidirectional=True)
    ses.send(sv, grp, vi(0x34) + vi(1) + vi(5) + vi(0) + vi(0) + moqt_lp(b"object-0"), end=True)
    ses.h3s.send_datagram(moqt, vi(0x08) + vi(1) + vi(5) + vi(1) + b"datagram-object")
    ses.flush()
    srv_bidi = ses.h3s.create_webtransport_stream(moqt)
    ses.send(sv, srv_bidi, moqt_msg(0x0D, vi(2) + vi(1) + moqt_lp(b"live") + moqt_lp(b"audio") + vi(0)))

    # Session 2: moq-lite-06, the only protocol offered.
    lite = connect(ses, "/moq-lite", '"moq-lite-06"', None)
    setup = ses.h3c.create_webtransport_stream(lite, is_unidirectional=True)
    ses.send(c, setup, qv(0x1) + lite_msg(qv(1) + qv(0x2) + qv(5) + b"/lite"))
    lsub = ses.h3c.create_webtransport_stream(lite)
    ses.send(c, lsub, qv(0x2) + lite_msg(qv(0) + lite_s("room") + lite_s("audio") + bytes([1]) +
                                         qv(0) + qv(0) + qv(0) + qv(0) + qv(0)))
    ses.send(sv, lsub, qv(0x0) + lite_msg(qv(4)))
    lgrp = ses.h3s.create_webtransport_stream(lite, is_unidirectional=True)
    ses.send(sv, lgrp, qv(0x0) + lite_msg(qv(0) + qv(4) + qv(0)) + qv(0) + qv(5) + b"frame", end=True)
    ses.h3s.send_datagram(lite, qv(0) + qv(5) + qv(960) + b"opus")
    ses.flush()

    # Session 1 capsules: flow control, then drain and close.
    ses.h3s.send_data(moqt, capsule(0x190B4D3D, qv(65536)) + capsule(0x78AE, b""), False)
    ses.flush()
    ses.h3c.send_data(moqt, capsule(0x2843, struct.pack("!I", 7) + b"bye"), True)
    ses.flush()

    c.close(error_code=0)
    ses.flush()
    write_pcapng(args.output, ses.packets, ses.keylog.getvalue())
    print(f"{len(ses.packets)} packets")


if __name__ == "__main__":
    main()
