#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate LOC (draft-ietf-moq-loc-05) media between in-process aioquic peers.

Connection 1 speaks MOQT draft 23 over raw QUIC. The subscriber asks for
live/video and live/audio; each SUBSCRIBE_OK carries a CODEC_STRING Track
Property. Video Objects are H.264 (a keyframe with VIDEO_CONFIG, then a
delta frame) on a subgroup stream; audio Objects are Opus datagrams with
AUDIO_LEVEL and TIMESTAMP properties.

Connection 2 speaks moq-lite-05 with a hang broadcast whose video rendition
uses the "loc" container: each frame is a self-contained LOC frame (property
count, properties, payload). The last frame uses the draft-02 numbering.

The TLS secrets are embedded in a Decryption Secrets Block.

Requires: pip install aioquic
Usage: generate-moq-loc-capture.py OUTPUT.pcapng.gz
"""

import argparse
import datetime
import gzip
import io
import json
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


def moqt_session(conn):
    c, sv = conn.client, conn.server
    ctl = c.get_next_available_stream_id(is_unidirectional=True)
    conn.send(c, ctl, moqt_msg(0x2F00, vi(0x01) + moqt_lp(b"/moqt")))

    # live/video: alias 1, H.264.
    vsub = c.get_next_available_stream_id()
    conn.send(c, vsub, moqt_msg(0x03, vi(0) + vi(1) + moqt_lp(b"live") + moqt_lp(b"video") + vi(0)))
    conn.send(sv, vsub, moqt_msg(0x04, vi(1) + vi(0) + moqt_props([(0x11, b"avc1.42000a")])))
    # live/audio: alias 2, Opus.
    asub = c.get_next_available_stream_id()
    conn.send(c, asub, moqt_msg(0x03, vi(2) + vi(1) + moqt_lp(b"live") + moqt_lp(b"audio") + vi(0)))
    conn.send(sv, asub, moqt_msg(0x04, vi(2) + vi(0) + moqt_props([(0x11, b"opus")])))

    # Subgroup stream: type 0x31 (properties, zero Subgroup ID, default priority).
    key_props = moqt_props([(0x08, 90000), (0x09, bytes([0xE0])), (0x0D, AVCC), (0x10, 0)])
    delta_props = moqt_props([(0x08, 90000), (0x09, bytes([0xC1, 0x00, 0x01])), (0x10, 3000)])
    key = nal_units(IDR)
    delta = nal_units(SLICE)
    grp = sv.get_next_available_stream_id(is_unidirectional=True)
    data = vi(0x31) + vi(1) + vi(0)
    data += vi(0) + moqt_lp(key_props) + moqt_lp(key)
    data += vi(0) + moqt_lp(delta_props) + moqt_lp(delta)
    conn.send(sv, grp, data, end=True)

    # Audio datagrams: type 0x09 (properties, default priority).
    for obj, (level, ts) in enumerate(((0xA5, 1790000000000000), (0x7F, 1790000000020000))):
        props = moqt_props([(0x0C, level), (0x10, ts)])
        sv.send_datagram_frame(vi(0x09) + vi(2) + vi(0) + vi(obj) + moqt_lp(props) +
                               b"\xfc" + bytes([0x11 * (obj + 1)]) * 20)
    conn.flush()
    c.close(error_code=0)
    conn.flush()


def hang_session(conn):
    c, sv = conn.client, conn.server
    path = b"room/loc.hang"

    def lite_s(text):
        return qv(len(text)) + text

    for sub_id, track in enumerate((b"catalog.json", b"video")):
        sid = c.get_next_available_stream_id()
        body = qv(sub_id) + lite_s(path) + lite_s(track) + b"\x00" + b"\x00" + qv(0) + qv(0) + qv(0)
        conn.send(c, sid, qv(2) + qv(len(body)) + body)

    def group(sub_id, frames):
        sid = sv.get_next_available_stream_id(is_unidirectional=True)
        hdr = qv(sub_id) + qv(0)
        data = qv(0) + qv(len(hdr)) + hdr
        for ts_delta, payload in frames:
            data += qv(ts_delta * 2) + qv(len(payload)) + payload
        conn.send(sv, sid, data, end=True)

    catalog = {"video": {"renditions": {"video": {
        "codec": "avc1.42000a", "container": {"kind": "loc"}, "codedWidth": 160}}}}
    group(0, [(0, json.dumps(catalog).encode())])
    group(1, [
        (0, loc_frame([(0x10, 0), (0x08, 90000), (0x09, bytes([0xE0])), (0x0D, AVCC)],
                      nal_units(SPS, PPS, IDR))),
        (33, loc_frame([(0x10, 3000), (0x08, 90000)], b"\x00\x00\x00\x01" + SLICE)),
        # draft-02 numbering: Capture Timestamp (2) and an integer frame marking (4).
        (33, loc_frame([(0x02, 1790000000066666), (0x04, 0xC0)], nal_units(SLICE))),
    ])
    c.close(error_code=0)
    conn.flush()


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    moqt = Connection("moqt-23", ("192.0.2.1", 50000), 1790000000.0)
    moqt_session(moqt)
    hang = Connection("moq-lite-05", ("192.0.2.1", 50001), moqt.now + 1)
    hang_session(hang)
    write_pcapng(args.output, moqt.packets + hang.packets,
                 moqt.keylog.getvalue() + hang.keylog.getvalue())
    print(f"{len(moqt.packets) + len(hang.packets)} packets")


if __name__ == "__main__":
    main()
