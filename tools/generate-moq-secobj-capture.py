#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate MOQ Secure Objects (draft-ietf-moq-secure-objects-01) over MOQT
draft 23 between in-process aioquic peers.

The encryption below is checked against the draft's Appendix B.4 vectors
before anything is written. Tracks of namespace example.com/meeting-123:
 - "video": Key ID 7, AES_128_GCM_SHA256_128 (suite 4), Group 42 Object 1,
   Publisher Priority 128, with an Encrypted Properties List and Padding;
 - "audio": Key ID 9, AES_128_CTR_HMAC_SHA256_80 (suite 1), an encrypted
   Opus frame on a track whose CODEC_STRING Track Property makes it LOC;
 - "slides": Key ID 11, AES_256_GCM_SHA512_128 (suite 5);
 - "chat": Key ID 99, for which the test supplies no key.
The track base keys are "sixteen byte key" for Key ID 7, "audio track key!"
for Key ID 9 and "a 32-byte base key for slides!!!" for Key ID 11.

Requires: pip install aioquic
Usage: generate-moq-secobj-capture.py OUTPUT.pcapng.gz
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from moq_capture import Connection, moqt_lp, moqt_msg, moqt_props, vi, write_pcapng  # noqa: E402

# suite: (hash length, key length, tag length, CTR+HMAC)
SUITES = {1: (32, 48, 10, True), 2: (32, 48, 8, True), 3: (32, 48, 4, True),
          4: (32, 16, 16, False), 5: (64, 32, 16, False)}


def hkdf_expand(md, prk, info, length):
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), md).digest()
        out += block
        counter += 1
    return out[:length]


def derive(suite, key_id, base_key, full_track_name):
    nh, nk, _, _ = SUITES[suite]
    md = "sha512" if nh == 64 else "sha256"
    prk = hmac.new(b"", base_key, md).digest()
    tail = full_track_name + struct.pack(">HQ", suite, key_id)
    return (hkdf_expand(md, prk, b"MOQ 1.0 Secure Objects Secret key " + tail, nk),
            hkdf_expand(md, prk, b"MOQ 1.0 Secret salt " + tail, 12))


def encrypt(suite, key_id, base_key, full_track_name, group, obj, priority, immutable, plaintext):
    """immutable: [(type, bytes)] serialized for the AAD after the Key ID."""
    _, _, nt, ctr = SUITES[suite]
    key, salt = derive(suite, key_id, base_key, full_track_name)
    nonce = bytes(a ^ b for a, b in zip(struct.pack(">QI", group, obj), salt))
    aad = struct.pack(">QIB", group, obj, priority) + struct.pack(">H", 2) + vi(len(vi(key_id))) + vi(key_id)
    for ptype, value in immutable:
        aad += struct.pack(">H", ptype) + vi(len(value)) + value
    if not ctr:
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    enc = Cipher(algorithms.AES(key[:16]), modes.CTR(nonce + b"\0" * 4)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct + hmac.new(key[16:48], aad + nonce + ct, "sha256").digest()[:nt]


def full_track_name(namespace, name):
    return vi(len(namespace)) + b"".join(vi(len(f)) + f for f in namespace) + vi(len(name)) + name


def check_vectors():
    """draft-ietf-moq-secure-objects-01 Appendix B.4."""
    ftn = full_track_name([b"example.com", b"meeting-123"], b"video")
    plaintext = bytes.fromhex("0e68656c6c6f2066726f6d206d6f71000a1001000d666f722d657965732d6f6e6c79")
    vectors = {
        1: ("7369787465656e2062797465206b6579",
            "170654428664c29b3eab20a76e86ab2c2fc210b218b38eb556974021b7804b1d7ced925e33e3d6080e8157d4"),
        4: ("7369787465656e2062797465206b6579",
            "facafee5c450bd140759bdffa6eef6948ae6dbfdb7ba87cf3e161a641b27f952eb4f13b18e351d4e7e344675f0dc96e0cd5e"),
        5: ("615d3235362d6269742d626173652d6b65792d666f722d746573742121212121",
            "09399b821a1452a320a8bf927c004c71f8fd34449070f99746ff6ab0ef67a4f93b7f889e64d194a7b18a7a946184fed15386"),
    }
    for suite, (base_key, expected) in vectors.items():
        ct = encrypt(suite, 7, bytes.fromhex(base_key), ftn, 42, 1, 128,
                     [(4, b"relay-ok")], plaintext)
        assert ct.hex() == expected, f"Appendix B.4 suite {suite}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    check_vectors()

    namespace = [b"example.com", b"meeting-123"]
    conn = Connection("moqt-23", ("192.0.2.1", 50000), 1790000000.0)
    c, sv = conn.client, conn.server
    ctl = c.get_next_available_stream_id(is_unidirectional=True)
    conn.send(c, ctl, moqt_msg(0x2F00, vi(0x01) + moqt_lp(b"/moq")))
    track_ns = vi(len(namespace)) + b"".join(moqt_lp(f) for f in namespace)
    for alias, name, track_props in ((1, b"video", b""), (2, b"audio", moqt_props([(0x11, b"opus")])),
                                     (3, b"chat", b""), (4, b"slides", b"")):
        sid = c.get_next_available_stream_id()
        conn.send(c, sid, moqt_msg(0x03, vi(2 * alias) + track_ns + moqt_lp(name) + vi(0)))
        conn.send(sv, sid, moqt_msg(0x04, vi(alias) + vi(0) + track_props))

    def secure_object(alias, name, key_id, suite, base_key, group, obj, priority, plaintext):
        ct = encrypt(suite, key_id, base_key, full_track_name(namespace, name), group, obj,
                     priority, [], plaintext)
        immutable = vi(0x02) + vi(key_id)
        # Subgroup type 0x11: properties, zero Subgroup ID, explicit priority.
        sid = sv.get_next_available_stream_id(is_unidirectional=True)
        data = vi(0x11) + vi(alias) + vi(group) + bytes([priority])
        data += vi(obj) + moqt_lp(moqt_props([(0x0B, immutable)])) + moqt_lp(ct)
        conn.send(sv, sid, data, end=True)

    epl = struct.pack(">H", 0x0A) + vi(3) + b"\x01\x02\x03"
    padding = struct.pack(">HH", 0x32, 4) + b"\x00" * 4
    payload = b"hello from moq"
    secure_object(1, b"video", 7, 4, b"sixteen byte key", 42, 1, 128,
                  vi(len(payload)) + payload + epl + padding)
    opus = b"\xfc" + b"\x77" * 20
    secure_object(2, b"audio", 9, 1, b"audio track key!", 3, 0, 64, vi(len(opus)) + opus)
    secure_object(3, b"chat", 99, 4, b"unknown key here", 0, 0, 0, vi(2) + b"hi")
    secure_object(4, b"slides", 11, 5, b"a 32-byte base key for slides!!!", 5, 2, 200,
                  vi(6) + b"slide2")
    c.close(error_code=0)
    conn.flush()
    write_pcapng(args.output, conn.packets, conn.keylog.getvalue())
    print(f"{len(conn.packets)} packets")


if __name__ == "__main__":
    main()
