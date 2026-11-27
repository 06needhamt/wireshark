#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate MoQ Media Interop (draft-cenzano-moq-media-interop) Objects over
MOQT draft 23 between in-process aioquic peers.

Tracks video0 (draft-03 H.264 metadata 0x15 and an AVCDecoderConfiguration
Record), video1 (draft-02 metadata 0x0B), audio0 (Opus) and text0 (UTF-8)
carry their metadata in Object Properties. audio1 uses draft-01, with the
metadata at the start of the payload.

Requires: pip install aioquic
Usage: generate-moq-mi-capture.py OUTPUT.pcapng.gz
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from moq_capture import (AVCC, IDR, SLICE, Connection, moqt_props, moqt_subscriber,  # noqa: E402
                         qv, write_pcapng)


def meta(*values):
    return b"".join(qv(v) for v in values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    conn = Connection("moqt-23", ("192.0.2.1", 50000), 1790000000.0)
    subscribe, objects = moqt_subscriber(conn, b"mi")
    for name in ("video0", "video1", "audio0", "text0", "audio1"):
        subscribe(name)
    nal = struct.pack("!I", len(IDR)) + IDR
    objects("video0", [nal], moqt_props([
        (0x0A, 0), (0x0D, AVCC), (0x15, meta(0, 90000, 90000, 90000, 3000, 1790000000000))]))
    objects("video1", [struct.pack("!I", len(SLICE)) + SLICE], moqt_props([
        (0x0A, 0), (0x0B, meta(1, 3000, 3000, 90000, 3000, 0))]))
    objects("audio0", [b"\xfc" + b"\x55" * 20], moqt_props([
        (0x0A, 1), (0x0F, meta(7, 960, 48000, 48000, 2, 960, 1790000000020))]))
    objects("text0", ["hello, mi".encode()], moqt_props([(0x0A, 2), (0x11, meta(3))]))
    objects("audio1", [qv(1) + meta(8, 1920, 48000, 48000, 2, 960, 0) + b"\xfc" + b"\x66" * 20])
    conn.client.close(error_code=0)
    conn.flush()
    write_pcapng(args.output, conn.packets, conn.keylog.getvalue())
    print(f"{len(conn.packets)} packets")


if __name__ == "__main__":
    main()
