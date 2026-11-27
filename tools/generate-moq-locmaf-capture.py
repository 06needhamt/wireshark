#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate LOCMAF (draft-einarsson-moq-locmaf-01) Objects in an MSF broadcast
over MOQT draft 23 between in-process aioquic peers.

The catalog lists one "locmaf" track. Its group carries a full header
Object preceded by a genBox (styp), then a delta header Object that changes
the sample count and deletes the sample flags, and finally a rawBoxes
Object holding a complete moof and mdat.

Requires: pip install aioquic
Usage: generate-moq-locmaf-capture.py OUTPUT.pcapng.gz
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from moq_capture import Connection, moqt_subscriber, vi, write_pcapng  # noqa: E402


def zigzag(n):
    return (n << 1) ^ (n >> 63)


def field(fid, value):
    """Even IDs are scalars; odd IDs carry a list of vi64 values."""
    if fid % 2 == 0:
        return vi(fid) + vi(value)
    body = b"".join(vi(v) for v in value)
    return vi(fid) + vi(len(body)) + body


def header(kind, fields, mdat):
    body = b"".join(fields)
    return vi(kind) + vi(len(body)) + body + mdat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    conn = Connection("moqt-23", ("192.0.2.1", 50000), 1790000000.0)
    subscribe, objects = moqt_subscriber(conn, b"cmaf")
    subscribe("catalog")
    subscribe("video")
    catalog = {"version": "draft-02", "tracks": [
        {"name": "video", "packaging": "locmaf", "locmafVersion": "0.3", "role": "video",
         "codec": "avc1.42000a", "timescale": 90000}]}
    objects("catalog", [json.dumps(catalog).encode()])

    styp = b"styp" + b"cmfs" + struct.pack(">I", 0)
    full = vi(1) + vi(len(styp)) + styp + header(2, [
        field(1, [100, 80]),            # trunSampleSizes (all but the last)
        field(4, 3000),                 # tfhdDefaultSampleDuration
        field(5, [zigzag(0), zigzag(-3000), zigzag(3000)]),  # CTOs
        field(7, [0x2000000, 0x1010000, 0x1010000]),          # trunSampleFlags
        field(10, 0),                   # tfdtBaseMediaDecodeTime
        field(14, 3),                   # trunSampleCount
    ], b"\x00" * 240)
    deleted = vi(27) + vi(1) + vi(7)    # deltaDeletedIDs: trunSampleFlags
    delta = header(3, [field(14, zigzag(-1)), deleted], b"\x11" * 150)
    moof = struct.pack(">I", 24) + b"moof" + struct.pack(">I", 16) + b"mfhd" + struct.pack(">II", 0, 1)
    mdat = struct.pack(">I", 12) + b"mdat" + b"\x01\x02\x03\x04"
    raw = vi(4) + moof + mdat
    objects("video", [full, delta, raw])
    conn.client.close(error_code=0)
    conn.flush()
    write_pcapng(args.output, conn.packets, conn.keylog.getvalue())
    print(f"{len(conn.packets)} packets")


if __name__ == "__main__":
    main()
