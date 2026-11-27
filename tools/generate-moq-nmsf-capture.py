#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate NMSF (draft-herz-moq-nmsf-01) Objects in an MSF broadcast over
MOQT draft 23 between in-process aioquic peers.

The catalog lists a single-track "nvc" track ("video", dcvc-rt) and the two
tracks of a two-track pair ("video-z" hyperprior and "video-y" latent).
The single track carries an Intra and an Inter Object, each with a
hyperprior and a latent tensor; the pair carries one component each.

Requires: pip install aioquic
Usage: generate-moq-nmsf-capture.py OUTPUT.pcapng.gz
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from moq_capture import Connection, moqt_subscriber, write_pcapng  # noqa: E402


def tensor(channels, height, width, data):
    return struct.pack(">IIII", channels, height, width, len(data)) + data


def nmsf(frame_type, qp, frame, pts, width, height, payload):
    return struct.pack(">BBIQIII", frame_type, qp, frame, pts, width, height,
                       len(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    conn = Connection("moqt-23", ("192.0.2.1", 50000), 1790000000.0)
    subscribe, objects = moqt_subscriber(conn, b"nvc")
    for name in ("catalog", "video", "video-z", "video-y"):
        subscribe(name)
    nvc = {"codec": "dcvc-rt", "colorspace": "yuv420", "gopSize": 32}
    catalog = {"version": "draft-02", "tracks": [
        {"name": "video", "packaging": "nvc", "role": "video", "codec": "dcvc-rt",
         "width": 256, "height": 128, "nvc": nvc},
        {"name": "video-z", "packaging": "nvc", "role": "video", "codec": "dcvc-rt",
         "nvcRole": "hyperprior", "nvc": nvc},
        {"name": "video-y", "packaging": "nvc", "role": "video", "codec": "dcvc-rt",
         "nvcRole": "latent", "depends": ["video-z"], "nvc": nvc},
    ]}
    objects("catalog", [json.dumps(catalog).encode()])
    z, y = tensor(128, 2, 4, b"\x5a" * 12), tensor(128, 8, 16, b"\x79" * 40)
    objects("video", [nmsf(0, 21, 0, 1790000000000, 256, 128, z + y),
                      nmsf(1, 21, 1, 1790000000033, 256, 128, z + y)])
    objects("video-z", [nmsf(0, 30, 0, 1790000000000, 256, 128, z)])
    objects("video-y", [nmsf(0, 30, 0, 1790000000000, 256, 128, y)])
    conn.client.close(error_code=0)
    conn.flush()
    write_pcapng(args.output, conn.packets, conn.keylog.getvalue())
    print(f"{len(conn.packets)} packets")


if __name__ == "__main__":
    main()
