/* packet-moq-loc.h
 * Low Overhead Media Container (LOC) handoff
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MOQ_LOC_H__
#define __PACKET_MOQ_LOC_H__

/*
 * Optional "data" argument of the "moq_loc.frame" dissector, which decodes a
 * self-contained LOC frame: a counted property list followed by the codec
 * payload. A container that knows the track's codec (for example from a
 * catalog) passes it here; a Codec String property in the frame wins.
 */
typedef struct _moq_loc_frame_info {
    const char *codec;      /* WebCodecs codec string, or NULL. */
} moq_loc_frame_info_t;

#endif /* __PACKET_MOQ_LOC_H__ */
