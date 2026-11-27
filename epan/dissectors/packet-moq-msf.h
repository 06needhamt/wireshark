/* packet-moq-msf.h
 * MOQT Streaming Format (MSF) track handoff
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MOQ_MSF_H__
#define __PACKET_MOQ_MSF_H__

#include <stdint.h>

#include "packet-moqt.h"

/*
 * Passed as the "data" argument to dissectors in the "moq_msf.packaging"
 * table, keyed by a catalog track's "packaging" ("loc", "cmaf", "locmaf",
 * "nvc", ...). The strings are the catalog's, NULL when absent; the payload
 * has already been decompressed when the track uses MSF compression.
 */
typedef struct _msf_track_info {
    const moqt_object_info_t *object;
    const char *packaging;
    const char *role;
    const char *codec;
    const char *event_type;
    const char *mime_type;
    uint32_t    catalog_frame;   /* frame of the catalog that described it */
} msf_track_info_t;

#endif /* __PACKET_MOQ_MSF_H__ */
