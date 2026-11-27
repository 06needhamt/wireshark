/* packet-moqt.h
 * Media over QUIC Transport (MOQT) Object payload and property handoff
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MOQT_H__
#define __PACKET_MOQT_H__

#include <stdbool.h>
#include <stdint.h>

/*
 * One Object or Track Property. Even types carry an integer; odd types carry
 * a byte string. The bytes stay valid for as long as the structure that holds
 * the property (the packet for Object Properties, the capture for Track
 * Properties).
 */
typedef struct _moqt_property {
    uint64_t       type;
    uint64_t       integer;     /* Even types only. */
    const uint8_t *data;        /* Odd types only. */
    unsigned       length;      /* Odd types only. */
} moqt_property_t;

/* A byte string; valid for as long as the structure that holds it. */
typedef struct _moqt_bytes {
    const uint8_t *data;
    unsigned       length;
} moqt_bytes_t;

/*
 * Passed as the "data" argument to dissectors registered in the
 * "moqt.property" table, which is keyed by Property type. The tvb holds the
 * value: the integer's encoding for an even type, the bytes for an odd one.
 */
typedef struct _moqt_property_info {
    unsigned draft;             /* draft-ietf-moq-transport version. */
    uint64_t type;
    uint64_t integer;           /* Even types only. */
    bool     track_scope;       /* Track Property rather than Object Property. */
} moqt_property_info_t;

/*
 * Passed as the "data" argument to dissectors in the "moqt.track_name" table
 * (keyed by Track Name) and the "moqt.payload" heuristic list. The track is
 * resolved from the SUBSCRIBE, PUBLISH or FETCH that set up its Track Alias or
 * Request ID; track_namespace and track_name are NULL when that was not seen.
 * The namespace fields are joined with '/'.
 */
typedef struct _moqt_object_info {
    unsigned    draft;
    const char *track_namespace;
    const char *track_name;
    /* The same, as the bytes on the wire (for Secure Objects' Full Track Name). */
    const moqt_bytes_t *namespace_fields;
    unsigned    namespace_field_count;
    moqt_bytes_t track_name_bytes;

    uint64_t    track_alias;
    bool        track_alias_known;  /* false on FETCH streams */
    uint64_t    request_id;
    bool        request_id_known;   /* FETCH streams only */

    uint64_t    group_id;
    bool        group_id_known;
    uint64_t    subgroup_id;
    bool        subgroup_id_known;
    uint64_t    object_id;
    bool        object_id_known;
    uint8_t     publisher_priority;
    bool        publisher_priority_known;  /* false when the track default applies */
    bool        datagram;

    /* Properties of this Object, in wire order. */
    const moqt_property_t *properties;
    unsigned    property_count;
    /* Track Properties from SUBSCRIBE_OK or PUBLISH, if any. */
    const moqt_property_t *track_properties;
    unsigned    track_property_count;
} moqt_object_info_t;

/* Find a property of an Object, falling back to the Track Properties. */
static inline const moqt_property_t *
moqt_object_find_property(const moqt_object_info_t *info, uint64_t type)
{
    for (unsigned i = 0; i < info->property_count; i++) {
        if (info->properties[i].type == type) {
            return &info->properties[i];
        }
    }
    for (unsigned i = 0; i < info->track_property_count; i++) {
        if (info->track_properties[i].type == type) {
            return &info->track_properties[i];
        }
    }
    return NULL;
}

#endif /* __PACKET_MOQT_H__ */
