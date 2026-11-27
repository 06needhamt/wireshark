/* packet-moq-locmaf.c
 * Routines for LOCMAF (Low Overhead CMAF for Media over QUIC) dissection
 * draft-einarsson-moq-locmaf-01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A LOCMAF Object carries one CMAF chunk as a sequence of elements, every
 * integer a MOQT vi64:
 *
 *   Object  = genBox* (fullHeader | deltaHeader) mdat-payload
 *           | rawBoxes ISO-BMFF-boxes
 *   genBox  = 1, Box Size, FourCC, contents      (a box before the moof)
 *   header  = 2 or 3, Length, field*             (the moof, as fields)
 *   field   = ID (even) value | ID (odd) Length bytes
 *
 * Even field IDs are scalars; odd ones are per-sample lists of vi64 values
 * (or, for senc IVs, raw bytes). In a delta header (3) scalars and list
 * entries are zigzag-coded differences from the group's reference header,
 * and field 27 lists fields deleted from it. Reconstructing the moof needs
 * the track's CMAF Header and the group's earlier Objects, so the fields
 * are shown as sent and the mdat payload as bytes.
 *
 * The track is identified by an MSF catalog with "packaging": "locmaf".
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

void proto_register_moq_locmaf(void);
void proto_reg_handoff_moq_locmaf(void);

#define LOCMAF_ELEM_GENBOX        1
#define LOCMAF_ELEM_FULL_HEADER   2
#define LOCMAF_ELEM_DELTA_HEADER  3
#define LOCMAF_ELEM_RAW_BOXES     4

#define LOCMAF_F_SENC_IV            9
#define LOCMAF_F_TFDT_BMDT         10
#define LOCMAF_F_TRUN_SAMPLE_CTOS   5
#define LOCMAF_F_DELTA_DELETED_IDS 27

static int proto_moq_locmaf;

static int hf_locmaf_element_type;
static int hf_locmaf_genbox_size;
static int hf_locmaf_genbox_type;
static int hf_locmaf_genbox_payload;
static int hf_locmaf_header_length;
static int hf_locmaf_field_id;
static int hf_locmaf_field_value;
static int hf_locmaf_field_delta;
static int hf_locmaf_field_length;
static int hf_locmaf_field_entry;
static int hf_locmaf_field_bytes;
static int hf_locmaf_field_deleted;
static int hf_locmaf_mdat;

static int ett_locmaf;
static int ett_locmaf_element;
static int ett_locmaf_field;

static expert_field ei_locmaf_malformed;
static expert_field ei_locmaf_unknown_element;
static expert_field ei_locmaf_duplicate_field;
static expert_field ei_locmaf_field_misplaced;

static dissector_handle_t mp4_handle;

static const val64_string locmaf_element_vals[] = {
    { LOCMAF_ELEM_GENBOX,       "genBox" },
    { LOCMAF_ELEM_FULL_HEADER,  "Full Header" },
    { LOCMAF_ELEM_DELTA_HEADER, "Delta Header" },
    { LOCMAF_ELEM_RAW_BOXES,    "rawBoxes" },
    { 0, NULL }
};

static const val64_string locmaf_field_vals[] = {
    {  1, "trunSampleSizes" },
    {  2, "tfhdSampleDescriptionIndex" },
    {  3, "trunSampleDurations" },
    {  4, "tfhdDefaultSampleDuration" },
    {  5, "trunSampleCompositionTimeOffsets" },
    {  6, "tfhdDefaultSampleSize" },
    {  7, "trunSampleFlags" },
    {  8, "tfhdDefaultSampleFlags" },
    {  9, "sencIV" },
    { 10, "tfdtBaseMediaDecodeTime" },
    { 11, "sencSubsampleCount" },
    { 12, "trunFirstSampleFlags" },
    { 13, "sencClearBytes" },
    { 14, "trunSampleCount" },
    { 15, "sencProtectedBytes" },
    { 16, "sencIVSize" },
    { 27, "deltaDeletedIDs" },
    { 0, NULL }
};

/* MOQT vi64: the leading 1 bits of the first byte give the extra bytes. */
static int
locmaf_vi64(tvbuff_t *tvb, int offset, int end, uint64_t *value)
{
    uint8_t first;
    int length = 1;

    if (offset >= end) {
        return 0;
    }
    first = tvb_get_uint8(tvb, offset);
    while (length < 9 && (first & (0x100 >> length)) != 0) {
        length++;
    }
    if (offset + length > end) {
        return 0;
    }
    if (length == 9) {
        *value = tvb_get_ntoh64(tvb, offset + 1);
    } else {
        *value = first & (0xff >> length);
        for (int i = 1; i < length; i++) {
            *value = (*value << 8) | tvb_get_uint8(tvb, offset + i);
        }
    }
    return length;
}

static int64_t
locmaf_zigzag(uint64_t z)
{
    return (int64_t)(z >> 1) ^ -(int64_t)(z & 1);
}

static proto_item *
locmaf_add_vi64(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int end,
                uint64_t *value, int *length, packet_info *pinfo)
{
    proto_item *item;

    *length = locmaf_vi64(tvb, offset, end, value);
    if (*length == 0) {
        proto_tree_add_expert(tree, pinfo, &ei_locmaf_malformed, tvb, offset,
                              end - offset);
        return NULL;
    }
    item = proto_tree_add_uint64(tree, hf, tvb, offset, *length, *value);
    return item;
}

/* A list field: vi64 entries, signed for compositions offsets and deltas. */
static void
locmaf_dissect_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    int offset, int end, uint64_t id, bool delta)
{
    unsigned count = 0;

    while (offset < end) {
        uint64_t value;
        int length = locmaf_vi64(tvb, offset, end, &value);
        proto_item *item;

        if (length == 0) {
            proto_tree_add_expert(tree, pinfo, &ei_locmaf_malformed, tvb, offset,
                                  end - offset);
            return;
        }
        if (id == LOCMAF_F_DELTA_DELETED_IDS) {
            item = proto_tree_add_uint64(tree, hf_locmaf_field_deleted, tvb, offset,
                                         length, value);
            proto_item_append_text(item, " (%s)",
                                   val64_to_str_const(value, locmaf_field_vals, "Unknown"));
        } else if (delta || id == LOCMAF_F_TRUN_SAMPLE_CTOS) {
            item = proto_tree_add_int64(tree, hf_locmaf_field_delta, tvb, offset, length,
                                        locmaf_zigzag(value));
        } else {
            item = proto_tree_add_uint64(tree, hf_locmaf_field_entry, tvb, offset, length,
                                         value);
        }
        proto_item_prepend_text(item, "[%u] ", count++);
        offset += length;
    }
}

/* The fields of a full (2) or delta (3) header. */
static void
locmaf_dissect_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      int offset, int end, bool delta)
{
    wmem_map_t *seen = wmem_map_new(pinfo->pool, g_int64_hash, g_int64_equal);

    while (offset < end) {
        proto_item *field_item, *id_item;
        proto_tree *field_tree;
        uint64_t id, value, *key;
        int start = offset, length;
        const char *name;

        field_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_locmaf_field,
                                            &field_item, "Field");
        id_item = locmaf_add_vi64(field_tree, hf_locmaf_field_id, tvb, offset, end,
                                  &id, &length, pinfo);
        if (!id_item) {
            return;
        }
        offset += length;
        name = val64_to_str_const(id, locmaf_field_vals, "Unknown");
        proto_item_append_text(id_item, " (%s)", name);
        proto_item_set_text(field_item, "Field: %s (%" PRIu64 ")", name, id);

        key = wmem_new(pinfo->pool, uint64_t);
        *key = id;
        if (wmem_map_contains(seen, key)) {
            expert_add_info(pinfo, id_item, &ei_locmaf_duplicate_field);
        }
        wmem_map_insert(seen, key, key);
        if ((id == LOCMAF_F_TFDT_BMDT && delta) ||
            (id == LOCMAF_F_DELTA_DELETED_IDS && !delta)) {
            expert_add_info_format(pinfo, id_item, &ei_locmaf_field_misplaced,
                                   "%s is not allowed in a %s header", name,
                                   delta ? "delta" : "full");
        }

        if ((id & 1) == 0) {
            proto_item *item = locmaf_add_vi64(field_tree, hf_locmaf_field_value, tvb,
                                               offset, end, &value, &length, pinfo);

            if (!item) {
                return;
            }
            if (delta) {
                proto_item_set_generated(proto_tree_add_int64(
                    field_tree, hf_locmaf_field_delta, tvb, offset, length,
                    locmaf_zigzag(value)));
                proto_item_append_text(field_item, ": %+" PRId64, locmaf_zigzag(value));
            } else {
                proto_item_append_text(field_item, ": %" PRIu64, value);
            }
            offset += length;
        } else {
            if (!locmaf_add_vi64(field_tree, hf_locmaf_field_length, tvb, offset, end,
                                 &value, &length, pinfo)) {
                return;
            }
            offset += length;
            if (value > (uint64_t)(end - offset)) {
                proto_tree_add_expert(field_tree, pinfo, &ei_locmaf_malformed, tvb,
                                      offset, end - offset);
                return;
            }
            if (id == LOCMAF_F_SENC_IV) {
                proto_tree_add_item(field_tree, hf_locmaf_field_bytes, tvb, offset,
                                    (int)value, ENC_NA);
            } else {
                locmaf_dissect_list(tvb, pinfo, field_tree, offset, offset + (int)value,
                                    id, delta);
            }
            offset += (int)value;
        }
        proto_item_set_len(field_item, offset - start);
    }
}

static int
dissect_locmaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int end = tvb_reported_length(tvb);
    proto_item *locmaf_item, *element_item, *item;
    proto_tree *locmaf_tree, *element_tree;
    uint64_t type, value;
    int offset = 0, length, start;
    unsigned genboxes = 0;

    locmaf_item = proto_tree_add_item(tree, proto_moq_locmaf, tvb, 0, -1, ENC_NA);
    locmaf_tree = proto_item_add_subtree(locmaf_item, ett_locmaf);

    for (;;) {
        start = offset;
        element_tree = proto_tree_add_subtree(locmaf_tree, tvb, offset, -1,
                                              ett_locmaf_element, &element_item, "Element");
        item = locmaf_add_vi64(element_tree, hf_locmaf_element_type, tvb, offset, end,
                               &type, &length, pinfo);
        if (!item) {
            return end;
        }
        offset += length;
        proto_item_set_text(element_item, "%s",
                            val64_to_str_const(type, locmaf_element_vals, "Unknown element"));

        switch (type) {
        case LOCMAF_ELEM_RAW_BOXES:
            if (genboxes != 0) {
                expert_add_info_format(pinfo, item, &ei_locmaf_unknown_element,
                                       "rawBoxes must be the only element");
            }
            proto_item_set_len(element_item, end - start);
            proto_item_append_text(locmaf_item, ", rawBoxes");
            if (offset < end) {
                col_set_fence(pinfo->cinfo, COL_INFO);
                call_dissector(mp4_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
                               element_tree);
            }
            return end;

        case LOCMAF_ELEM_GENBOX:
            if (!locmaf_add_vi64(element_tree, hf_locmaf_genbox_size, tvb, offset, end,
                                 &value, &length, pinfo)) {
                return end;
            }
            offset += length;
            if (value < 4 || value > (uint64_t)(end - offset)) {
                proto_tree_add_expert(element_tree, pinfo, &ei_locmaf_malformed, tvb,
                                      offset, end - offset);
                return end;
            }
            proto_tree_add_item(element_tree, hf_locmaf_genbox_type, tvb, offset, 4,
                                ENC_ASCII);
            proto_item_append_text(element_item, ": %s",
                                   tvb_format_text(pinfo->pool, tvb, offset, 4));
            if (value > 4) {
                proto_tree_add_item(element_tree, hf_locmaf_genbox_payload, tvb,
                                    offset + 4, (int)value - 4, ENC_NA);
            }
            offset += (int)value;
            proto_item_set_len(element_item, offset - start);
            genboxes++;
            continue;

        case LOCMAF_ELEM_FULL_HEADER:
        case LOCMAF_ELEM_DELTA_HEADER: {
            bool delta = type == LOCMAF_ELEM_DELTA_HEADER;

            if (!locmaf_add_vi64(element_tree, hf_locmaf_header_length, tvb, offset, end,
                                 &value, &length, pinfo)) {
                return end;
            }
            offset += length;
            if (value > (uint64_t)(end - offset)) {
                proto_tree_add_expert(element_tree, pinfo, &ei_locmaf_malformed, tvb,
                                      offset, end - offset);
                return end;
            }
            locmaf_dissect_fields(tvb, pinfo, element_tree, offset, offset + (int)value,
                                  delta);
            offset += (int)value;
            proto_item_set_len(element_item, offset - start);
            proto_item_append_text(locmaf_item, ", %s", delta ? "Delta" : "Full");
            if (offset < end) {
                proto_tree_add_item(locmaf_tree, hf_locmaf_mdat, tvb, offset, -1, ENC_NA);
            }
            return end;
        }

        default:
            expert_add_info(pinfo, item, &ei_locmaf_unknown_element);
            proto_item_set_len(element_item, end - start);
            return end;
        }
    }
}

void
proto_register_moq_locmaf(void)
{
    static hf_register_info hf[] = {
        { &hf_locmaf_element_type,
          { "Element Type", "moq_locmaf.element_type",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(locmaf_element_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_locmaf_genbox_size,
          { "Box Size", "moq_locmaf.genbox.size",
            FT_UINT64, BASE_DEC, NULL, 0x0, "FourCC and contents", HFILL }
        },
        { &hf_locmaf_genbox_type,
          { "Box Type", "moq_locmaf.genbox.type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_genbox_payload,
          { "Box Contents", "moq_locmaf.genbox.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_header_length,
          { "Header Length", "moq_locmaf.header.length",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_id,
          { "Field ID", "moq_locmaf.field.id",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_value,
          { "Value", "moq_locmaf.field.value",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_delta,
          { "Signed Value", "moq_locmaf.field.signed",
            FT_INT64, BASE_DEC, NULL, 0x0,
            "Zigzag-decoded difference or composition time offset", HFILL }
        },
        { &hf_locmaf_field_length,
          { "Length", "moq_locmaf.field.length",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_entry,
          { "Entry", "moq_locmaf.field.entry",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_bytes,
          { "Bytes", "moq_locmaf.field.bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_field_deleted,
          { "Deleted Field", "moq_locmaf.field.deleted",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_locmaf_mdat,
          { "mdat Payload", "moq_locmaf.mdat",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_locmaf,
        &ett_locmaf_element,
        &ett_locmaf_field,
    };

    static ei_register_info ei[] = {
        { &ei_locmaf_malformed,
          { "moq_locmaf.malformed", PI_MALFORMED, PI_ERROR,
            "Truncated or overlong LOCMAF element", EXPFILL }
        },
        { &ei_locmaf_unknown_element,
          { "moq_locmaf.element.unexpected", PI_PROTOCOL, PI_ERROR,
            "Unknown or misplaced element", EXPFILL }
        },
        { &ei_locmaf_duplicate_field,
          { "moq_locmaf.field.duplicate", PI_PROTOCOL, PI_ERROR,
            "A field ID appears twice", EXPFILL }
        },
        { &ei_locmaf_field_misplaced,
          { "moq_locmaf.field.misplaced", PI_PROTOCOL, PI_ERROR,
            "Field not allowed in this header", EXPFILL }
        },
    };

    expert_module_t *expert_locmaf;

    proto_moq_locmaf = proto_register_protocol("Low Overhead CMAF", "LOCMAF",
                                               "moq_locmaf");
    proto_register_field_array(proto_moq_locmaf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_locmaf = expert_register_protocol(proto_moq_locmaf);
    expert_register_field_array(expert_locmaf, ei, array_length(ei));
    register_dissector("moq_locmaf", dissect_locmaf, proto_moq_locmaf);
}

void
proto_reg_handoff_moq_locmaf(void)
{
    mp4_handle = find_dissector_add_dependency("mp4", proto_moq_locmaf);
    dissector_add_string("moq_msf.packaging", "locmaf",
                         find_dissector("moq_locmaf"));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
