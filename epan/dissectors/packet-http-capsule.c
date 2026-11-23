/* packet-http-capsule.c
 * Routines for the HTTP Capsule Protocol dissection
 * RFC 9297, Section 3.2
 * https://www.rfc-editor.org/rfc/rfc9297
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A request stream that uses the Capsule Protocol carries a sequence of
 * capsules in its message content (HTTP/3 DATA frames):
 *
 *  Capsule {
 *    Capsule Type (i),
 *    Capsule Length (i),
 *    Capsule Value (..),
 *  }
 *
 * Capsule types are registered by the protocols that use them. This file
 * decodes the DATAGRAM capsule of RFC 9297 and the WebTransport over HTTP/3
 * capsules (draft-ietf-webtrans-http3-17, Section 9.6), and hands every other
 * type to the dissectors in the "capsule.type" table, such as MASQUE.
 *
 * Each HTTP/3 DATA frame is dissected on its own, so a capsule split across
 * DATA frames is reported as truncated.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-http-capsule.h"

void proto_register_http_capsule(void);

/* RFC 9297, Section 3.5. */
#define CAPSULE_DATAGRAM                    0x00

/* draft-ietf-webtrans-http3-17, Section 9.6. */
#define CAPSULE_WT_CLOSE_SESSION            0x2843
#define CAPSULE_WT_DRAIN_SESSION            0x78ae
#define CAPSULE_WT_MAX_DATA                 0x190b4d3d
#define CAPSULE_WT_MAX_STREAMS_BIDI         0x190b4d3f
#define CAPSULE_WT_MAX_STREAMS_UNI          0x190b4d40
#define CAPSULE_WT_DATA_BLOCKED             0x190b4d41
#define CAPSULE_WT_STREAMS_BLOCKED_BIDI     0x190b4d43
#define CAPSULE_WT_STREAMS_BLOCKED_UNI      0x190b4d44

/* Maximum WT_CLOSE_SESSION message length (draft-ietf-webtrans-http3-17, Section 6). */
#define WT_CLOSE_MESSAGE_MAX                1024
/* Largest WT_MAX_STREAMS or WT_STREAMS_BLOCKED value (Section 5.6.2). */
#define WT_MAX_STREAMS_LIMIT                (UINT64_C(1) << 60)

static int proto_http_capsule;

static int hf_capsule_type;
static int hf_capsule_length;
static int hf_capsule_value;
static int hf_capsule_datagram_payload;
static int hf_capsule_wt_error_code;
static int hf_capsule_wt_error_message;
static int hf_capsule_wt_max_data;
static int hf_capsule_wt_max_streams;
static int hf_capsule_wt_data_blocked;
static int hf_capsule_wt_streams_blocked;

static int ett_capsule;

static expert_field ei_capsule_truncated;
static expert_field ei_capsule_invalid;

static dissector_table_t capsule_type_table;

/*
 * Names for the capsule types known to Wireshark, including those decoded by
 * other dissectors through "capsule.type", so that every capsule is named.
 */
static const val64_string capsule_type_vals[] = {
    { CAPSULE_DATAGRAM,                "DATAGRAM" },
    /* RFC 9484 (CONNECT-IP). */
    { 0x01,                            "ADDRESS_ASSIGN" },
    { 0x02,                            "ADDRESS_REQUEST" },
    { 0x03,                            "ROUTE_ADVERTISEMENT" },
    /* draft-ietf-masque-connect-udp-listen. */
    { 0x11,                            "COMPRESSION_ASSIGN" },
    { 0x12,                            "COMPRESSION_ACK" },
    { 0x13,                            "COMPRESSION_CLOSE" },
    /* draft-ietf-masque-quic-proxy. */
    { 0xffe600,                        "REGISTER_CLIENT_CID" },
    { 0xffe601,                        "REGISTER_TARGET_CID" },
    { 0xffe602,                        "ACK_CLIENT_CID" },
    { 0xffe603,                        "ACK_TARGET_CID" },
    { 0xffe604,                        "CLOSE_CLIENT_CID" },
    { 0xffe605,                        "CLOSE_TARGET_CID" },
    /* draft-ietf-webtrans-http3. */
    { CAPSULE_WT_CLOSE_SESSION,        "WT_CLOSE_SESSION" },
    { CAPSULE_WT_DRAIN_SESSION,        "WT_DRAIN_SESSION" },
    { CAPSULE_WT_MAX_DATA,             "WT_MAX_DATA" },
    { CAPSULE_WT_MAX_STREAMS_BIDI,     "WT_MAX_STREAMS (bidirectional)" },
    { CAPSULE_WT_MAX_STREAMS_UNI,      "WT_MAX_STREAMS (unidirectional)" },
    { CAPSULE_WT_DATA_BLOCKED,         "WT_DATA_BLOCKED" },
    { CAPSULE_WT_STREAMS_BLOCKED_BIDI, "WT_STREAMS_BLOCKED (bidirectional)" },
    { CAPSULE_WT_STREAMS_BLOCKED_UNI,  "WT_STREAMS_BLOCKED (unidirectional)" },
    { 0, NULL }
};

static const char *
capsule_type_name(wmem_allocator_t *scope, uint64_t type)
{
    /* RFC 9297, Section 5.4: 0x29 * N + 0x17 is reserved for greasing. */
    if (type >= 0x17 && (type - 0x17) % 0x29 == 0) {
        return "Reserved (GREASE)";
    }
    return val64_to_str_wmem(scope, type, capsule_type_vals, "Unknown (0x%" PRIx64 ")");
}

/* Returns true if the value is fully decoded; false leaves it shown as data. */
static bool
dissect_builtin_capsule(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *capsule_item, uint64_t type,
                        http_capsule_info_t *info)
{
    int length = (int)tvb_reported_length(tvb);
    uint64_t value;
    unsigned lenvar;
    proto_item *ti;

    switch (type) {
    case CAPSULE_DATAGRAM:
        if (info && info->datagram_handle) {
            call_dissector_with_data(info->datagram_handle, tvb, pinfo,
                                     proto_tree_get_root(tree), info->datagram_data);
        } else {
            proto_tree_add_item(tree, hf_capsule_datagram_payload, tvb, 0, length, ENC_NA);
        }
        return true;

    case CAPSULE_WT_CLOSE_SESSION: {
        uint32_t code;

        if (length < 4) {
            proto_tree_add_expert_format(tree, pinfo, &ei_capsule_invalid, tvb, 0, length,
                                         "WT_CLOSE_SESSION is shorter than its error code");
            return false;
        }
        proto_tree_add_item_ret_uint(tree, hf_capsule_wt_error_code, tvb, 0, 4,
                                     ENC_BIG_ENDIAN, &code);
        proto_item_append_text(capsule_item, ": Error Code %u", code);
        if (length > 4) {
            ti = proto_tree_add_item(tree, hf_capsule_wt_error_message, tvb, 4, length - 4,
                                     ENC_UTF_8);
            if (length - 4 > WT_CLOSE_MESSAGE_MAX) {
                expert_add_info_format(pinfo, ti, &ei_capsule_invalid,
                                       "The error message exceeds %u bytes",
                                       WT_CLOSE_MESSAGE_MAX);
            }
        }
        return true;
    }

    case CAPSULE_WT_DRAIN_SESSION:
        if (length != 0) {
            proto_tree_add_expert_format(tree, pinfo, &ei_capsule_invalid, tvb, 0, length,
                                         "WT_DRAIN_SESSION has no value");
            return false;
        }
        return true;

    case CAPSULE_WT_MAX_DATA:
    case CAPSULE_WT_MAX_STREAMS_BIDI:
    case CAPSULE_WT_MAX_STREAMS_UNI:
    case CAPSULE_WT_DATA_BLOCKED:
    case CAPSULE_WT_STREAMS_BLOCKED_BIDI:
    case CAPSULE_WT_STREAMS_BLOCKED_UNI: {
        int hf = type == CAPSULE_WT_MAX_DATA ? hf_capsule_wt_max_data :
                 type == CAPSULE_WT_DATA_BLOCKED ? hf_capsule_wt_data_blocked :
                 type == CAPSULE_WT_MAX_STREAMS_BIDI || type == CAPSULE_WT_MAX_STREAMS_UNI
                     ? hf_capsule_wt_max_streams : hf_capsule_wt_streams_blocked;

        ti = proto_tree_add_item_ret_varint(tree, hf, tvb, 0, -1, ENC_VARINT_QUIC, &value,
                                            &lenvar);
        if (lenvar == 0 || (int)lenvar != length) {
            expert_add_info_format(pinfo, ti, &ei_capsule_invalid,
                                   "The value must be exactly one variable-length integer");
            return false;
        }
        proto_item_append_text(capsule_item, ": %" PRIu64, value);
        if (hf != hf_capsule_wt_max_data && hf != hf_capsule_wt_data_blocked &&
            value > WT_MAX_STREAMS_LIMIT) {
            expert_add_info_format(pinfo, ti, &ei_capsule_invalid,
                                   "The stream count exceeds 2^60");
        }
        return true;
    }

    default:
        return false;
    }
}

static int
dissect_http_capsules(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    http_capsule_info_t *info = (http_capsule_info_t *)data;
    int offset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_item *capsule_item, *type_item;
        proto_tree *capsule_tree;
        uint64_t type, length;
        unsigned type_len, length_len;
        int start = offset;
        const char *name;

        capsule_item = proto_tree_add_item(tree, proto_http_capsule, tvb, offset, -1, ENC_NA);
        capsule_tree = proto_item_add_subtree(capsule_item, ett_capsule);

        type_item = proto_tree_add_item_ret_varint(capsule_tree, hf_capsule_type, tvb, offset,
                                                   -1, ENC_VARINT_QUIC, &type, &type_len);
        if (type_len == 0) {
            proto_tree_add_expert(capsule_tree, pinfo, &ei_capsule_truncated, tvb, offset, -1);
            break;
        }
        offset += type_len;
        name = capsule_type_name(pinfo->pool, type);
        proto_item_append_text(type_item, " (%s)", name);
        proto_item_set_text(capsule_item, "Capsule: %s", name);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", name);

        proto_tree_add_item_ret_varint(capsule_tree, hf_capsule_length, tvb, offset, -1,
                                       ENC_VARINT_QUIC, &length, &length_len);
        if (length_len == 0) {
            proto_tree_add_expert(capsule_tree, pinfo, &ei_capsule_truncated, tvb, offset, -1);
            break;
        }
        offset += length_len;
        if (length > (uint64_t)tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_expert_format(capsule_tree, pinfo, &ei_capsule_truncated, tvb, offset,
                                         -1, "The %" PRIu64 "-byte capsule value continues "
                                         "beyond this DATA frame", length);
            break;
        }

        tvbuff_t *value_tvb = tvb_new_subset_length(tvb, offset, (int)length);

        if (length > 0) {
            proto_tree_add_item(capsule_tree, hf_capsule_value, tvb, offset, (int)length, ENC_NA);
        }
        if (!dissect_builtin_capsule(value_tvb, pinfo, capsule_tree, capsule_item, type, info) &&
            (type > UINT32_MAX ||
             !dissector_try_uint_with_data(capsule_type_table, (uint32_t)type, value_tvb, pinfo,
                                           capsule_tree, true, info))) {
            /* The value is shown as data above. */
        }
        offset += (int)length;
        proto_item_set_len(capsule_item, offset - start);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_http_capsule(void)
{
    static hf_register_info hf[] = {
        { &hf_capsule_type,
          { "Capsule Type", "capsule.type",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_length,
          { "Capsule Length", "capsule.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_value,
          { "Capsule Value", "capsule.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_datagram_payload,
          { "HTTP Datagram Payload", "capsule.datagram.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_wt_error_code,
          { "Application Error Code", "capsule.wt.error_code",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "WT_CLOSE_SESSION error code", HFILL }
        },
        { &hf_capsule_wt_error_message,
          { "Application Error Message", "capsule.wt.error_message",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "WT_CLOSE_SESSION error message", HFILL }
        },
        { &hf_capsule_wt_max_data,
          { "Maximum Data", "capsule.wt.max_data",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_wt_max_streams,
          { "Maximum Streams", "capsule.wt.max_streams",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_capsule_wt_data_blocked,
          { "Data Limit", "capsule.wt.data_blocked",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "WT_DATA_BLOCKED: the session data limit that blocked the sender", HFILL }
        },
        { &hf_capsule_wt_streams_blocked,
          { "Stream Limit", "capsule.wt.streams_blocked",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "WT_STREAMS_BLOCKED: the stream limit that blocked the sender", HFILL }
        },
    };

    static int *ett[] = {
        &ett_capsule,
    };

    static ei_register_info ei[] = {
        { &ei_capsule_truncated,
          { "capsule.truncated", PI_MALFORMED, PI_WARN,
            "Truncated capsule", EXPFILL }
        },
        { &ei_capsule_invalid,
          { "capsule.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid capsule value", EXPFILL }
        },
    };

    expert_module_t *expert_capsule;

    proto_http_capsule = proto_register_protocol("HTTP Capsule Protocol", "Capsule",
                                                 "capsule");
    proto_register_field_array(proto_http_capsule, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_capsule = expert_register_protocol(proto_http_capsule);
    expert_register_field_array(expert_capsule, ei, array_length(ei));

    register_dissector("capsule", dissect_http_capsules, proto_http_capsule);
    capsule_type_table = register_dissector_table("capsule.type", "HTTP Capsule Type",
                                                  proto_http_capsule, FT_UINT32, BASE_HEX);
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
