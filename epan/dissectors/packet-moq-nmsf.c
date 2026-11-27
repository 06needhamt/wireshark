/* packet-moq-nmsf.c
 * Routines for NMSF (Neural Video Codec packaging for MSF) dissection
 * draft-herz-moq-nmsf-01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * An NMSF Object (an MSF track with "packaging": "nvc") is a 26-byte
 * big-endian header followed by the codec's entropy-coded latent tensors:
 *
 *   frame_type (8), qp (8), frame_number (32), pts_ms (64),
 *   width (32), height (32), payload_len (32), payload
 *
 * The payload is one or more tensor components, each channels, height and
 * width (32 bits each), data_len (32) and data. A track in two-track mode
 * carries one component (hyperprior or latent); in single-track mode the
 * hyperprior precedes the latent. The tensor contents are codec specific.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-moq-msf.h"

void proto_register_moq_nmsf(void);
void proto_reg_handoff_moq_nmsf(void);

#define NMSF_HEADER_LEN        26
#define NMSF_TENSOR_HEADER_LEN 16
#define NMSF_QP_MAX            63

static int proto_moq_nmsf;

static int hf_nmsf_frame_type;
static int hf_nmsf_qp;
static int hf_nmsf_frame_number;
static int hf_nmsf_pts;
static int hf_nmsf_pts_time;
static int hf_nmsf_width;
static int hf_nmsf_height;
static int hf_nmsf_payload_len;
static int hf_nmsf_codec;
static int hf_nmsf_tensor_channels;
static int hf_nmsf_tensor_height;
static int hf_nmsf_tensor_width;
static int hf_nmsf_tensor_data_len;
static int hf_nmsf_tensor_data;
static int hf_nmsf_payload;

static int ett_nmsf;
static int ett_nmsf_tensor;

static expert_field ei_nmsf_truncated;
static expert_field ei_nmsf_length;
static expert_field ei_nmsf_reserved;

static const value_string nmsf_frame_type_vals[] = {
    { 0x00, "Intra" },
    { 0x01, "Inter" },
    { 0, NULL }
};

static const char *const nmsf_component_names[] = { "Hyperprior", "Latent" };

/*
 * Tensor components, when the payload is made of them exactly; otherwise
 * the payload is shown as bytes.
 */
static void
nmsf_dissect_tensors(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     int offset, int end)
{
    int scan = offset;
    unsigned count = 0;

    while (scan < end) {
        uint32_t data_len;

        if (end - scan < NMSF_TENSOR_HEADER_LEN) {
            break;
        }
        data_len = tvb_get_ntohl(tvb, scan + 12);
        if (data_len > (uint32_t)(end - scan - NMSF_TENSOR_HEADER_LEN)) {
            break;
        }
        scan += NMSF_TENSOR_HEADER_LEN + (int)data_len;
        count++;
    }
    if (scan != end || count == 0) {
        proto_tree_add_item(tree, hf_nmsf_payload, tvb, offset, end - offset, ENC_NA);
        return;
    }
    for (unsigned i = 0; i < count; i++) {
        proto_item *item;
        proto_tree *tensor_tree;
        uint32_t channels, height, width, data_len;
        const char *name = count == 2 ? nmsf_component_names[i] : "Tensor";

        data_len = tvb_get_ntohl(tvb, offset + 12);
        tensor_tree = proto_tree_add_subtree(tree, tvb, offset,
                                             NMSF_TENSOR_HEADER_LEN + (int)data_len,
                                             ett_nmsf_tensor, &item, name);
        proto_tree_add_item_ret_uint(tensor_tree, hf_nmsf_tensor_channels, tvb, offset,
                                     4, ENC_BIG_ENDIAN, &channels);
        proto_tree_add_item_ret_uint(tensor_tree, hf_nmsf_tensor_height, tvb, offset + 4,
                                     4, ENC_BIG_ENDIAN, &height);
        proto_tree_add_item_ret_uint(tensor_tree, hf_nmsf_tensor_width, tvb, offset + 8,
                                     4, ENC_BIG_ENDIAN, &width);
        proto_tree_add_item(tensor_tree, hf_nmsf_tensor_data_len, tvb, offset + 12, 4,
                            ENC_BIG_ENDIAN);
        if (data_len > 0) {
            proto_tree_add_item(tensor_tree, hf_nmsf_tensor_data, tvb, offset + 16,
                                (int)data_len, ENC_NA);
        }
        proto_item_append_text(item, ": %ux%ux%u, %u bytes", channels, height, width,
                               data_len);
        offset += NMSF_TENSOR_HEADER_LEN + (int)data_len;
    }
}

static int
dissect_nmsf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const msf_track_info_t *info = (const msf_track_info_t *)data;
    int length = tvb_reported_length(tvb);
    proto_item *nmsf_item, *item;
    proto_tree *nmsf_tree;
    uint32_t frame_type, qp, frame_number, width, height, payload_len;
    uint64_t pts;

    nmsf_item = proto_tree_add_item(tree, proto_moq_nmsf, tvb, 0, -1, ENC_NA);
    nmsf_tree = proto_item_add_subtree(nmsf_item, ett_nmsf);
    if (info && info->codec) {
        item = proto_tree_add_string(nmsf_tree, hf_nmsf_codec, tvb, 0, 0, info->codec);
        proto_item_set_generated(item);
    }
    if (length < NMSF_HEADER_LEN) {
        proto_tree_add_expert(nmsf_tree, pinfo, &ei_nmsf_truncated, tvb, 0, length);
        return length;
    }

    item = proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_frame_type, tvb, 0, 1,
                                        ENC_NA, &frame_type);
    if (frame_type > 0x01) {
        expert_add_info(pinfo, item, &ei_nmsf_reserved);
    }
    item = proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_qp, tvb, 1, 1, ENC_NA, &qp);
    if (qp > NMSF_QP_MAX) {
        expert_add_info(pinfo, item, &ei_nmsf_reserved);
    }
    proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_frame_number, tvb, 2, 4,
                                 ENC_BIG_ENDIAN, &frame_number);
    proto_tree_add_item_ret_uint64(nmsf_tree, hf_nmsf_pts, tvb, 6, 8, ENC_BIG_ENDIAN, &pts);
    if (pts != 0) {
        nstime_t t = { (time_t)(pts / 1000), (int)((pts % 1000) * 1000000) };

        item = proto_tree_add_time(nmsf_tree, hf_nmsf_pts_time, tvb, 6, 8, &t);
        proto_item_set_generated(item);
    }
    proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_width, tvb, 14, 4, ENC_BIG_ENDIAN,
                                 &width);
    proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_height, tvb, 18, 4, ENC_BIG_ENDIAN,
                                 &height);
    item = proto_tree_add_item_ret_uint(nmsf_tree, hf_nmsf_payload_len, tvb, 22, 4,
                                        ENC_BIG_ENDIAN, &payload_len);
    proto_item_append_text(nmsf_item, ", %s frame %u, %ux%u, qp %u",
                           val_to_str_const(frame_type, nmsf_frame_type_vals, "Reserved"),
                           frame_number, width, height, qp);

    /* The payload fills the rest of the Object exactly. */
    if (payload_len != (uint32_t)(length - NMSF_HEADER_LEN)) {
        expert_add_info_format(pinfo, item, &ei_nmsf_length,
                               "payload_len %u, but %d bytes follow the header",
                               payload_len, length - NMSF_HEADER_LEN);
        if (length > NMSF_HEADER_LEN) {
            proto_tree_add_item(nmsf_tree, hf_nmsf_payload, tvb, NMSF_HEADER_LEN, -1,
                                ENC_NA);
        }
        return length;
    }
    if (payload_len > 0) {
        nmsf_dissect_tensors(tvb, pinfo, nmsf_tree, NMSF_HEADER_LEN, length);
    }
    return length;
}

void
proto_register_moq_nmsf(void)
{
    static hf_register_info hf[] = {
        { &hf_nmsf_frame_type,
          { "Frame Type", "moq_nmsf.frame_type",
            FT_UINT8, BASE_HEX, VALS(nmsf_frame_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_nmsf_qp,
          { "QP", "moq_nmsf.qp",
            FT_UINT8, BASE_DEC, NULL, 0x0, "Quality parameter index", HFILL }
        },
        { &hf_nmsf_frame_number,
          { "Frame Number", "moq_nmsf.frame_number",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_pts,
          { "PTS", "moq_nmsf.pts",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Capture wallclock in milliseconds since 1970; 0 if unknown", HFILL }
        },
        { &hf_nmsf_pts_time,
          { "Capture Time", "moq_nmsf.pts_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_width,
          { "Width", "moq_nmsf.width",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_height,
          { "Height", "moq_nmsf.height",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_payload_len,
          { "Payload Length", "moq_nmsf.payload_len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_codec,
          { "Codec", "moq_nmsf.codec",
            FT_STRING, BASE_NONE, NULL, 0x0, "Neural codec from the catalog", HFILL }
        },
        { &hf_nmsf_tensor_channels,
          { "Channels", "moq_nmsf.tensor.channels",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_tensor_height,
          { "Height", "moq_nmsf.tensor.height",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_tensor_width,
          { "Width", "moq_nmsf.tensor.width",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_tensor_data_len,
          { "Data Length", "moq_nmsf.tensor.data_len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_nmsf_tensor_data,
          { "Data", "moq_nmsf.tensor.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Entropy-coded tensor", HFILL }
        },
        { &hf_nmsf_payload,
          { "Payload", "moq_nmsf.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_nmsf,
        &ett_nmsf_tensor,
    };

    static ei_register_info ei[] = {
        { &ei_nmsf_truncated,
          { "moq_nmsf.truncated", PI_MALFORMED, PI_ERROR,
            "Object is shorter than the 26-byte header", EXPFILL }
        },
        { &ei_nmsf_length,
          { "moq_nmsf.payload_len.mismatch", PI_MALFORMED, PI_ERROR,
            "payload_len does not match the Object", EXPFILL }
        },
        { &ei_nmsf_reserved,
          { "moq_nmsf.reserved", PI_PROTOCOL, PI_WARN,
            "Reserved value", EXPFILL }
        },
    };

    expert_module_t *expert_nmsf;

    proto_moq_nmsf = proto_register_protocol("Neural Video Codec MSF Packaging",
                                             "NMSF", "moq_nmsf");
    proto_register_field_array(proto_moq_nmsf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_nmsf = expert_register_protocol(proto_moq_nmsf);
    expert_register_field_array(expert_nmsf, ei, array_length(ei));
    register_dissector("moq_nmsf", dissect_nmsf, proto_moq_nmsf);
}

void
proto_reg_handoff_moq_nmsf(void)
{
    dissector_add_string("moq_msf.packaging", "nvc", find_dissector("moq_nmsf"));
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
