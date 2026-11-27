/* packet-sframe.c
 * Routines for SFrame (Secure Frame) dissection
 * RFC 9605
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * An SFrame ciphertext is a header, the encrypted frame and the AEAD tag.
 * RFC 9605 section 4.3 header:
 *
 *    0 1 2 3 4 5 6 7
 *   +-+-+-+-+-+-+-+-+---------------------------------+
 *   |X|  K  |Y|  C  |   Key ID (opt)  |  Counter (opt)  |
 *   +-+-+-+-+-+-+-+-+---------------------------------+
 *
 * X=0: K is the Key ID (0-7); X=1: K+1 bytes of Key ID follow.
 * Y=0: C is the Counter (0-7); Y=1: C+1 bytes of Counter follow.
 *
 * Earlier drafts, which libloc still writes, used a different layout:
 * R (reserved), LEN (Counter bytes - 1), K (extended Key ID), KID (Key ID or
 * its length - 1), then the Counter and then any extended Key ID. The
 * "header_format" preference selects it.
 *
 * The tag length depends on the cipher suite (RFC 9605 section 8.1), which
 * is not on the wire; the "cipher_suite" preference supplies it. Frames are
 * not decrypted.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_sframe(void);
void proto_reg_handoff_sframe(void);

enum {
    SFRAME_FORMAT_RFC9605,
    SFRAME_FORMAT_LEGACY,
};

static int proto_sframe;

static int hf_sframe_config;
static int hf_sframe_x;
static int hf_sframe_k;
static int hf_sframe_y;
static int hf_sframe_c;
static int hf_sframe_legacy_r;
static int hf_sframe_legacy_len;
static int hf_sframe_legacy_k;
static int hf_sframe_legacy_kid;
static int hf_sframe_kid;
static int hf_sframe_ctr;
static int hf_sframe_ciphertext;
static int hf_sframe_tag;
static int hf_sframe_cipher_suite;

static int ett_sframe;
static int ett_sframe_config;

static expert_field ei_sframe_truncated;
static expert_field ei_sframe_reserved;

static int pref_header_format = SFRAME_FORMAT_RFC9605;
static int pref_cipher_suite = 0x0004;

static const enum_val_t sframe_format_vals[] = {
    { "rfc9605", "RFC 9605", SFRAME_FORMAT_RFC9605 },
    { "legacy", "Pre-RFC drafts (as libloc writes it)", SFRAME_FORMAT_LEGACY },
    { NULL, NULL, 0 }
};

/* RFC 9605 section 8.1, with Nt. */
static const value_string sframe_cipher_suite_vals[] = {
    { 0x0001, "AES_128_CTR_HMAC_SHA256_80" },
    { 0x0002, "AES_128_CTR_HMAC_SHA256_64" },
    { 0x0003, "AES_128_CTR_HMAC_SHA256_32" },
    { 0x0004, "AES_128_GCM_SHA256_128" },
    { 0x0005, "AES_256_GCM_SHA512_128" },
    { 0, NULL }
};

static int * const sframe_config_fields[] = {
    &hf_sframe_x, &hf_sframe_k, &hf_sframe_y, &hf_sframe_c, NULL
};

static int * const sframe_legacy_config_fields[] = {
    &hf_sframe_legacy_r, &hf_sframe_legacy_len, &hf_sframe_legacy_k,
    &hf_sframe_legacy_kid, NULL
};

static unsigned
sframe_tag_length(unsigned suite)
{
    switch (suite) {
    case 0x0001: return 10;
    case 0x0002: return 8;
    case 0x0003: return 4;
    default:     return 16;
    }
}

static int
dissect_sframe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int length = tvb_reported_length(tvb);
    proto_item *sframe_item, *item;
    proto_tree *sframe_tree;
    uint8_t config;
    uint64_t kid = 0, ctr = 0;
    int offset = 1, kid_len = 0, ctr_len = 0, kid_offset, ctr_offset;
    unsigned tag_len = sframe_tag_length((unsigned)pref_cipher_suite);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SFrame");
    sframe_item = proto_tree_add_item(tree, proto_sframe, tvb, 0, -1, ENC_NA);
    sframe_tree = proto_item_add_subtree(sframe_item, ett_sframe);
    if (length < 1) {
        proto_tree_add_expert(sframe_tree, pinfo, &ei_sframe_truncated, tvb, 0, 0);
        return 0;
    }
    config = tvb_get_uint8(tvb, 0);

    if (pref_header_format == SFRAME_FORMAT_RFC9605) {
        proto_tree_add_bitmask(sframe_tree, tvb, 0, hf_sframe_config, ett_sframe_config,
                               sframe_config_fields, ENC_NA);
        kid = (config >> 4) & 0x07;
        ctr = config & 0x07;
        if (config & 0x80) {
            kid_len = (int)kid + 1;
        }
        if (config & 0x08) {
            ctr_len = (int)ctr + 1;
        }
        kid_offset = offset;
        ctr_offset = offset + kid_len;
    } else {
        item = proto_tree_add_bitmask(sframe_tree, tvb, 0, hf_sframe_config,
                                      ett_sframe_config, sframe_legacy_config_fields,
                                      ENC_NA);
        if (config & 0x80) {
            expert_add_info(pinfo, item, &ei_sframe_reserved);
        }
        ctr_len = ((config >> 4) & 0x07) + 1;
        kid = config & 0x07;
        if (config & 0x08) {
            kid_len = (int)kid + 1;
        }
        ctr_offset = offset;
        kid_offset = offset + ctr_len;
    }
    if (length < 1 + kid_len + ctr_len) {
        proto_tree_add_expert(sframe_tree, pinfo, &ei_sframe_truncated, tvb, 0, length);
        return length;
    }
    if (kid_len > 0) {
        kid = tvb_get_uint64_with_length(tvb, kid_offset, kid_len, ENC_BIG_ENDIAN);
        proto_tree_add_uint64(sframe_tree, hf_sframe_kid, tvb, kid_offset, kid_len, kid);
    } else {
        item = proto_tree_add_uint64(sframe_tree, hf_sframe_kid, tvb, 0, 1, kid);
        proto_item_set_generated(item);
    }
    if (ctr_len > 0) {
        ctr = tvb_get_uint64_with_length(tvb, ctr_offset, ctr_len, ENC_BIG_ENDIAN);
        proto_tree_add_uint64(sframe_tree, hf_sframe_ctr, tvb, ctr_offset, ctr_len, ctr);
    } else {
        item = proto_tree_add_uint64(sframe_tree, hf_sframe_ctr, tvb, 0, 1, ctr);
        proto_item_set_generated(item);
    }
    offset = 1 + kid_len + ctr_len;
    proto_item_set_len(sframe_item, length);
    proto_item_append_text(sframe_item, ", KID %" PRIu64 ", CTR %" PRIu64, kid, ctr);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "[SFrame KID %" PRIu64 " CTR %" PRIu64 "]",
                        kid, ctr);

    item = proto_tree_add_uint(sframe_tree, hf_sframe_cipher_suite, tvb, 0, 0,
                               (uint32_t)pref_cipher_suite);
    proto_item_set_generated(item);
    if ((unsigned)(length - offset) < tag_len) {
        proto_tree_add_expert(sframe_tree, pinfo, &ei_sframe_truncated, tvb, offset,
                              length - offset);
        return length;
    }
    if (length - offset > (int)tag_len) {
        proto_tree_add_item(sframe_tree, hf_sframe_ciphertext, tvb, offset,
                            length - offset - (int)tag_len, ENC_NA);
    }
    proto_tree_add_item(sframe_tree, hf_sframe_tag, tvb, length - (int)tag_len,
                        (int)tag_len, ENC_NA);
    return length;
}

void
proto_register_sframe(void)
{
    static hf_register_info hf[] = {
        { &hf_sframe_config,
          { "Config", "sframe.config",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sframe_x,
          { "Extended Key ID", "sframe.config.x",
            FT_BOOLEAN, 8, NULL, 0x80, "X: the Key ID follows the config byte", HFILL }
        },
        { &hf_sframe_k,
          { "K", "sframe.config.k",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            "Key ID, or the length of the Key ID minus one", HFILL }
        },
        { &hf_sframe_y,
          { "Extended Counter", "sframe.config.y",
            FT_BOOLEAN, 8, NULL, 0x08, "Y: the Counter follows", HFILL }
        },
        { &hf_sframe_c,
          { "C", "sframe.config.c",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Counter, or the length of the Counter minus one", HFILL }
        },
        { &hf_sframe_legacy_r,
          { "Reserved", "sframe.config.r",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_sframe_legacy_len,
          { "LEN", "sframe.config.len",
            FT_UINT8, BASE_DEC, NULL, 0x70, "Counter length minus one", HFILL }
        },
        { &hf_sframe_legacy_k,
          { "Extended Key ID", "sframe.config.legacy_k",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_sframe_legacy_kid,
          { "KID", "sframe.config.kid",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Key ID, or the length of the Key ID minus one", HFILL }
        },
        { &hf_sframe_kid,
          { "Key ID", "sframe.kid",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sframe_ctr,
          { "Counter", "sframe.ctr",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sframe_ciphertext,
          { "Ciphertext", "sframe.ciphertext",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sframe_tag,
          { "Authentication Tag", "sframe.tag",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sframe_cipher_suite,
          { "Cipher Suite", "sframe.cipher_suite",
            FT_UINT16, BASE_HEX, VALS(sframe_cipher_suite_vals), 0x0,
            "From the cipher_suite preference", HFILL }
        },
    };

    static int *ett[] = {
        &ett_sframe,
        &ett_sframe_config,
    };

    static ei_register_info ei[] = {
        { &ei_sframe_truncated,
          { "sframe.truncated", PI_MALFORMED, PI_ERROR,
            "SFrame is shorter than its header and tag", EXPFILL }
        },
        { &ei_sframe_reserved,
          { "sframe.reserved", PI_PROTOCOL, PI_WARN,
            "Reserved bit set", EXPFILL }
        },
    };

    static const enum_val_t suite_vals[] = {
        { "0x0001", "AES_128_CTR_HMAC_SHA256_80", 0x0001 },
        { "0x0002", "AES_128_CTR_HMAC_SHA256_64", 0x0002 },
        { "0x0003", "AES_128_CTR_HMAC_SHA256_32", 0x0003 },
        { "0x0004", "AES_128_GCM_SHA256_128", 0x0004 },
        { "0x0005", "AES_256_GCM_SHA512_128", 0x0005 },
        { NULL, NULL, 0 }
    };

    expert_module_t *expert_sframe;
    module_t *sframe_module;

    proto_sframe = proto_register_protocol("Secure Frame", "SFrame", "sframe");
    proto_register_field_array(proto_sframe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sframe = expert_register_protocol(proto_sframe);
    expert_register_field_array(expert_sframe, ei, array_length(ei));
    register_dissector("sframe", dissect_sframe, proto_sframe);

    sframe_module = prefs_register_protocol(proto_sframe, NULL);
    prefs_register_enum_preference(sframe_module, "header_format", "Header format",
                                   "RFC 9605, or the layout of earlier drafts that "
                                   "libloc writes (Counter length in the config byte, "
                                   "Counter before the Key ID)",
                                   &pref_header_format, sframe_format_vals, false);
    prefs_register_enum_preference(sframe_module, "cipher_suite", "Cipher suite",
                                   "Cipher suite in use, which sets the tag length",
                                   &pref_cipher_suite, suite_vals, false);
}

void
proto_reg_handoff_sframe(void)
{
    dissector_handle_t handle = find_dissector("sframe");

    /* SFrame has no codepoint of its own: it is chosen by Decode As. */
    dissector_add_for_decode_as("rtp.pt", handle);
    dissector_add_for_decode_as("udp.port", handle);
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
