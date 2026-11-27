/* packet-moq-loc.c
 * Routines for Low Overhead Media Container (LOC) dissection
 * draft-ietf-moq-loc-05, compatible with -04, -03 and -02
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A LOC Object is a codec bitstream (the internal data of a WebCodecs
 * EncodedAudioChunk or EncodedVideoChunk) plus LOC Properties. In MOQT the
 * properties are Object or Track Properties, which this dissector decodes
 * through the "moqt.property" table. The payload is then routed by the Codec
 * String property (draft-05, 0x11; libloc's Codec ID 0x21 before it) to the
 * dissector registered for the codec in the "moq_loc.codec" table.
 *
 * Property identifiers (draft-03 onwards, the MOQ Properties Registry):
 *   0x08 TIMESCALE, 0x09 VIDEO_FRAME_MARKING (RFC 9626 bytes),
 *   0x0c AUDIO_LEVEL (RFC 6464), 0x0d VIDEO_CONFIG, 0x0f AUDIO_CONFIG,
 *   0x10 TIMESTAMP, 0x11 CODEC_STRING (draft-05).
 * Draft-02 used 2, 4 and 6 for the timestamp, frame marking (an integer)
 * and audio level, and 8 and 15 for the text encoding and MIME type; those
 * conflict with MOQT's own properties, so they are only read in LOC frames.
 *
 * Outside MOQT (moq-lite, hang's "loc" container) a LOC frame is
 * self-contained, as libloc's loc_encode() writes it: a property count, each
 * property as an absolute identifier with an integer (even) or a
 * length-prefixed value (odd), then the payload. That is the "moq_loc.frame"
 * dissector.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/charsets.h>

#include "packet-moq-loc.h"
#include "packet-moqt.h"

void proto_register_moq_loc(void);
void proto_reg_handoff_moq_loc(void);

/* draft-03 and later, in the MOQ Properties Registry. */
#define LOC_PROP_TIMESCALE            0x08
#define LOC_PROP_VIDEO_FRAME_MARKING  0x09
#define LOC_PROP_AUDIO_LEVEL          0x0c
#define LOC_PROP_VIDEO_CONFIG         0x0d
#define LOC_PROP_AUDIO_CONFIG         0x0f
#define LOC_PROP_TIMESTAMP            0x10
#define LOC_PROP_CODEC_STRING         0x11
/* libloc's Codec ID, before draft-05 standardised the Codec String. */
#define LOC_PROP_CODEC_ID             0x21

/* draft-02 "LOC Header Extensions". */
#define LOC02_CAPTURE_TIMESTAMP       0x02
#define LOC02_VIDEO_FRAME_MARKING     0x04
#define LOC02_AUDIO_LEVEL             0x06
#define LOC02_TEXT_ENCODING           0x08
#define LOC02_VIDEO_CONFIG            0x0d
#define LOC02_TEXT_MIME_TYPE          0x0f

static int proto_moq_loc;

static int hf_loc_property_count;
static int hf_loc_property_id;
static int hf_loc_property_length;
static int hf_loc_property_integer;
static int hf_loc_property_value;
static int hf_loc_version;
static int hf_loc_timestamp;
static int hf_loc_timescale;
static int hf_loc_capture_time;
static int hf_loc_media_time;
static int hf_loc_vfm;
static int hf_loc_vfm_start;
static int hf_loc_vfm_end;
static int hf_loc_vfm_independent;
static int hf_loc_vfm_discardable;
static int hf_loc_vfm_base_layer_sync;
static int hf_loc_vfm_tid;
static int hf_loc_vfm_lid;
static int hf_loc_vfm_tl0picidx;
static int hf_loc_audio_level;
static int hf_loc_audio_level_voice;
static int hf_loc_audio_level_dbov;
static int hf_loc_video_config;
static int hf_loc_audio_config;
static int hf_loc_config_version;
static int hf_loc_config_nal_length_size;
static int hf_loc_config_nal_length;
static int hf_loc_codec_string;
static int hf_loc_text_encoding;
static int hf_loc_text_mime_type;
static int hf_loc_codec;
static int hf_loc_nal_length;
static int hf_loc_payload;

static int ett_loc;
static int ett_loc_properties;
static int ett_loc_property;
static int ett_loc_vfm;
static int ett_loc_audio_level;
static int ett_loc_config;

static expert_field ei_loc_malformed;
static expert_field ei_loc_bad_nal_length;
static expert_field ei_loc_unknown_codec;

static dissector_table_t loc_codec_table;
static dissector_handle_t loc_frame_handle;
static dissector_handle_t h264_handle;
static dissector_handle_t h264_bytestream_handle;
static dissector_handle_t h265_handle;
static dissector_handle_t h265_bytestream_handle;
static dissector_handle_t opus_handle;

static const value_string loc_version_vals[] = {
    { 2, "draft-ietf-moq-loc-02" },
    { 3, "draft-ietf-moq-loc-03 or later" },
    { 0, NULL }
};

static const val64_string loc_property_vals[] = {
    { LOC_PROP_TIMESCALE,           "TIMESCALE" },
    { LOC_PROP_VIDEO_FRAME_MARKING, "VIDEO_FRAME_MARKING" },
    { LOC_PROP_AUDIO_LEVEL,         "AUDIO_LEVEL" },
    { LOC_PROP_VIDEO_CONFIG,        "VIDEO_CONFIG" },
    { LOC_PROP_AUDIO_CONFIG,        "AUDIO_CONFIG" },
    { LOC_PROP_TIMESTAMP,           "TIMESTAMP" },
    { LOC_PROP_CODEC_STRING,        "CODEC_STRING" },
    { LOC_PROP_CODEC_ID,            "Codec ID (libloc)" },
    { 0, NULL }
};

static const val64_string loc02_property_vals[] = {
    { 0x00,                         "Key ID" },
    { LOC02_CAPTURE_TIMESTAMP,      "Capture Timestamp" },
    { LOC02_VIDEO_FRAME_MARKING,    "Video Frame Marking" },
    { LOC02_AUDIO_LEVEL,            "Audio Level" },
    { LOC02_TEXT_ENCODING,          "Text Encoding" },
    { LOC02_VIDEO_CONFIG,           "Video Config" },
    { LOC02_TEXT_MIME_TYPE,         "Text MIME Type" },
    { LOC_PROP_CODEC_ID,            "Codec ID (libloc)" },
    { 0, NULL }
};

static const value_string loc_text_encoding_vals[] = {
    { 0, "UTF-8" },
    { 1, "UTF-16LE" },
    { 2, "UTF-16BE" },
    { 3, "US-ASCII" },
    { 0, NULL }
};

static int * const loc_vfm_fields[] = {
    &hf_loc_vfm_start,
    &hf_loc_vfm_end,
    &hf_loc_vfm_independent,
    &hf_loc_vfm_discardable,
    &hf_loc_vfm_base_layer_sync,
    &hf_loc_vfm_tid,
    NULL
};

static int * const loc_audio_level_fields[] = {
    &hf_loc_audio_level_voice,
    &hf_loc_audio_level_dbov,
    NULL
};

/* Data passed to the built-in codec handlers in the "moq_loc.codec" table. */
typedef struct {
    const char *codec;
    unsigned nal_length_size;   /* 0: not known */
} loc_codec_info_t;

/* ------------------------------------------------------------------------- */
/* Properties                                                                */
/* ------------------------------------------------------------------------- */

/* RFC 9626 Video Frame Marking; the short form has no LID or TL0PICIDX. */
static void
loc_add_vfm(proto_tree *tree, tvbuff_t *tvb, int length, uint32_t packed,
            unsigned bytes)
{
    proto_item *item;
    proto_tree *vfm_tree;

    item = proto_tree_add_bitmask_value(tree, tvb, 0, hf_loc_vfm, ett_loc_vfm,
                                        loc_vfm_fields, packed & 0xff);
    proto_item_set_len(item, length);
    vfm_tree = proto_item_add_subtree(item, ett_loc_vfm);
    if (bytes >= 2) {
        proto_tree_add_uint(vfm_tree, hf_loc_vfm_lid, tvb, 0, length,
                            (packed >> 8) & 0xff);
    }
    if (bytes >= 3) {
        proto_tree_add_uint(vfm_tree, hf_loc_vfm_tl0picidx, tvb, 0, length,
                            (packed >> 16) & 0xff);
    }
}

static void
loc_add_audio_level(proto_tree *tree, tvbuff_t *tvb, int length, uint64_t raw)
{
    proto_item *item;

    item = proto_tree_add_bitmask_value(tree, tvb, 0, hf_loc_audio_level,
                                        ett_loc_audio_level,
                                        loc_audio_level_fields, raw & 0xff);
    proto_item_set_len(item, length);
    proto_item_append_text(item, " (%s-%u dBov)",
                           (raw & 0x80) ? "voice, " : "",
                           (unsigned)(raw & 0x7f));
}

/*
 * The parameter sets of an AVCDecoderConfigurationRecord (ISO/IEC 14496-15
 * 5.3.3.1), each handed to the H.264 dissector.
 */
static bool
loc_dissect_avcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int length = tvb_reported_length(tvb);
    int offset = 6;

    if (length < 7 || tvb_get_uint8(tvb, 0) != 1 ||
        (tvb_get_uint8(tvb, 4) & 0xfc) != 0xfc ||
        (tvb_get_uint8(tvb, 5) & 0xe0) != 0xe0) {
        return false;
    }
    proto_tree_add_item(tree, hf_loc_config_version, tvb, 0, 1, ENC_NA);
    proto_tree_add_uint(tree, hf_loc_config_nal_length_size, tvb, 4, 1,
                        (tvb_get_uint8(tvb, 4) & 0x03) + 1);
    for (int set = 0; set < 2; set++) {
        unsigned count;

        if (set == 0) {
            count = tvb_get_uint8(tvb, 5) & 0x1f;
        } else {
            count = tvb_get_uint8(tvb, offset);
            offset++;
        }
        for (unsigned i = 0; i < count; i++) {
            uint32_t nal_length;

            proto_tree_add_item_ret_uint(tree, hf_loc_config_nal_length, tvb,
                                         offset, 2, ENC_BIG_ENDIAN, &nal_length);
            offset += 2;
            if (h264_handle && nal_length > 0) {
                call_dissector(h264_handle,
                               tvb_new_subset_length(tvb, offset, nal_length),
                               pinfo, tree);
            }
            offset += nal_length;
        }
    }
    return true;
}

/* An HEVCDecoderConfigurationRecord (ISO/IEC 14496-15 8.3.3.1). */
static bool
loc_dissect_hvcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int length = tvb_reported_length(tvb);
    int offset = 23;
    unsigned arrays;

    if (length < 23 || tvb_get_uint8(tvb, 0) != 1 ||
        (tvb_get_uint8(tvb, 13) & 0xf0) != 0xf0 ||
        (tvb_get_uint8(tvb, 15) & 0xfc) != 0xfc ||
        (tvb_get_uint8(tvb, 16) & 0xfc) != 0xfc ||
        (tvb_get_uint8(tvb, 17) & 0xf8) != 0xf8 ||
        (tvb_get_uint8(tvb, 18) & 0xf8) != 0xf8) {
        return false;
    }
    proto_tree_add_item(tree, hf_loc_config_version, tvb, 0, 1, ENC_NA);
    proto_tree_add_uint(tree, hf_loc_config_nal_length_size, tvb, 21, 1,
                        (tvb_get_uint8(tvb, 21) & 0x03) + 1);
    arrays = tvb_get_uint8(tvb, 22);
    for (unsigned a = 0; a < arrays; a++) {
        unsigned count = tvb_get_ntohs(tvb, offset + 1);

        offset += 3;
        for (unsigned i = 0; i < count; i++) {
            uint32_t nal_length;

            proto_tree_add_item_ret_uint(tree, hf_loc_config_nal_length, tvb,
                                         offset, 2, ENC_BIG_ENDIAN, &nal_length);
            offset += 2;
            if (h265_handle && nal_length > 0) {
                call_dissector(h265_handle,
                               tvb_new_subset_length(tvb, offset, nal_length),
                               pinfo, tree);
            }
            offset += nal_length;
        }
    }
    return true;
}

/* The NAL unit length size a decoder configuration record declares. */
static unsigned
loc_config_nal_length_size(const uint8_t *data, unsigned length)
{
    if (length >= 7 && data[0] == 1 && (data[4] & 0xfc) == 0xfc &&
        (data[5] & 0xe0) == 0xe0) {
        return (data[4] & 0x03) + 1u;
    }
    if (length >= 23 && data[0] == 1 && (data[13] & 0xf0) == 0xf0) {
        return (data[21] & 0x03) + 1u;
    }
    return 0;
}

static void
loc_add_video_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *config_tree;

    item = proto_tree_add_item(tree, hf_loc_video_config, tvb, 0, -1, ENC_NA);
    config_tree = proto_item_add_subtree(item, ett_loc_config);
    if (loc_dissect_avcc(tvb, pinfo, config_tree)) {
        proto_item_append_text(item, " (AVCDecoderConfigurationRecord)");
    } else if (loc_dissect_hvcc(tvb, pinfo, config_tree)) {
        proto_item_append_text(item, " (HEVCDecoderConfigurationRecord)");
    }
}

/*
 * Decode one property value. tvb holds the value: the integer's encoding for
 * an even identifier (its value is "integer"), the bytes for an odd one.
 * Returns false for an identifier LOC does not define.
 */
static bool
loc_dissect_property_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           uint64_t id, uint64_t integer, bool draft02)
{
    int length = tvb_reported_length(tvb);
    proto_item *item;

    if (draft02) {
        switch (id) {
        case LOC02_CAPTURE_TIMESTAMP:
            proto_tree_add_uint64(tree, hf_loc_timestamp, tvb, 0, length, integer);
            return true;
        case LOC02_VIDEO_FRAME_MARKING:
            loc_add_vfm(tree, tvb, length, (uint32_t)integer,
                        (integer & 0xffff00) != 0 ? 3 : 1);
            return true;
        case LOC02_AUDIO_LEVEL:
            loc_add_audio_level(tree, tvb, length, integer);
            return true;
        case LOC02_TEXT_ENCODING:
            item = proto_tree_add_uint64(tree, hf_loc_text_encoding, tvb, 0,
                                         length, integer);
            proto_item_append_text(item, " (%s)",
                                   val_to_str_const((uint32_t)integer,
                                                    loc_text_encoding_vals,
                                                    "Unknown"));
            return true;
        case LOC02_VIDEO_CONFIG:
            loc_add_video_config(tvb, pinfo, tree);
            return true;
        case LOC02_TEXT_MIME_TYPE:
            proto_tree_add_item(tree, hf_loc_text_mime_type, tvb, 0, length,
                                ENC_UTF_8);
            return true;
        case LOC_PROP_CODEC_ID:
            proto_tree_add_item(tree, hf_loc_codec_string, tvb, 0, length,
                                ENC_UTF_8);
            return true;
        default:
            return false;
        }
    }

    switch (id) {
    case LOC_PROP_TIMESCALE:
        item = proto_tree_add_uint64(tree, hf_loc_timescale, tvb, 0, length, integer);
        proto_item_append_text(item, " units/s");
        return true;
    case LOC_PROP_TIMESTAMP:
        proto_tree_add_uint64(tree, hf_loc_timestamp, tvb, 0, length, integer);
        return true;
    case LOC_PROP_VIDEO_FRAME_MARKING: {
        uint32_t packed = 0;

        if (length < 1 || length > 4) {
            proto_tree_add_expert_format(tree, pinfo, &ei_loc_malformed, tvb, 0,
                                         length,
                                         "Video Frame Marking is %d bytes; "
                                         "it must be 1 to 4", length);
            return true;
        }
        for (int i = 0; i < length; i++) {
            packed |= (uint32_t)tvb_get_uint8(tvb, i) << (8 * i);
        }
        loc_add_vfm(tree, tvb, length, packed, (unsigned)length);
        return true;
    }
    case LOC_PROP_AUDIO_LEVEL:
        loc_add_audio_level(tree, tvb, length, integer);
        return true;
    case LOC_PROP_VIDEO_CONFIG:
        loc_add_video_config(tvb, pinfo, tree);
        return true;
    case LOC_PROP_AUDIO_CONFIG:
        proto_tree_add_item(tree, hf_loc_audio_config, tvb, 0, length, ENC_NA);
        return true;
    case LOC_PROP_CODEC_STRING:
    case LOC_PROP_CODEC_ID:
        proto_tree_add_item(tree, hf_loc_codec_string, tvb, 0, length, ENC_UTF_8);
        return true;
    default:
        return false;
    }
}

/* "moqt.property": a LOC property in MOQT Object or Track Properties. */
static int
dissect_loc_moqt_property(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          void *data)
{
    const moqt_property_info_t *info = (const moqt_property_info_t *)data;

    if (!info) {
        return 0;
    }
    if (!loc_dissect_property_value(tvb, pinfo, tree, info->type, info->integer,
                                    false)) {
        return 0;
    }
    return tvb_captured_length(tvb);
}

/* ------------------------------------------------------------------------- */
/* Payloads                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * H.264 and H.265 payloads are either Annex B byte streams or, when the
 * track has a decoder configuration record, length-prefixed NAL units.
 */
static int
loc_dissect_nal_units(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      dissector_handle_t nal_handle,
                      dissector_handle_t bytestream_handle,
                      unsigned length_size)
{
    int length = tvb_reported_length(tvb);
    int offset = 0;

    if ((length >= 3 && tvb_get_ntoh24(tvb, 0) == 1) ||
        (length >= 4 && tvb_get_ntohl(tvb, 0) == 1)) {
        call_dissector(bytestream_handle, tvb, pinfo, tree);
        return length;
    }
    if (length_size != 1 && length_size != 2 && length_size != 4) {
        length_size = 4;
    }
    while (offset < length) {
        proto_item *item;
        uint32_t nal_length;

        if (length - offset < (int)length_size) {
            proto_tree_add_expert(tree, pinfo, &ei_loc_bad_nal_length, tvb,
                                  offset, length - offset);
            break;
        }
        item = proto_tree_add_item_ret_uint(tree, hf_loc_nal_length, tvb, offset,
                                            length_size, ENC_BIG_ENDIAN,
                                            &nal_length);
        offset += length_size;
        if (nal_length == 0 || nal_length > (uint32_t)(length - offset)) {
            expert_add_info(pinfo, item, &ei_loc_bad_nal_length);
            proto_tree_add_item(tree, hf_loc_payload, tvb, offset, -1, ENC_NA);
            break;
        }
        call_dissector(nal_handle,
                       tvb_new_subset_length(tvb, offset, nal_length),
                       pinfo, tree);
        offset += nal_length;
    }
    return length;
}

static int
dissect_loc_avc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const loc_codec_info_t *info = (const loc_codec_info_t *)data;

    return loc_dissect_nal_units(tvb, pinfo, tree, h264_handle,
                                 h264_bytestream_handle,
                                 info ? info->nal_length_size : 0);
}

static int
dissect_loc_hevc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const loc_codec_info_t *info = (const loc_codec_info_t *)data;

    return loc_dissect_nal_units(tvb, pinfo, tree, h265_handle,
                                 h265_bytestream_handle,
                                 info ? info->nal_length_size : 0);
}

/*
 * Route a payload by its WebCodecs codec string, keyed in "moq_loc.codec" by
 * the part before the first '.' ("avc1", "opus", ...).
 */
static void
loc_dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    proto_item *loc_item, const char *codec,
                    unsigned nal_length_size)
{
    loc_codec_info_t info = { codec, nal_length_size };

    if (tvb_reported_length(tvb) == 0) {
        return;
    }
    if (codec) {
        const char *dot = strchr(codec, '.');
        char *key = dot ? wmem_strndup(pinfo->pool, codec, dot - codec)
                        : wmem_strdup(pinfo->pool, codec);

        proto_item_append_text(loc_item, ", %s", codec);
        if (dissector_try_string_with_data(loc_codec_table, key, tvb, pinfo,
                                           tree, true, &info)) {
            return;
        }
        proto_tree_add_expert_format(tree, pinfo, &ei_loc_unknown_codec, tvb, 0, 0,
                                     "No dissector for codec \"%s\"", codec);
    }
    proto_tree_add_item(tree, hf_loc_payload, tvb, 0, -1, ENC_NA);
}

static const char *
loc_property_string(wmem_allocator_t *scope, const moqt_property_t *property)
{
    if (!property || !property->data) {
        return NULL;
    }
    return (const char *)get_utf_8_string(scope, property->data, property->length);
}

static void
loc_add_presentation_time(proto_tree *tree, tvbuff_t *tvb, uint64_t timestamp,
                          bool timestamp_known, uint64_t timescale)
{
    proto_item *item;
    nstime_t t;

    if (!timestamp_known) {
        return;
    }
    if (timescale != 0) {
        t.secs = (time_t)(timestamp / timescale);
        t.nsecs = (int)(((timestamp % timescale) * 1000000000) / timescale);
        item = proto_tree_add_time(tree, hf_loc_media_time, tvb, 0, 0, &t);
    } else {
        /* Without a Timescale the Timestamp is in microseconds since 1970. */
        t.secs = (time_t)(timestamp / 1000000);
        t.nsecs = (int)((timestamp % 1000000) * 1000);
        item = proto_tree_add_time(tree, hf_loc_capture_time, tvb, 0, 0, &t);
    }
    proto_item_set_generated(item);
}

static void
loc_dissect_moqt_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        const moqt_object_info_t *info, const char *codec_hint)
{
    const moqt_property_t *timestamp, *timescale, *codec, *config;
    proto_item *item, *loc_item;
    proto_tree *loc_tree;
    const char *codec_string;

    loc_item = proto_tree_add_item(tree, proto_moq_loc, tvb, 0, -1, ENC_NA);
    loc_tree = proto_item_add_subtree(loc_item, ett_loc);

    codec = moqt_object_find_property(info, LOC_PROP_CODEC_STRING);
    if (!codec) {
        codec = moqt_object_find_property(info, LOC_PROP_CODEC_ID);
    }
    codec_string = loc_property_string(pinfo->pool, codec);
    if (!codec_string) {
        codec_string = codec_hint;
    }
    if (codec_string) {
        item = proto_tree_add_string(loc_tree, hf_loc_codec, tvb, 0, 0, codec_string);
        proto_item_set_generated(item);
    }
    timestamp = moqt_object_find_property(info, LOC_PROP_TIMESTAMP);
    timescale = moqt_object_find_property(info, LOC_PROP_TIMESCALE);
    loc_add_presentation_time(loc_tree, tvb, timestamp ? timestamp->integer : 0,
                              timestamp != NULL,
                              timescale ? timescale->integer : 0);
    config = moqt_object_find_property(info, LOC_PROP_VIDEO_CONFIG);
    loc_dissect_payload(tvb, pinfo, loc_tree, loc_item, codec_string,
                        config && config->data
                            ? loc_config_nal_length_size(config->data, config->length)
                            : 0);
}

/* "moq_loc.object": a MOQT Object a streaming format says is LOC. */
static int
dissect_loc_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moq_loc_object_info_t *info = (const moq_loc_object_info_t *)data;

    if (!info || !info->object) {
        return 0;
    }
    loc_dissect_moqt_object(tvb, pinfo, tree, info->object, info->codec);
    return tvb_captured_length(tvb);
}

/*
 * "moqt.payload": an Object is LOC when it or its track has a LOC property
 * other than TIMESCALE, which is too generic to rely on.
 */
static bool
dissect_loc_moqt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
    const moqt_object_info_t *info = (const moqt_object_info_t *)data;
    static const uint64_t markers[] = {
        LOC_PROP_VIDEO_FRAME_MARKING, LOC_PROP_AUDIO_LEVEL, LOC_PROP_VIDEO_CONFIG,
        LOC_PROP_AUDIO_CONFIG, LOC_PROP_TIMESTAMP, LOC_PROP_CODEC_STRING,
        LOC_PROP_CODEC_ID,
    };
    bool found = false;

    if (!info) {
        return false;
    }
    for (unsigned i = 0; i < array_length(markers) && !found; i++) {
        found = moqt_object_find_property(info, markers[i]) != NULL;
    }
    if (!found) {
        return false;
    }
    loc_dissect_moqt_object(tvb, pinfo, tree, info, NULL);
    return true;
}

/*
 * draft-02 and draft-03 renumbered the properties. As libloc does, take a
 * frame as draft-02 only when it uses a draft-02 identifier and no draft-03
 * one; draft-03 to -05 share their numbering.
 */
static bool
loc_frame_is_draft02(tvbuff_t *tvb)
{
    int length = tvb_reported_length(tvb);
    uint64_t count, id, value;
    int offset, consumed;
    bool draft02 = false;

    offset = tvb_get_varint(tvb, 0, length, &count, ENC_VARINT_QUIC);
    if (offset == 0) {
        return false;
    }
    for (uint64_t i = 0; i < count && offset < length; i++) {
        consumed = tvb_get_varint(tvb, offset, length - offset, &id, ENC_VARINT_QUIC);
        if (consumed == 0) {
            break;
        }
        offset += consumed;
        switch (id) {
        case LOC_PROP_TIMESTAMP:
        case LOC_PROP_VIDEO_FRAME_MARKING:
        case LOC_PROP_AUDIO_LEVEL:
            return false;
        case LOC02_CAPTURE_TIMESTAMP:
        case LOC02_VIDEO_FRAME_MARKING:
        case LOC02_AUDIO_LEVEL:
            draft02 = true;
            break;
        default:
            break;
        }
        consumed = tvb_get_varint(tvb, offset, length - offset, &value, ENC_VARINT_QUIC);
        if (consumed == 0) {
            break;
        }
        offset += consumed;
        if ((id & 1) != 0) {
            if (value > (uint64_t)(length - offset)) {
                break;
            }
            offset += (int)value;
        }
    }
    return draft02;
}

/* "moq_loc.frame": a property count, the properties, then the payload. */
static int
dissect_loc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moq_loc_frame_info_t *frame_info = (const moq_loc_frame_info_t *)data;
    int length = tvb_reported_length(tvb);
    bool draft02 = loc_frame_is_draft02(tvb);
    const val64_string *names = draft02 ? loc02_property_vals : loc_property_vals;
    proto_item *loc_item, *props_item, *item;
    proto_tree *loc_tree, *props_tree;
    const char *codec, *codec_string = NULL, *codec_id = NULL;
    uint64_t count, timestamp = 0, timescale = 0;
    bool timestamp_known = false;
    unsigned nal_length_size = 0;
    unsigned consumed;
    int offset = 0;

    loc_item = proto_tree_add_item(tree, proto_moq_loc, tvb, 0, -1, ENC_NA);
    loc_tree = proto_item_add_subtree(loc_item, ett_loc);
    item = proto_tree_add_uint(loc_tree, hf_loc_version, tvb, 0, 0, draft02 ? 2 : 3);
    proto_item_set_generated(item);

    props_tree = proto_tree_add_subtree(loc_tree, tvb, 0, -1, ett_loc_properties,
                                        &props_item, "Properties");
    item = proto_tree_add_item_ret_varint(props_tree, hf_loc_property_count, tvb,
                                          0, -1, ENC_VARINT_QUIC, &count, &consumed);
    if (consumed == 0) {
        expert_add_info(pinfo, item, &ei_loc_malformed);
        return length;
    }
    offset = consumed;
    for (uint64_t i = 0; i < count; i++) {
        proto_item *prop_item;
        proto_tree *prop_tree;
        uint64_t id, value;
        int start = offset;
        tvbuff_t *value_tvb;

        prop_tree = proto_tree_add_subtree(props_tree, tvb, offset, -1,
                                           ett_loc_property, &prop_item, "Property");
        item = proto_tree_add_item_ret_varint(prop_tree, hf_loc_property_id, tvb,
                                              offset, -1, ENC_VARINT_QUIC, &id,
                                              &consumed);
        if (consumed == 0) {
            expert_add_info(pinfo, item, &ei_loc_malformed);
            return length;
        }
        offset += consumed;
        proto_item_append_text(prop_item, ": %s (0x%" PRIx64 ")",
                               val64_to_str_const(id, names, "Unknown"), id);
        if ((id & 1) == 0) {
            item = proto_tree_add_item_ret_varint(prop_tree, hf_loc_property_integer,
                                                  tvb, offset, -1, ENC_VARINT_QUIC,
                                                  &value, &consumed);
            if (consumed == 0) {
                expert_add_info(pinfo, item, &ei_loc_malformed);
                return length;
            }
            value_tvb = tvb_new_subset_length(tvb, offset, consumed);
            offset += consumed;
        } else {
            item = proto_tree_add_item_ret_varint(prop_tree, hf_loc_property_length,
                                                  tvb, offset, -1, ENC_VARINT_QUIC,
                                                  &value, &consumed);
            if (consumed == 0 || value > (uint64_t)(length - offset - (int)consumed)) {
                expert_add_info(pinfo, item, &ei_loc_malformed);
                return length;
            }
            offset += consumed;
            proto_tree_add_item(prop_tree, hf_loc_property_value, tvb, offset,
                                (int)value, ENC_NA);
            value_tvb = tvb_new_subset_length(tvb, offset, (int)value);
            offset += (int)value;
        }
        loc_dissect_property_value(value_tvb, pinfo, prop_tree, id, value, draft02);
        proto_item_set_len(prop_item, offset - start);

        if (id == (draft02 ? LOC02_CAPTURE_TIMESTAMP : LOC_PROP_TIMESTAMP)) {
            timestamp = value;
            timestamp_known = true;
        } else if (!draft02 && id == LOC_PROP_TIMESCALE) {
            timescale = value;
        } else if (!draft02 && id == LOC_PROP_CODEC_STRING) {
            codec_string = (const char *)tvb_get_string_enc(
                pinfo->pool, value_tvb, 0, (int)value, ENC_UTF_8);
        } else if (id == LOC_PROP_CODEC_ID) {
            codec_id = (const char *)tvb_get_string_enc(
                pinfo->pool, value_tvb, 0, (int)value, ENC_UTF_8);
        } else if (id == LOC_PROP_VIDEO_CONFIG) {
            uint8_t *config = (uint8_t *)tvb_memdup(pinfo->pool, value_tvb, 0,
                                                    (int)value);

            nal_length_size = loc_config_nal_length_size(config, (unsigned)value);
        }
    }
    proto_item_set_len(props_item, offset);
    /* draft-05's Codec String wins over libloc's Codec ID and the container. */
    codec = codec_string ? codec_string
          : codec_id ? codec_id
          : frame_info ? frame_info->codec : NULL;
    if (codec) {
        item = proto_tree_add_string(loc_tree, hf_loc_codec, tvb, offset, 0, codec);
        proto_item_set_generated(item);
    }
    loc_add_presentation_time(loc_tree, tvb, timestamp, timestamp_known,
                              draft02 ? 0 : timescale);
    loc_dissect_payload(tvb_new_subset_remaining(tvb, offset), pinfo, loc_tree,
                        loc_item, codec, nal_length_size);
    return length;
}

void
proto_register_moq_loc(void)
{
    static hf_register_info hf[] = {
        { &hf_loc_property_count,
          { "Property Count", "moq_loc.property.count",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_property_id,
          { "Property ID", "moq_loc.property.id",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_property_length,
          { "Property Length", "moq_loc.property.length",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_property_integer,
          { "Property Value", "moq_loc.property.integer",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_property_value,
          { "Property Value", "moq_loc.property.value",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_version,
          { "Property Numbering", "moq_loc.version",
            FT_UINT8, BASE_DEC, VALS(loc_version_vals), 0x0,
            "LOC draft whose property identifiers this frame uses", HFILL }
        },
        { &hf_loc_timestamp,
          { "Timestamp", "moq_loc.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "In Timescale units, or microseconds since 1970 without a Timescale",
            HFILL }
        },
        { &hf_loc_timescale,
          { "Timescale", "moq_loc.timescale",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Timestamp units per second", HFILL }
        },
        { &hf_loc_capture_time,
          { "Capture Time", "moq_loc.capture_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Timestamp in microseconds since 1970", HFILL }
        },
        { &hf_loc_media_time,
          { "Media Time", "moq_loc.media_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Timestamp divided by the Timescale", HFILL }
        },
        { &hf_loc_vfm,
          { "Video Frame Marking", "moq_loc.vfm",
            FT_UINT8, BASE_HEX, NULL, 0x0, "RFC 9626 frame marking", HFILL }
        },
        { &hf_loc_vfm_start,
          { "Start of Frame", "moq_loc.vfm.start",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_loc_vfm_end,
          { "End of Frame", "moq_loc.vfm.end",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_loc_vfm_independent,
          { "Independent Frame", "moq_loc.vfm.independent",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
        },
        { &hf_loc_vfm_discardable,
          { "Discardable Frame", "moq_loc.vfm.discardable",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        { &hf_loc_vfm_base_layer_sync,
          { "Base Layer Sync", "moq_loc.vfm.base_layer_sync",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_loc_vfm_tid,
          { "Temporal ID", "moq_loc.vfm.tid",
            FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }
        },
        { &hf_loc_vfm_lid,
          { "Layer ID", "moq_loc.vfm.lid",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_vfm_tl0picidx,
          { "TL0PICIDX", "moq_loc.vfm.tl0picidx",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Temporal layer 0 picture index", HFILL }
        },
        { &hf_loc_audio_level,
          { "Audio Level", "moq_loc.audio_level",
            FT_UINT8, BASE_HEX, NULL, 0x0, "RFC 6464 audio level", HFILL }
        },
        { &hf_loc_audio_level_voice,
          { "Voice Activity", "moq_loc.audio_level.voice",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_loc_audio_level_dbov,
          { "Level (-dBov)", "moq_loc.audio_level.dbov",
            FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }
        },
        { &hf_loc_video_config,
          { "Video Config", "moq_loc.video_config",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Codec decoder configuration (WebCodecs description)", HFILL }
        },
        { &hf_loc_audio_config,
          { "Audio Config", "moq_loc.audio_config",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Codec decoder configuration (WebCodecs description)", HFILL }
        },
        { &hf_loc_config_version,
          { "Configuration Version", "moq_loc.config.version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_config_nal_length_size,
          { "NAL Unit Length Size", "moq_loc.config.nal_length_size",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_config_nal_length,
          { "Parameter Set Length", "moq_loc.config.nal_length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_codec_string,
          { "Codec String", "moq_loc.codec_string",
            FT_STRING, BASE_NONE, NULL, 0x0, "WebCodecs codec string", HFILL }
        },
        { &hf_loc_text_encoding,
          { "Text Encoding", "moq_loc.text_encoding",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_text_mime_type,
          { "Text MIME Type", "moq_loc.text_mime_type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_codec,
          { "Codec", "moq_loc.codec",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Codec string used to decode the payload", HFILL }
        },
        { &hf_loc_nal_length,
          { "NAL Unit Length", "moq_loc.nal_length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_loc_payload,
          { "Payload", "moq_loc.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_loc,
        &ett_loc_properties,
        &ett_loc_property,
        &ett_loc_vfm,
        &ett_loc_audio_level,
        &ett_loc_config,
    };

    static ei_register_info ei[] = {
        { &ei_loc_malformed,
          { "moq_loc.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed LOC property", EXPFILL }
        },
        { &ei_loc_bad_nal_length,
          { "moq_loc.nal_length.bad", PI_MALFORMED, PI_ERROR,
            "NAL unit length runs past the payload", EXPFILL }
        },
        { &ei_loc_unknown_codec,
          { "moq_loc.codec.unknown", PI_UNDECODED, PI_NOTE,
            "No dissector for this codec", EXPFILL }
        },
    };

    expert_module_t *expert_loc;

    proto_moq_loc = proto_register_protocol("Low Overhead Media Container",
                                            "LOC", "moq_loc");
    proto_register_field_array(proto_moq_loc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_loc = expert_register_protocol(proto_moq_loc);
    expert_register_field_array(expert_loc, ei, array_length(ei));

    loc_codec_table = register_dissector_table(
        "moq_loc.codec", "LOC codec (WebCodecs codec string prefix)",
        proto_moq_loc, FT_STRING, STRING_CASE_SENSITIVE);
    loc_frame_handle = register_dissector_with_description(
        "moq_loc.frame", "LOC frame (property count, properties, payload)",
        dissect_loc_frame, proto_moq_loc);
    register_dissector_with_description(
        "moq_loc.object", "LOC MOQT Object (with a codec from a catalog)",
        dissect_loc_object, proto_moq_loc);
}

void
proto_reg_handoff_moq_loc(void)
{
    static const uint32_t properties[] = {
        LOC_PROP_TIMESCALE, LOC_PROP_VIDEO_FRAME_MARKING, LOC_PROP_AUDIO_LEVEL,
        LOC_PROP_VIDEO_CONFIG, LOC_PROP_AUDIO_CONFIG, LOC_PROP_TIMESTAMP,
        LOC_PROP_CODEC_STRING, LOC_PROP_CODEC_ID,
    };
    dissector_handle_t property_handle =
        create_dissector_handle(dissect_loc_moqt_property, proto_moq_loc);
    dissector_handle_t avc_handle =
        create_dissector_handle(dissect_loc_avc, proto_moq_loc);
    dissector_handle_t hevc_handle =
        create_dissector_handle(dissect_loc_hevc, proto_moq_loc);

    for (unsigned i = 0; i < array_length(properties); i++) {
        dissector_add_uint("moqt.property", properties[i], property_handle);
    }
    heur_dissector_add("moqt.payload", dissect_loc_moqt_heur, "LOC over MOQT",
                       "loc_moqt", proto_moq_loc, HEURISTIC_ENABLE);

    h264_handle = find_dissector_add_dependency("h264", proto_moq_loc);
    h264_bytestream_handle = find_dissector_add_dependency("h264_bytestream",
                                                           proto_moq_loc);
    h265_handle = find_dissector_add_dependency("h265", proto_moq_loc);
    h265_bytestream_handle = find_dissector_add_dependency("h265_bytestream",
                                                           proto_moq_loc);
    opus_handle = find_dissector_add_dependency("opus", proto_moq_loc);

    dissector_add_string("moq_loc.codec", "avc1", avc_handle);
    dissector_add_string("moq_loc.codec", "avc3", avc_handle);
    dissector_add_string("moq_loc.codec", "hev1", hevc_handle);
    dissector_add_string("moq_loc.codec", "hvc1", hevc_handle);
    dissector_add_string("moq_loc.codec", "opus", opus_handle);
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
