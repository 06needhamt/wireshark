/* packet-moq-mi.c
 * Routines for MoQ Media Interop (moq-mi) dissection
 * draft-cenzano-moq-media-interop-03, also -02 and -01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * moq-mi carries one media frame per MOQT Object on tracks named
 * "video<idx>" and "audio<idx>" ("text<idx>" is libloc's addition).
 *
 * Draft -02 and -03 put the metadata in Object Properties:
 *   0x0A Media Type (integer): 0 H.264 (AVCC), 1 Opus, 2 UTF-8 text, 3 AAC-LC
 *   0x0B (-02) / 0x15 (-03) H.264 metadata, 0x0F Opus, 0x11 text,
 *   0x13 AAC-LC metadata: QUIC varints (see below)
 *   0x0D AVCDecoderConfigurationRecord, at a group start after a change
 * and the payload is the media itself.
 *
 * Draft -01 puts the Media Type and the same varints at the start of the
 * payload, the H.264 decoder configuration as a length-prefixed field.
 *
 * The varints are Seq ID, PTS, DTS, Timebase, Duration and Wallclock for
 * H.264; Seq ID, PTS, Timebase, Sample Frequency, Channels, Duration and
 * Wallclock for audio; Seq ID for text.
 *
 * These property types are also used by LOC and Secure Objects, so moq-mi
 * is recognised only by its track names together with a Media Type.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-moqt.h"

void proto_register_moq_mi(void);
void proto_reg_handoff_moq_mi(void);

#define MOQ_MI_PROP_MEDIA_TYPE      0x0a
#define MOQ_MI_PROP_H264_META_02    0x0b
#define MOQ_MI_PROP_H264_EXTRADATA  0x0d
#define MOQ_MI_PROP_OPUS_META       0x0f
#define MOQ_MI_PROP_TEXT_META       0x11
#define MOQ_MI_PROP_AAC_META        0x13
#define MOQ_MI_PROP_H264_META_03    0x15

#define MOQ_MI_TYPE_H264   0
#define MOQ_MI_TYPE_OPUS   1
#define MOQ_MI_TYPE_TEXT   2
#define MOQ_MI_TYPE_AAC_LC 3

static int proto_moq_mi;

static int hf_mi_version;
static int hf_mi_media_type;
static int hf_mi_seq_id;
static int hf_mi_pts;
static int hf_mi_dts;
static int hf_mi_timebase;
static int hf_mi_sample_freq;
static int hf_mi_channels;
static int hf_mi_duration;
static int hf_mi_wallclock;
static int hf_mi_wallclock_time;
static int hf_mi_pts_time;
static int hf_mi_extradata_length;
static int hf_mi_extradata;
static int hf_mi_text;
static int hf_mi_payload;

static int ett_mi;
static int ett_mi_metadata;

static expert_field ei_mi_truncated;
static expert_field ei_mi_missing_metadata;
static expert_field ei_mi_unknown_type;

static dissector_table_t loc_codec_table;
static dissector_handle_t h264_handle;

static const value_string mi_version_vals[] = {
    { 1, "draft-01 (metadata in the payload)" },
    { 2, "draft-02" },
    { 3, "draft-03" },
    { 23, "draft-02 or -03" },
    { 0, NULL }
};

static const value_string mi_media_type_vals[] = {
    { MOQ_MI_TYPE_H264,   "H.264 (AVCC)" },
    { MOQ_MI_TYPE_OPUS,   "Opus" },
    { MOQ_MI_TYPE_TEXT,   "UTF-8 text" },
    { MOQ_MI_TYPE_AAC_LC, "AAC-LC" },
    { 0, NULL }
};

/* "video0", "audio12", ... */
static bool
mi_track_name_matches(const char *name)
{
    static const char *const prefixes[] = { "video", "audio", "text" };

    for (unsigned i = 0; i < array_length(prefixes); i++) {
        size_t length = strlen(prefixes[i]);

        if (strncmp(name, prefixes[i], length) == 0 && name[length] != '\0') {
            const char *p = name + length;

            while (g_ascii_isdigit(*p)) {
                p++;
            }
            if (*p == '\0') {
                return true;
            }
        }
    }
    return false;
}

static const moqt_property_t *
mi_object_property(const moqt_object_info_t *info, uint64_t type)
{
    for (unsigned i = 0; i < info->property_count; i++) {
        if (info->properties[i].type == type) {
            return &info->properties[i];
        }
    }
    return NULL;
}

/*
 * The metadata varints of one Media Type. Returns the offset after them, or
 * -1 when they are truncated.
 */
static int
mi_dissect_metadata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                    uint32_t media_type)
{
    static int *const video[] = {
        &hf_mi_seq_id, &hf_mi_pts, &hf_mi_dts, &hf_mi_timebase, &hf_mi_duration,
        &hf_mi_wallclock, NULL };
    static int *const audio[] = {
        &hf_mi_seq_id, &hf_mi_pts, &hf_mi_timebase, &hf_mi_sample_freq,
        &hf_mi_channels, &hf_mi_duration, &hf_mi_wallclock, NULL };
    static int *const text[] = { &hf_mi_seq_id, NULL };
    int *const *fields;
    uint64_t pts = 0, timebase = 0;

    switch (media_type) {
    case MOQ_MI_TYPE_H264:
        fields = video;
        break;
    case MOQ_MI_TYPE_OPUS:
    case MOQ_MI_TYPE_AAC_LC:
        fields = audio;
        break;
    default:
        fields = text;
        break;
    }
    for (; *fields; fields++) {
        proto_item *item;
        uint64_t value;
        unsigned length;

        item = proto_tree_add_item_ret_varint(tree, **fields, tvb, offset, -1,
                                              ENC_VARINT_QUIC, &value, &length);
        if (length == 0) {
            expert_add_info(pinfo, item, &ei_mi_truncated);
            return -1;
        }
        if (**fields == hf_mi_pts) {
            pts = value;
        } else if (**fields == hf_mi_timebase) {
            timebase = value;
            if (timebase != 0) {
                nstime_t t = { (time_t)(pts / timebase),
                               (int)(((pts % timebase) * 1000000000) / timebase) };

                proto_item_set_generated(
                    proto_tree_add_time(tree, hf_mi_pts_time, tvb, offset, length, &t));
            }
        } else if (**fields == hf_mi_wallclock && value != 0) {
            nstime_t t = { (time_t)(value / 1000), (int)((value % 1000) * 1000000) };

            proto_item_set_generated(
                proto_tree_add_time(tree, hf_mi_wallclock_time, tvb, offset, length, &t));
        }
        offset += length;
    }
    return offset;
}

static void
mi_dissect_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t media_type)
{
    if (tvb_reported_length(tvb) == 0) {
        return;
    }
    switch (media_type) {
    case MOQ_MI_TYPE_H264:
        /* AVCC framing with 4-byte NAL unit lengths. */
        if (dissector_try_string_with_data(loc_codec_table, "avc1", tvb, pinfo, tree,
                                           true, NULL)) {
            return;
        }
        break;
    case MOQ_MI_TYPE_OPUS:
        if (dissector_try_string_with_data(loc_codec_table, "opus", tvb, pinfo, tree,
                                           true, NULL)) {
            return;
        }
        break;
    case MOQ_MI_TYPE_TEXT:
        proto_tree_add_item(tree, hf_mi_text, tvb, 0, -1, ENC_UTF_8);
        return;
    default:
        break;
    }
    proto_tree_add_item(tree, hf_mi_payload, tvb, 0, -1, ENC_NA);
}

/* A property's bytes as a tvb of their own, for decoding and highlighting. */
static tvbuff_t *
mi_property_tvb(tvbuff_t *parent, packet_info *pinfo, const moqt_property_t *property,
                const char *name)
{
    tvbuff_t *tvb = tvb_new_child_real_data(parent, property->data, property->length,
                                            property->length);

    add_new_data_source(pinfo, tvb, name);
    return tvb;
}

static void
mi_dissect_extradata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item = proto_tree_add_item(tree, hf_mi_extradata, tvb, 0, -1, ENC_NA);
    proto_tree *config_tree = proto_item_add_subtree(item, ett_mi_metadata);
    int length = tvb_reported_length(tvb);

    /* AVCDecoderConfigurationRecord: the SPS and PPS go to H.264. */
    if (length >= 7 && tvb_get_uint8(tvb, 0) == 1 && h264_handle) {
        int offset = 6;
        unsigned count = tvb_get_uint8(tvb, 5) & 0x1f;

        for (int set = 0; set < 2 && offset < length; set++) {
            if (set == 1) {
                count = tvb_get_uint8(tvb, offset++);
            }
            for (unsigned i = 0; i < count && offset + 2 <= length; i++) {
                unsigned nal = tvb_get_ntohs(tvb, offset);

                offset += 2;
                if (nal == 0 || nal > (unsigned)(length - offset)) {
                    return;
                }
                call_dissector(h264_handle, tvb_new_subset_length(tvb, offset, nal),
                               pinfo, config_tree);
                offset += nal;
            }
        }
    }
}

static bool
dissect_moq_mi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moqt_object_info_t *info = (const moqt_object_info_t *)data;
    const moqt_property_t *media_type_prop, *meta = NULL, *extradata;
    proto_item *mi_item, *item;
    proto_tree *mi_tree, *meta_tree;
    uint32_t media_type, version;
    int offset = 0;

    if (!info || !info->track_name || !mi_track_name_matches(info->track_name)) {
        return false;
    }
    media_type_prop = mi_object_property(info, MOQ_MI_PROP_MEDIA_TYPE);

    if (!media_type_prop) {
        /* Draft -01: a known Media Type at the start of the payload. */
        uint64_t value;

        if (info->property_count != 0 ||
            tvb_get_varint(tvb, 0, tvb_reported_length(tvb), &value, ENC_VARINT_QUIC) != 1 ||
            value > MOQ_MI_TYPE_AAC_LC) {
            return false;
        }
    }

    mi_item = proto_tree_add_item(tree, proto_moq_mi, tvb, 0, -1, ENC_NA);
    mi_tree = proto_item_add_subtree(mi_item, ett_mi);

    if (!media_type_prop) {
        version = 1;
        proto_item_set_generated(proto_tree_add_uint(mi_tree, hf_mi_version, tvb, 0, 0,
                                                     version));
        proto_tree_add_item_ret_uint(mi_tree, hf_mi_media_type, tvb, 0, 1, ENC_NA,
                                     &media_type);
        offset = mi_dissect_metadata(tvb, pinfo, mi_tree, 1, media_type);
        if (offset < 0) {
            return true;
        }
        if (media_type == MOQ_MI_TYPE_H264) {
            uint64_t length;
            unsigned consumed;

            item = proto_tree_add_item_ret_varint(mi_tree, hf_mi_extradata_length, tvb,
                                                  offset, -1, ENC_VARINT_QUIC, &length,
                                                  &consumed);
            if (consumed == 0 ||
                length > (uint64_t)tvb_reported_length_remaining(tvb, offset + consumed)) {
                expert_add_info(pinfo, item, &ei_mi_truncated);
                return true;
            }
            offset += consumed;
            if (length > 0) {
                mi_dissect_extradata(tvb_new_subset_length(tvb, offset, (int)length),
                                     pinfo, mi_tree);
                offset += (int)length;
            }
        }
    } else {
        uint64_t want;

        media_type = (uint32_t)MIN(media_type_prop->integer, UINT32_MAX);
        item = proto_tree_add_uint(mi_tree, hf_mi_media_type, tvb, 0, 0, media_type);
        proto_item_set_generated(item);
        switch (media_type) {
        case MOQ_MI_TYPE_H264:
            meta = mi_object_property(info, MOQ_MI_PROP_H264_META_03);
            version = 3;
            if (!meta) {
                meta = mi_object_property(info, MOQ_MI_PROP_H264_META_02);
                version = 2;
            }
            want = 0;
            break;
        case MOQ_MI_TYPE_OPUS:
            want = MOQ_MI_PROP_OPUS_META;
            version = 23;
            break;
        case MOQ_MI_TYPE_TEXT:
            want = MOQ_MI_PROP_TEXT_META;
            version = 23;
            break;
        case MOQ_MI_TYPE_AAC_LC:
            want = MOQ_MI_PROP_AAC_META;
            version = 23;
            break;
        default:
            expert_add_info(pinfo, item, &ei_mi_unknown_type);
            proto_tree_add_item(mi_tree, hf_mi_payload, tvb, 0, -1, ENC_NA);
            return true;
        }
        if (want) {
            meta = mi_object_property(info, want);
        }
        proto_item_set_generated(proto_tree_add_uint(mi_tree, hf_mi_version, tvb, 0, 0,
                                                     version));
        if (!meta || !meta->data) {
            proto_tree_add_expert(mi_tree, pinfo, &ei_mi_missing_metadata, tvb, 0, 0);
        } else {
            tvbuff_t *meta_tvb = mi_property_tvb(tvb, pinfo, meta, "moq-mi metadata");

            meta_tree = proto_tree_add_subtree(mi_tree, meta_tvb, 0, -1, ett_mi_metadata,
                                               NULL, "Metadata");
            mi_dissect_metadata(meta_tvb, pinfo, meta_tree, 0, media_type);
        }
        extradata = mi_object_property(info, MOQ_MI_PROP_H264_EXTRADATA);
        if (media_type == MOQ_MI_TYPE_H264 && extradata && extradata->data) {
            mi_dissect_extradata(mi_property_tvb(tvb, pinfo, extradata,
                                                 "AVCDecoderConfigurationRecord"),
                                 pinfo, mi_tree);
        }
    }
    proto_item_append_text(mi_item, ", %s",
                           val_to_str_const(media_type, mi_media_type_vals, "Unknown"));
    mi_dissect_media(tvb_new_subset_remaining(tvb, offset), pinfo, mi_tree, media_type);
    return true;
}

void
proto_register_moq_mi(void)
{
    static hf_register_info hf[] = {
        { &hf_mi_version,
          { "Draft", "moq_mi.version",
            FT_UINT8, BASE_DEC, VALS(mi_version_vals), 0x0,
            "draft-cenzano-moq-media-interop revision the Object follows", HFILL }
        },
        { &hf_mi_media_type,
          { "Media Type", "moq_mi.media_type",
            FT_UINT32, BASE_DEC, VALS(mi_media_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_mi_seq_id,
          { "Seq ID", "moq_mi.seq_id",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mi_pts,
          { "PTS", "moq_mi.pts",
            FT_UINT64, BASE_DEC, NULL, 0x0, "In Timebase units", HFILL }
        },
        { &hf_mi_dts,
          { "DTS", "moq_mi.dts",
            FT_UINT64, BASE_DEC, NULL, 0x0, "In Timebase units", HFILL }
        },
        { &hf_mi_timebase,
          { "Timebase", "moq_mi.timebase",
            FT_UINT64, BASE_DEC, NULL, 0x0, "Units per second", HFILL }
        },
        { &hf_mi_sample_freq,
          { "Sample Frequency", "moq_mi.sample_freq",
            FT_UINT64, BASE_DEC, NULL, 0x0, "Of the original signal, in Hz", HFILL }
        },
        { &hf_mi_channels,
          { "Channels", "moq_mi.channels",
            FT_UINT64, BASE_DEC, NULL, 0x0, "Of the original signal", HFILL }
        },
        { &hf_mi_duration,
          { "Duration", "moq_mi.duration",
            FT_UINT64, BASE_DEC, NULL, 0x0, "In Timebase units; 0 if not set", HFILL }
        },
        { &hf_mi_wallclock,
          { "Wallclock", "moq_mi.wallclock",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Capture time in milliseconds since 1970; 0 if not set", HFILL }
        },
        { &hf_mi_wallclock_time,
          { "Capture Time", "moq_mi.wallclock_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mi_pts_time,
          { "Presentation Time", "moq_mi.pts_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "PTS divided by the Timebase", HFILL }
        },
        { &hf_mi_extradata_length,
          { "Metadata Length", "moq_mi.extradata.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the AVCDecoderConfigurationRecord (draft-01)", HFILL }
        },
        { &hf_mi_extradata,
          { "AVCDecoderConfigurationRecord", "moq_mi.extradata",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mi_text,
          { "Text", "moq_mi.text",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mi_payload,
          { "Payload", "moq_mi.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_mi,
        &ett_mi_metadata,
    };

    static ei_register_info ei[] = {
        { &ei_mi_truncated,
          { "moq_mi.truncated", PI_MALFORMED, PI_ERROR,
            "Truncated moq-mi metadata", EXPFILL }
        },
        { &ei_mi_missing_metadata,
          { "moq_mi.metadata.missing", PI_PROTOCOL, PI_ERROR,
            "No metadata property for this Media Type", EXPFILL }
        },
        { &ei_mi_unknown_type,
          { "moq_mi.media_type.unknown", PI_PROTOCOL, PI_WARN,
            "Unknown Media Type", EXPFILL }
        },
    };

    expert_module_t *expert_mi;

    proto_moq_mi = proto_register_protocol("MoQ Media Interop", "moq-mi", "moq_mi");
    proto_register_field_array(proto_moq_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mi = expert_register_protocol(proto_moq_mi);
    expert_register_field_array(expert_mi, ei, array_length(ei));
}

void
proto_reg_handoff_moq_mi(void)
{
    /*
     * Registered after LOC's, so it runs first and claims "video0"-style
     * tracks before LOC's heuristic sees their VIDEO_CONFIG (0x0d).
     */
    heur_dissector_add("moqt.payload", dissect_moq_mi_heur, "MoQ Media Interop",
                       "moq_mi_moqt", proto_moq_mi, HEURISTIC_ENABLE);
    loc_codec_table = find_dissector_table("moq_loc.codec");
    h264_handle = find_dissector_add_dependency("h264", proto_moq_mi);
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
