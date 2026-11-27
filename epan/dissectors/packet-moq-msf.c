/* packet-moq-msf.c
 * Routines for MOQT Streaming Format (MSF) and CMSF dissection
 * draft-ietf-moq-msf-02 (-01 and -00 catalogs are read too)
 * draft-ietf-moq-cmsf-01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * An MSF broadcast is a MOQT namespace with a JSON catalog on the track named
 * "catalog". The catalog lists the broadcast's tracks with their packaging
 * ("loc", "cmaf", "mpeg2ts", "mediatimeline", "eventtimeline", ...), role and
 * codec; later catalog Objects either replace it or, as delta updates, add,
 * remove, clone or update tracks:
 *  - draft-00: "deltaUpdate": true with root addTracks / removeTracks /
 *    cloneTracks arrays;
 *  - draft-01 and -02: "deltaUpdate": [{"op": ..., "tracks": [...]}], applied
 *    in order; draft-02 adds the "update" operation.
 * CMSF adds the "cmaf" packaging (moof+mdat Objects) and a SAP-type event
 * timeline; LOCMAF and NMSF add their own packagings.
 *
 * Catalogs are learned on the first pass, per MOQT session and namespace,
 * and remembered with the frame that introduced each track definition. An
 * Object of a cataloged track is then routed by its packaging through the
 * "moq_msf.packaging" table. Catalog, timeline, log and metrics Objects may
 * be GZIP-compressed, as the MSF_COMPRESSION Track or Object property (0x78
 * in libloc, which follows the draft's provisional value) says.
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <wsutil/str_util.h>
#include <wsutil/wsjson.h>

#include "packet-moq-loc.h"
#include "packet-moq-msf.h"
#include "packet-moqt.h"

void proto_register_moq_msf(void);
void proto_reg_handoff_moq_msf(void);

#define MSF_CATALOG_TRACK        "catalog"
#define MSF_PROP_COMPRESSION     0x78
#define MSF_COMPRESSION_NONE     0
#define MSF_COMPRESSION_GZIP     1
#define MSF_MAX_JSON_TOKENS      8192
#define MPEG_TS_PACKET_SIZE      188

static int proto_moq_msf;

static int hf_msf_version;
static int hf_msf_generated_at;
static int hf_msf_is_complete;
static int hf_msf_delta;
static int hf_msf_delta_op;
static int hf_msf_track_count;
static int hf_msf_track;
static int hf_msf_track_namespace;
static int hf_msf_track_packaging;
static int hf_msf_track_role;
static int hf_msf_track_codec;
static int hf_msf_track_event_type;
static int hf_msf_track_mime_type;
static int hf_msf_track_parent;
static int hf_msf_compression;
static int hf_msf_catalog_frame;
static int hf_msf_timeline_records;
static int hf_msf_payload;
static int hf_msf_text;

static int ett_msf;
static int ett_msf_track;
static int ett_msf_delta;

static expert_field ei_msf_bad_json;
static expert_field ei_msf_decompress;
static expert_field ei_msf_unknown_compression;
static expert_field ei_msf_unknown_packaging;
static expert_field ei_msf_ts_length;

static dissector_table_t msf_packaging_table;
static dissector_handle_t msf_catalog_handle;
static dissector_handle_t json_handle;
static dissector_handle_t mp4_handle;
static dissector_handle_t mp2t_handle;
static dissector_handle_t loc_object_handle;

static const val64_string msf_compression_vals[] = {
    { MSF_COMPRESSION_NONE, "None" },
    { MSF_COMPRESSION_GZIP, "GZIP" },
    { 0, NULL }
};

/* ------------------------------------------------------------------------- */
/* Catalog state                                                             */
/* ------------------------------------------------------------------------- */

/*
 * One definition of a track, valid from "frame" on. A removal is a
 * definition with removed set. Older definitions stay reachable through
 * "older" so redissection sees the catalog as it was at each frame.
 */
typedef struct msf_track_def msf_track_def_t;
struct msf_track_def {
    uint32_t frame;
    bool removed;
    const char *packaging;
    const char *role;
    const char *codec;
    const char *event_type;
    const char *mime_type;
    msf_track_def_t *older;
};

/* Track definitions keyed by "namespace\nname", per MOQT session. */
typedef struct {
    wmem_map_t *tracks;
} msf_session_t;

static msf_session_t *
msf_session_get(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    msf_session_t *session =
        (msf_session_t *)conversation_get_proto_data(conversation, proto_moq_msf);

    if (!session) {
        session = wmem_new0(wmem_file_scope(), msf_session_t);
        session->tracks = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
        conversation_add_proto_data(conversation, proto_moq_msf, session);
    }
    return session;
}

static char *
msf_track_key(wmem_allocator_t *scope, const char *track_namespace, const char *name)
{
    return wmem_strdup_printf(scope, "%s\n%s", track_namespace ? track_namespace : "", name);
}

static const msf_track_def_t *
msf_track_lookup(packet_info *pinfo, const char *track_namespace, const char *name)
{
    const msf_track_def_t *def = (const msf_track_def_t *)wmem_map_lookup(
        msf_session_get(pinfo)->tracks, msf_track_key(pinfo->pool, track_namespace, name));

    for (; def; def = def->older) {
        if (def->frame <= pinfo->num) {
            return def->removed ? NULL : def;
        }
    }
    return NULL;
}

static void
msf_track_define(packet_info *pinfo, const char *track_namespace, const char *name,
                 const msf_track_def_t *fields)
{
    msf_session_t *session = msf_session_get(pinfo);
    char *key = msf_track_key(wmem_file_scope(), track_namespace, name);
    msf_track_def_t *def = wmem_new(wmem_file_scope(), msf_track_def_t);

    *def = *fields;
    def->frame = pinfo->num;
    def->older = (msf_track_def_t *)wmem_map_lookup(session->tracks, key);
    wmem_map_insert(session->tracks, key, def);
}

/* ------------------------------------------------------------------------- */
/* JSON helpers                                                              */
/* ------------------------------------------------------------------------- */

static jsmntok_t *
msf_json_member(const char *buf, jsmntok_t *object, const char *name)
{
    jsmntok_t *key;
    size_t length = strlen(name);

    if (!object || object->type != JSMN_OBJECT) {
        return NULL;
    }
    /*
     * jsmn is not strict: a key without a value has no child, so step over
     * each member with its own children rather than assuming key/value pairs.
     */
    key = object + 1;
    for (int i = 0; i < object->size; i++) {
        if (key->type == JSMN_STRING && key->size == 1 &&
            (size_t)(key->end - key->start) == length &&
            strncmp(buf + key->start, name, length) == 0) {
            return key + 1;
        }
        key = json_get_next_object(key);
    }
    return NULL;
}

/* A string member, decoded, in file scope; NULL when absent or not a string. */
static const char *
msf_json_string(const char *buf, jsmntok_t *object, const char *name)
{
    jsmntok_t *value = msf_json_member(buf, object, name);
    char *text;

    if (!value || value->type != JSMN_STRING) {
        return NULL;
    }
    text = wmem_strndup(wmem_file_scope(), buf + value->start,
                        (size_t)(value->end - value->start));
    if (!json_decode_string_inplace(text)) {
        return NULL;
    }
    return text;
}

/* Any scalar member as its JSON text (a number, a string's contents, ...). */
static const char *
msf_json_text(wmem_allocator_t *scope, const char *buf, jsmntok_t *object,
              const char *name)
{
    jsmntok_t *value = msf_json_member(buf, object, name);

    if (!value || value->type == JSMN_OBJECT || value->type == JSMN_ARRAY) {
        return NULL;
    }
    return wmem_strndup(scope, buf + value->start, (size_t)(value->end - value->start));
}

/* ------------------------------------------------------------------------- */
/* Compression                                                               */
/* ------------------------------------------------------------------------- */

/*
 * MSF_COMPRESSION applies from the Object property or the Track property
 * (a publisher must not use both). Returns the tvb to dissect, NULL when it
 * cannot be decompressed.
 */
static tvbuff_t *
msf_decompress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               const moqt_object_info_t *object)
{
    const moqt_property_t *property =
        object ? moqt_object_find_property(object, MSF_PROP_COMPRESSION) : NULL;
    proto_item *item;
    tvbuff_t *plain;

    if (!property || property->integer == MSF_COMPRESSION_NONE) {
        return tvb;
    }
    item = proto_tree_add_uint64(tree, hf_msf_compression, tvb, 0, 0, property->integer);
    proto_item_set_generated(item);
    if (property->integer != MSF_COMPRESSION_GZIP) {
        expert_add_info(pinfo, item, &ei_msf_unknown_compression);
        return NULL;
    }
    plain = tvb_child_uncompress_zlib(tvb, tvb, 0, tvb_reported_length(tvb));
    if (!plain) {
        expert_add_info(pinfo, item, &ei_msf_decompress);
        return NULL;
    }
    add_new_data_source(pinfo, plain, "Decompressed MSF Object");
    return plain;
}

/* ------------------------------------------------------------------------- */
/* Catalog                                                                   */
/* ------------------------------------------------------------------------- */

typedef struct {
    packet_info *pinfo;
    proto_tree *tree;
    tvbuff_t *tvb;
    const char *buf;
    const char *catalog_namespace;
    bool learn;          /* first pass: update the catalog state */
} msf_catalog_ctx_t;

static void
msf_read_track(msf_catalog_ctx_t *ctx, jsmntok_t *track, msf_track_def_t *def)
{
    const char *value;

#define MSF_READ(field, key) \
    if ((value = msf_json_string(ctx->buf, track, key)) != NULL) { def->field = value; }
    MSF_READ(packaging, "packaging");
    MSF_READ(role, "role");
    MSF_READ(codec, "codec");
    MSF_READ(event_type, "eventType");
    MSF_READ(mime_type, "mimeType");
#undef MSF_READ
}

static const char *
msf_track_namespace(msf_catalog_ctx_t *ctx, jsmntok_t *track)
{
    const char *track_namespace = msf_json_string(ctx->buf, track, "namespace");

    return track_namespace ? track_namespace : ctx->catalog_namespace;
}

/*
 * One entry of a tracks array. op is "add" for a full catalog. "clone" and
 * "update" start from the existing definition (of parentName, or of the
 * track itself) and override the fields the entry carries.
 */
static void
msf_catalog_track(msf_catalog_ctx_t *ctx, proto_tree *tree, jsmntok_t *track,
                  const char *op)
{
    const char *name = msf_json_string(ctx->buf, track, "name");
    const char *track_namespace, *parent;
    msf_track_def_t def = { 0 };
    proto_item *item;
    proto_tree *track_tree;

    if (!name || track->type != JSMN_OBJECT) {
        return;
    }
    track_namespace = msf_track_namespace(ctx, track);
    parent = msf_json_string(ctx->buf, track, "parentName");
    if (strcmp(op, "clone") == 0 || strcmp(op, "update") == 0) {
        const char *base_namespace = track_namespace;
        const msf_track_def_t *base;

        if (parent) {
            const char *parent_namespace =
                msf_json_string(ctx->buf, track, "parentNamespace");

            base_namespace = parent_namespace ? parent_namespace : ctx->catalog_namespace;
        }
        base = msf_track_lookup(ctx->pinfo, base_namespace, parent ? parent : name);
        if (base) {
            def = *base;
            def.older = NULL;
        }
    }
    if (strcmp(op, "remove") != 0) {
        msf_read_track(ctx, track, &def);
    } else {
        def.removed = true;
    }

    item = proto_tree_add_string(tree, hf_msf_track, ctx->tvb, 0, 0, name);
    proto_item_set_generated(item);
    proto_item_append_text(item, " (%s%s%s)", op,
                           def.packaging ? ", " : "", def.packaging ? def.packaging : "");
    track_tree = proto_item_add_subtree(item, ett_msf_track);
#define MSF_SHOW(hf, value) \
    if (value) { proto_item_set_generated( \
        proto_tree_add_string(track_tree, hf, ctx->tvb, 0, 0, value)); }
    MSF_SHOW(hf_msf_track_namespace, track_namespace);
    MSF_SHOW(hf_msf_track_parent, parent);
    if (!def.removed) {
        MSF_SHOW(hf_msf_track_packaging, def.packaging);
        MSF_SHOW(hf_msf_track_role, def.role);
        MSF_SHOW(hf_msf_track_codec, def.codec);
        MSF_SHOW(hf_msf_track_event_type, def.event_type);
        MSF_SHOW(hf_msf_track_mime_type, def.mime_type);
    }
#undef MSF_SHOW

    if (ctx->learn) {
        msf_track_define(ctx->pinfo, track_namespace, name, &def);
    }
}

static unsigned
msf_catalog_tracks(msf_catalog_ctx_t *ctx, proto_tree *tree, jsmntok_t *array,
                   const char *op)
{
    int count;

    if (!array || array->type != JSMN_ARRAY) {
        return 0;
    }
    count = json_get_array_len(array);
    for (int i = 0; i < count; i++) {
        msf_catalog_track(ctx, tree, json_get_array_index(array, i), op);
    }
    return (unsigned)count;
}

/* A full catalog replaces the previous one: its tracks not listed are gone. */
static void
msf_catalog_replace(msf_catalog_ctx_t *ctx, jsmntok_t *tracks)
{
    msf_session_t *session = msf_session_get(ctx->pinfo);
    wmem_list_t *keys = wmem_map_get_keys(ctx->pinfo->pool, session->tracks);
    wmem_map_t *listed = wmem_map_new(ctx->pinfo->pool, wmem_str_hash, g_str_equal);
    int count = tracks && tracks->type == JSMN_ARRAY ? json_get_array_len(tracks) : 0;

    for (int i = 0; i < count; i++) {
        jsmntok_t *track = json_get_array_index(tracks, i);
        const char *name = msf_json_string(ctx->buf, track, "name");

        if (name) {
            wmem_map_insert(listed, msf_track_key(ctx->pinfo->pool,
                                                  msf_track_namespace(ctx, track), name),
                            GINT_TO_POINTER(1));
        }
    }
    for (wmem_list_frame_t *frame = wmem_list_head(keys); frame;
         frame = wmem_list_frame_next(frame)) {
        const char *key = (const char *)wmem_list_frame_data(frame);
        msf_track_def_t *def = (msf_track_def_t *)wmem_map_lookup(session->tracks, key);
        const char *newline = strchr(key, '\n');

        /* Only tracks described by a catalog of this namespace are replaced. */
        if (!def || def->removed || !newline || wmem_map_contains(listed, key) ||
            (size_t)(newline - key) != strlen(ctx->catalog_namespace) ||
            strncmp(key, ctx->catalog_namespace, (size_t)(newline - key)) != 0) {
            continue;
        }
        msf_track_def_t removed = { .removed = true };
        msf_track_define(ctx->pinfo, ctx->catalog_namespace, newline + 1, &removed);
    }
}

static void
msf_dissect_catalog_json(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         proto_item *msf_item, const char *catalog_namespace)
{
    int length = tvb_reported_length(tvb);
    msf_catalog_ctx_t ctx = {
        .pinfo = pinfo,
        .tvb = tvb,
        .catalog_namespace = catalog_namespace ? catalog_namespace : "",
        .learn = !PINFO_FD_VISITED(pinfo),
    };
    jsmntok_t *tokens, *delta;
    const char *version, *text;
    proto_item *item;
    char *buf;
    int ntok;
    bool is_delta = false, value;
    unsigned tracks = 0;

    /* jsmn accepts malformed objects that its token walkers then overrun. */
    if (length <= 0 || !json_validate(tvb_get_ptr(tvb, 0, length), (size_t)length)) {
        proto_tree_add_expert(tree, pinfo, &ei_msf_bad_json, tvb, 0, length);
        return;
    }
    buf = (char *)tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_UTF_8);
    ntok = json_parse(buf, NULL, 0);
    if (ntok <= 0 || ntok > MSF_MAX_JSON_TOKENS) {
        proto_tree_add_expert(tree, pinfo, &ei_msf_bad_json, tvb, 0, length);
        return;
    }
    tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, ntok);
    if (json_parse(buf, tokens, ntok) <= 0 || tokens[0].type != JSMN_OBJECT) {
        proto_tree_add_expert(tree, pinfo, &ei_msf_bad_json, tvb, 0, length);
        return;
    }
    ctx.buf = buf;
    ctx.tree = tree;

    version = msf_json_text(pinfo->pool, buf, tokens, "version");
    if (version) {
        item = proto_tree_add_string(tree, hf_msf_version, tvb, 0, 0, version);
        proto_item_set_generated(item);
    }
    text = msf_json_text(pinfo->pool, buf, tokens, "generatedAt");
    if (text) {
        item = proto_tree_add_uint64(tree, hf_msf_generated_at, tvb, 0, 0,
                                     g_ascii_strtoull(text, NULL, 10));
        proto_item_set_generated(item);
    }
    if (json_get_boolean(buf, tokens, "isComplete", &value)) {
        item = proto_tree_add_boolean(tree, hf_msf_is_complete, tvb, 0, 0, value);
        proto_item_set_generated(item);
    }

    delta = msf_json_member(buf, tokens, "deltaUpdate");
    if (delta && delta->type == JSMN_ARRAY) {
        /* draft-01 and -02: operations in order. */
        int count = json_get_array_len(delta);

        is_delta = true;
        for (int i = 0; i < count; i++) {
            jsmntok_t *operation = json_get_array_index(delta, i);
            const char *op = msf_json_string(buf, operation, "op");
            proto_tree *op_tree;

            if (!op) {
                continue;
            }
            item = proto_tree_add_string(tree, hf_msf_delta_op, tvb, 0, 0, op);
            proto_item_set_generated(item);
            op_tree = proto_item_add_subtree(item, ett_msf_delta);
            tracks += msf_catalog_tracks(&ctx, op_tree,
                                         msf_json_member(buf, operation, "tracks"), op);
        }
    } else if (json_get_boolean(buf, tokens, "deltaUpdate", &value) && value) {
        /* draft-00: unordered root arrays. */
        static const struct { const char *key; const char *op; } ops[] = {
            { "addTracks", "add" }, { "cloneTracks", "clone" }, { "removeTracks", "remove" },
        };

        is_delta = true;
        for (unsigned i = 0; i < array_length(ops); i++) {
            jsmntok_t *array = msf_json_member(buf, tokens, ops[i].key);
            proto_tree *op_tree;

            if (!array) {
                continue;
            }
            item = proto_tree_add_string(tree, hf_msf_delta_op, tvb, 0, 0, ops[i].op);
            proto_item_set_generated(item);
            op_tree = proto_item_add_subtree(item, ett_msf_delta);
            tracks += msf_catalog_tracks(&ctx, op_tree, array, ops[i].op);
        }
    } else {
        jsmntok_t *array = msf_json_member(buf, tokens, "tracks");

        if (ctx.learn) {
            msf_catalog_replace(&ctx, array);
        }
        tracks = msf_catalog_tracks(&ctx, tree, array, "add");
    }
    item = proto_tree_add_boolean(tree, hf_msf_delta, tvb, 0, 0, is_delta);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(tree, hf_msf_track_count, tvb, 0, 0, tracks);
    proto_item_set_generated(item);
    proto_item_append_text(msf_item, ", %s, %u track%s", is_delta ? "Delta Catalog" : "Catalog",
                           tracks, plurality(tracks, "", "s"));
    col_append_str(pinfo->cinfo, COL_INFO, is_delta ? " [MSF delta catalog]" : " [MSF catalog]");
}

/* The "catalog" track, or a track with "catalog" packaging. */
static int
dissect_msf_catalog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moqt_object_info_t *object = (const moqt_object_info_t *)data;
    proto_item *msf_item;
    proto_tree *msf_tree;
    tvbuff_t *plain;

    msf_item = proto_tree_add_item(tree, proto_moq_msf, tvb, 0, -1, ENC_NA);
    msf_tree = proto_item_add_subtree(msf_item, ett_msf);
    plain = msf_decompress(tvb, pinfo, msf_tree, object);
    if (!plain) {
        return tvb_captured_length(tvb);
    }
    msf_dissect_catalog_json(plain, pinfo, msf_tree, msf_item,
                             object ? object->track_namespace : NULL);
    if (json_handle) {
        call_dissector(json_handle, plain, pinfo, msf_tree);
    }
    return tvb_captured_length(tvb);
}

/* ------------------------------------------------------------------------- */
/* Packagings                                                                */
/* ------------------------------------------------------------------------- */

static int
dissect_msf_loc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const msf_track_info_t *info = (const msf_track_info_t *)data;
    moq_loc_object_info_t loc = { info->object, info->codec };

    return call_dissector_with_data(loc_object_handle, tvb, pinfo, tree, &loc);
}

/* CMSF: each Object is a CMAF chunk (moof+mdat, optionally with styp). */
static int
dissect_msf_cmaf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* The MP4 dissector clears the Info column; keep what MOQT wrote. */
    col_set_fence(pinfo->cinfo, COL_INFO);
    return call_dissector(mp4_handle, tvb, pinfo, tree);
}

/*
 * MPEG-2 TS: whole 188-byte packets; draft-gregoire-moq-msfts-00's "m2ts"
 * packaging uses 192-byte source packets with a 4-byte TP_extra_header.
 */
static int
msf_dissect_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int packet_size)
{
    int length = tvb_reported_length(tvb);
    int header = packet_size - MPEG_TS_PACKET_SIZE;

    if (length % packet_size != 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_msf_ts_length, tvb, 0, length,
                                     "Payload of %d bytes is not a whole number "
                                     "of %d-byte packets", length, packet_size);
    }
    for (int offset = 0; offset + packet_size <= length; offset += packet_size) {
        call_dissector(mp2t_handle,
                       tvb_new_subset_length(tvb, offset + header, MPEG_TS_PACKET_SIZE),
                       pinfo, tree);
    }
    return length;
}

static int
dissect_msf_mpeg2ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return msf_dissect_ts(tvb, pinfo, tree, MPEG_TS_PACKET_SIZE);
}

static int
dissect_msf_m2ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return msf_dissect_ts(tvb, pinfo, tree, MPEG_TS_PACKET_SIZE + 4);
}

/*
 * Media and event timelines, logs and metrics are JSON, possibly compressed.
 * A media timeline is an array of [mediaTime, [group, object], wallclock].
 */
static int
dissect_msf_json_track(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const msf_track_info_t *info = (const msf_track_info_t *)data;
    int length = tvb_reported_length(tvb);
    tvbuff_t *plain = msf_decompress(tvb, pinfo, tree, info->object);

    if (!plain) {
        return length;
    }
    length = tvb_reported_length(plain);
    if (!json_validate(tvb_get_ptr(plain, 0, length), (size_t)length)) {
        proto_tree_add_item(tree, hf_msf_text, plain, 0, length, ENC_UTF_8);
        return tvb_reported_length(tvb);
    }
    if (info->packaging && strcmp(info->packaging, "mediatimeline") == 0) {
        char *buf = (char *)tvb_get_string_enc(pinfo->pool, plain, 0, length, ENC_UTF_8);
        int ntok = json_parse(buf, NULL, 0);

        if (ntok > 0 && ntok <= MSF_MAX_JSON_TOKENS) {
            jsmntok_t *tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, ntok);

            if (json_parse(buf, tokens, ntok) > 0 && tokens[0].type == JSMN_ARRAY) {
                proto_item *item = proto_tree_add_uint(tree, hf_msf_timeline_records,
                                                       plain, 0, 0,
                                                       (uint32_t)tokens[0].size);
                proto_item_set_generated(item);
            }
        }
    }
    call_dissector(json_handle, plain, pinfo, tree);
    return tvb_reported_length(tvb);
}

/*
 * "moqt.payload": an Object of a track some catalog of this session
 * described. The catalog track itself is in "moqt.track_name".
 */
static bool
dissect_msf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moqt_object_info_t *object = (const moqt_object_info_t *)data;
    const msf_track_def_t *def;
    msf_track_info_t info;
    proto_item *msf_item, *item;
    proto_tree *msf_tree;

    if (!object || !object->track_name) {
        return false;
    }
    def = msf_track_lookup(pinfo, object->track_namespace, object->track_name);
    if (!def) {
        return false;
    }
    info = (msf_track_info_t){
        .object = object,
        .packaging = def->packaging,
        .role = def->role,
        .codec = def->codec,
        .event_type = def->event_type,
        .mime_type = def->mime_type,
        .catalog_frame = def->frame,
    };

    msf_item = proto_tree_add_item(tree, proto_moq_msf, tvb, 0, -1, ENC_NA);
    msf_tree = proto_item_add_subtree(msf_item, ett_msf);
    item = proto_tree_add_uint(msf_tree, hf_msf_catalog_frame, tvb, 0, 0, def->frame);
    proto_item_set_generated(item);
#define MSF_SHOW(hf, value) \
    if (value) { proto_item_set_generated( \
        proto_tree_add_string(msf_tree, hf, tvb, 0, 0, value)); }
    MSF_SHOW(hf_msf_track_packaging, def->packaging);
    MSF_SHOW(hf_msf_track_role, def->role);
    MSF_SHOW(hf_msf_track_codec, def->codec);
    MSF_SHOW(hf_msf_track_event_type, def->event_type);
#undef MSF_SHOW
    proto_item_append_text(msf_item, ", %s", def->packaging ? def->packaging : "no packaging");

    if (!def->packaging ||
        !dissector_try_string_with_data(msf_packaging_table, def->packaging, tvb, pinfo,
                                        msf_tree, true, &info)) {
        if (def->packaging) {
            proto_tree_add_expert_format(msf_tree, pinfo, &ei_msf_unknown_packaging, tvb,
                                         0, 0, "No dissector for packaging \"%s\"",
                                         def->packaging);
        }
        proto_tree_add_item(msf_tree, hf_msf_payload, tvb, 0, -1, ENC_NA);
    }
    return true;
}

static int
dissect_msf_subcatalog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const msf_track_info_t *info = (const msf_track_info_t *)data;

    return dissect_msf_catalog(tvb, pinfo, tree, (void *)info->object);
}

void
proto_register_moq_msf(void)
{
    static hf_register_info hf[] = {
        { &hf_msf_version,
          { "Catalog Version", "moq_msf.version",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "1 in draft-00, \"draft-01\" or \"draft-02\" later", HFILL }
        },
        { &hf_msf_generated_at,
          { "Generated At", "moq_msf.generated_at",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Wallclock time in milliseconds since 1970", HFILL }
        },
        { &hf_msf_is_complete,
          { "Is Complete", "moq_msf.is_complete",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, "The broadcast has ended", HFILL }
        },
        { &hf_msf_delta,
          { "Delta Update", "moq_msf.delta",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_delta_op,
          { "Delta Operation", "moq_msf.delta.op",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_count,
          { "Tracks", "moq_msf.track_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, "Track entries in this catalog Object", HFILL }
        },
        { &hf_msf_track,
          { "Track", "moq_msf.track",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_namespace,
          { "Namespace", "moq_msf.track.namespace",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_packaging,
          { "Packaging", "moq_msf.packaging",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_role,
          { "Role", "moq_msf.role",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_codec,
          { "Codec", "moq_msf.codec",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_event_type,
          { "Event Type", "moq_msf.event_type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_mime_type,
          { "MIME Type", "moq_msf.mime_type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_track_parent,
          { "Parent Track", "moq_msf.track.parent",
            FT_STRING, BASE_NONE, NULL, 0x0, "parentName of a cloned track", HFILL }
        },
        { &hf_msf_compression,
          { "Compression", "moq_msf.compression",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(msf_compression_vals), 0x0,
            "MSF_COMPRESSION property", HFILL }
        },
        { &hf_msf_catalog_frame,
          { "Catalog Frame", "moq_msf.catalog_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Frame of the catalog that described this track", HFILL }
        },
        { &hf_msf_timeline_records,
          { "Timeline Records", "moq_msf.timeline.records",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_payload,
          { "Payload", "moq_msf.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_msf_text,
          { "Text", "moq_msf.text",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_msf,
        &ett_msf_track,
        &ett_msf_delta,
    };

    static ei_register_info ei[] = {
        { &ei_msf_bad_json,
          { "moq_msf.json.bad", PI_MALFORMED, PI_ERROR,
            "Catalog is not a JSON object", EXPFILL }
        },
        { &ei_msf_decompress,
          { "moq_msf.compression.failed", PI_MALFORMED, PI_ERROR,
            "Object could not be decompressed", EXPFILL }
        },
        { &ei_msf_unknown_compression,
          { "moq_msf.compression.unknown", PI_UNDECODED, PI_WARN,
            "Unknown compression algorithm", EXPFILL }
        },
        { &ei_msf_unknown_packaging,
          { "moq_msf.packaging.unknown", PI_UNDECODED, PI_NOTE,
            "No dissector for this packaging", EXPFILL }
        },
        { &ei_msf_ts_length,
          { "moq_msf.mpeg2ts.length", PI_MALFORMED, PI_WARN,
            "MPEG-2 TS payload is not a whole number of packets", EXPFILL }
        },
    };

    expert_module_t *expert_msf;

    proto_moq_msf = proto_register_protocol("MOQT Streaming Format", "MSF", "moq_msf");
    proto_register_field_array(proto_moq_msf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_msf = expert_register_protocol(proto_moq_msf);
    expert_register_field_array(expert_msf, ei, array_length(ei));

    msf_packaging_table = register_dissector_table(
        "moq_msf.packaging", "MSF track packaging", proto_moq_msf, FT_STRING,
        STRING_CASE_SENSITIVE);
    msf_catalog_handle = register_dissector("moq_msf.catalog", dissect_msf_catalog,
                                            proto_moq_msf);
}

void
proto_reg_handoff_moq_msf(void)
{
    dissector_handle_t json_track_handle =
        create_dissector_handle(dissect_msf_json_track, proto_moq_msf);

    json_handle = find_dissector_add_dependency("json", proto_moq_msf);
    mp4_handle = find_dissector_add_dependency("mp4", proto_moq_msf);
    mp2t_handle = find_dissector_add_dependency("mp2t", proto_moq_msf);
    loc_object_handle = find_dissector_add_dependency("moq_loc.object", proto_moq_msf);

    dissector_add_string("moqt.track_name", MSF_CATALOG_TRACK, msf_catalog_handle);
    /*
     * Registered after LOC's (handoffs run in name order, and heuristics run
     * last registered first), so a cataloged LOC track gets its codec from
     * the catalog rather than through LOC's own heuristic.
     */
    heur_dissector_add("moqt.payload", dissect_msf_heur, "MSF cataloged tracks",
                       "msf_moqt", proto_moq_msf, HEURISTIC_ENABLE);

    dissector_add_string("moq_msf.packaging", "loc",
                         create_dissector_handle(dissect_msf_loc, proto_moq_msf));
    dissector_add_string("moq_msf.packaging", "cmaf",
                         create_dissector_handle(dissect_msf_cmaf, proto_moq_msf));
    dissector_add_string("moq_msf.packaging", "mpeg2ts",
                         create_dissector_handle(dissect_msf_mpeg2ts, proto_moq_msf));
    dissector_add_string("moq_msf.packaging", "m2ts",
                         create_dissector_handle(dissect_msf_m2ts, proto_moq_msf));
    dissector_add_string("moq_msf.packaging", "catalog",
                         create_dissector_handle(dissect_msf_subcatalog, proto_moq_msf));
    dissector_add_string("moq_msf.packaging", "mediatimeline", json_track_handle);
    dissector_add_string("moq_msf.packaging", "eventtimeline", json_track_handle);
    dissector_add_string("moq_msf.packaging", "timeline", json_track_handle);
    dissector_add_string("moq_msf.packaging", "moqlog", json_track_handle);
    dissector_add_string("moq_msf.packaging", "moqmetrics", json_track_handle);
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
