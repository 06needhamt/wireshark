/* packet-moq-auth.c
 * Routines for MOQT authorization tokens
 * Common Access Token for MOQT (draft-ietf-moq-c4m-02, also -01 and -00)
 * Privacy Pass authentication for MOQT (draft-ietf-moq-privacy-pass-auth-03)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MOQT's AUTHORIZATION_TOKEN carries a Token Type and a Token Value; the
 * MOQT dissector hands the value to the "moqt.auth_token_type" table:
 *
 *  - 0x01, CAT: a CWT, i.e. a COSE_Sign1, COSE_Mac0 or COSE_Encrypt0
 *    (optionally tagged as a CWT) whose payload is a CBOR claims set. The
 *    COSE structure goes to the COSE dissector and the claims are decoded
 *    here, including the "moqt" scope claim (327 in c4m-00/-01, -65537 in
 *    c4m-02) with its actions and namespace and track matches.
 *  - 0x50505400, PRIVACY_PASS_TOKEN (libloc's provisional value for the
 *    draft's TBD codepoint): an RFC 9577 Token, i.e. token_type, nonce,
 *    challenge_digest, token_key_id and the authenticator.
 *  - 0x00, agreed out of band. libloc prefixes its own forms with a tag
 *    byte (1 test token, 2 CWT, 3 unprotected claims set), which is
 *    recognised when the "libloc_token_forms" preference is set.
 *
 * Signatures and MACs are not verified.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_moq_auth(void);
void proto_reg_handoff_moq_auth(void);

#define MOQT_TOKEN_TYPE_NEGOTIATED   0x00
#define MOQT_TOKEN_TYPE_CAT          0x01
#define MOQT_TOKEN_TYPE_PRIVACY_PASS 0x50505400

#define CWT_TAG          61
#define COSE_TAG_ENCRYPT0 16
#define COSE_TAG_MAC0    17
#define COSE_TAG_SIGN1   18

#define CLAIM_ISS        1
#define CLAIM_SUB        2
#define CLAIM_AUD        3
#define CLAIM_EXP        4
#define CLAIM_NBF        5
#define CLAIM_IAT        6
#define CLAIM_CTI        7
#define CLAIM_CNF        8
#define CLAIM_CATREPLAY  308
#define CLAIM_CATDPOP    321
#define CLAIM_MOQT_01    327
#define CLAIM_MOQT_REVAL_01 328
#define CLAIM_MOQT_02    (-65537)
#define CLAIM_MOQT_REVAL_02 (-65538)

#define AUTH_MAX_DEPTH   8

static int proto_moq_auth;

static int hf_auth_libloc_form;
static int hf_auth_cose_tag;
static int hf_auth_claim;
static int hf_auth_iss;
static int hf_auth_sub;
static int hf_auth_aud;
static int hf_auth_exp;
static int hf_auth_nbf;
static int hf_auth_iat;
static int hf_auth_cti;
static int hf_auth_cnf;
static int hf_auth_catreplay;
static int hf_auth_moqt_revision;
static int hf_auth_action;
static int hf_auth_ns_match;
static int hf_auth_track_match;
static int hf_auth_reval;
static int hf_auth_value;
static int hf_auth_pp_token_type;
static int hf_auth_pp_nonce;
static int hf_auth_pp_challenge_digest;
static int hf_auth_pp_token_key_id;
static int hf_auth_pp_authenticator;
static int hf_auth_opaque;

static int ett_auth;
static int ett_auth_claims;
static int ett_auth_claim;
static int ett_auth_scope;

static expert_field ei_auth_malformed;
static expert_field ei_auth_encrypted;
static expert_field ei_auth_not_cwt;
static expert_field ei_auth_pp_length;

static dissector_handle_t cose_handle;

static bool pref_libloc_forms = true;

static const value_string auth_libloc_form_vals[] = {
    { 0x01, "libloc test token" },
    { 0x02, "CWT" },
    { 0x03, "Unprotected claims set" },
    { 0, NULL }
};

static const value_string auth_cose_tag_vals[] = {
    { COSE_TAG_ENCRYPT0, "COSE_Encrypt0" },
    { COSE_TAG_MAC0,     "COSE_Mac0" },
    { COSE_TAG_SIGN1,    "COSE_Sign1" },
    { 0, NULL }
};

/* c4m-02 Table 1; c4m-00/-01 number CLIENT_SETUP 0 and SERVER_SETUP 1. */
static const value_string auth_action_vals[] = {
    { 0, "CLIENT_SETUP (c4m-00/-01)" },
    { 1, "SETUP" },
    { 2, "PUBLISH_NAMESPACE" },
    { 3, "SUBSCRIBE_NAMESPACE" },
    { 4, "SUBSCRIBE" },
    { 5, "REQUEST_UPDATE" },
    { 6, "PUBLISH" },
    { 7, "FETCH" },
    { 8, "TRACK_STATUS" },
    { 9, "SUBSCRIBE_TRACKS" },
    { 0, NULL }
};

static const value_string auth_pp_token_type_vals[] = {
    { 0x0001, "VOPRF(P-384, SHA-384)" },
    { 0x0002, "Blind RSA (2048-bit)" },
    { 0x0005, "VOPRF(ristretto255, SHA-512)" },
    { 0xE5AC, "ARC(P-256)" },
    { 0, NULL }
};

/* ------------------------------------------------------------------------- */
/* A minimal, bounds-checked CBOR reader                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    int start;
    int head_length;
    uint8_t major;
    uint64_t value;       /* integer, length or count */
} auth_cbor_t;

static bool
auth_cbor_head(tvbuff_t *tvb, int offset, int end, auth_cbor_t *item)
{
    uint8_t first, info;
    int extra;

    if (offset >= end) {
        return false;
    }
    first = tvb_get_uint8(tvb, offset);
    item->start = offset;
    item->major = first >> 5;
    info = first & 0x1f;
    if (info < 24) {
        item->value = info;
        item->head_length = 1;
        return true;
    }
    if (info > 27) {
        return false;   /* indefinite lengths and reserved values */
    }
    extra = 1 << (info - 24);
    if (end - offset - 1 < extra) {
        return false;
    }
    item->value = tvb_get_uint64_with_length(tvb, offset + 1, extra, ENC_BIG_ENDIAN);
    item->head_length = 1 + extra;
    return true;
}

/* Skip one item; returns the offset after it, or -1. */
static int
auth_cbor_skip(tvbuff_t *tvb, int offset, int end, int depth)
{
    auth_cbor_t item;

    if (depth > AUTH_MAX_DEPTH || !auth_cbor_head(tvb, offset, end, &item)) {
        return -1;
    }
    offset += item.head_length;
    switch (item.major) {
    case 2:
    case 3:
        if (item.value > (uint64_t)(end - offset)) {
            return -1;
        }
        return offset + (int)item.value;
    case 4:
    case 5: {
        uint64_t count = item.major == 5 ? item.value * 2 : item.value;

        if (item.value > (uint64_t)(end - offset)) {
            return -1;
        }
        for (uint64_t i = 0; i < count && offset >= 0; i++) {
            offset = auth_cbor_skip(tvb, offset, end, depth + 1);
        }
        return offset;
    }
    case 6:
        return auth_cbor_skip(tvb, offset, end, depth + 1);
    default:
        return offset;
    }
}

/* A short diagnostic-notation rendering of one item, for match values. */
static int
auth_cbor_text(wmem_strbuf_t *text, tvbuff_t *tvb, packet_info *pinfo, int offset,
               int end, int depth)
{
    auth_cbor_t item;

    if (depth > AUTH_MAX_DEPTH || !auth_cbor_head(tvb, offset, end, &item)) {
        return -1;
    }
    offset += item.head_length;
    switch (item.major) {
    case 0:
        wmem_strbuf_append_printf(text, "%" PRIu64, item.value);
        return offset;
    case 1:
        wmem_strbuf_append_printf(text, "-%" PRIu64 "%s", item.value + 1,
                                  item.value == UINT64_MAX ? " (overflow)" : "");
        return offset;
    case 2:
    case 3:
        if (item.value > (uint64_t)(end - offset)) {
            return -1;
        }
        wmem_strbuf_append_printf(text, item.major == 2 ? "'%s'" : "\"%s\"",
                                  tvb_format_text(pinfo->pool, tvb, offset, (int)item.value));
        return offset + (int)item.value;
    case 4:
    case 5:
        wmem_strbuf_append_c(text, item.major == 4 ? '[' : '{');
        for (uint64_t i = 0; i < item.value && offset >= 0; i++) {
            if (i) {
                wmem_strbuf_append(text, ", ");
            }
            offset = auth_cbor_text(text, tvb, pinfo, offset, end, depth + 1);
            if (item.major == 5 && offset >= 0) {
                wmem_strbuf_append(text, ": ");
                offset = auth_cbor_text(text, tvb, pinfo, offset, end, depth + 1);
            }
        }
        wmem_strbuf_append_c(text, item.major == 4 ? ']' : '}');
        return offset;
    case 6:
        wmem_strbuf_append_printf(text, "%" PRIu64 "(", item.value);
        offset = auth_cbor_text(text, tvb, pinfo, offset, end, depth + 1);
        wmem_strbuf_append_c(text, ')');
        return offset;
    default:
        wmem_strbuf_append(text, item.value == 20 ? "false" : item.value == 21 ? "true" :
                                 item.value == 22 ? "null" : "simple");
        return offset;
    }
}

/* ------------------------------------------------------------------------- */
/* Claims                                                                    */
/* ------------------------------------------------------------------------- */

/*
 * One scope: [actions, ? ns-match(es), ? track-match]. In c4m-00 the matches
 * are CTA-5007 maps; from c4m-01 a namespace match is an array of per-field
 * matches, each a bstr (exact) or [1 prefix / 2 suffix, bstr].
 */
static void
auth_dissect_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                   int end)
{
    auth_cbor_t scope, actions, action;
    proto_item *scope_item;
    proto_tree *scope_tree;
    int scope_end = auth_cbor_skip(tvb, offset, end, 0);

    if (scope_end < 0 || !auth_cbor_head(tvb, offset, end, &scope) || scope.major != 4) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, offset, end - offset);
        return;
    }
    scope_tree = proto_tree_add_subtree(tree, tvb, offset, scope_end - offset, ett_auth_scope,
                                        &scope_item, "Scope");
    offset += scope.head_length;
    if (scope.value == 0) {
        return;
    }

    if (!auth_cbor_head(tvb, offset, end, &actions) || actions.major != 4) {
        proto_tree_add_expert(scope_tree, pinfo, &ei_auth_malformed, tvb, offset, 1);
        return;
    }
    offset += actions.head_length;
    for (uint64_t i = 0; i < actions.value; i++) {
        if (!auth_cbor_head(tvb, offset, end, &action) || action.major != 0) {
            proto_tree_add_expert(scope_tree, pinfo, &ei_auth_malformed, tvb, offset, 1);
            return;
        }
        proto_tree_add_uint(scope_tree, hf_auth_action, tvb, offset, action.head_length,
                            (uint32_t)MIN(action.value, UINT32_MAX));
        proto_item_append_text(scope_item, "%s%s", i ? ", " : ": ",
                               val_to_str_const((uint32_t)MIN(action.value, UINT32_MAX),
                                                auth_action_vals, "Unknown"));
        offset += action.head_length;
    }
    for (uint64_t i = 1; i < scope.value && i <= 2; i++) {
        wmem_strbuf_t *text = wmem_strbuf_new(pinfo->pool, "");
        int next = auth_cbor_text(text, tvb, pinfo, offset, end, 0);

        if (next < 0) {
            proto_tree_add_expert(scope_tree, pinfo, &ei_auth_malformed, tvb, offset,
                                  end - offset);
            return;
        }
        proto_tree_add_string(scope_tree, i == 1 ? hf_auth_ns_match : hf_auth_track_match,
                              tvb, offset, next - offset, wmem_strbuf_get_str(text));
        offset = next;
    }
}

/* The "moqt" claim: c4m-02 {0: [+ scope]}, c4m-01 [+ scope], c4m-00 scope. */
static void
auth_dissect_moqt_claim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                        int end, bool c4m02)
{
    auth_cbor_t outer, first;

    if (!auth_cbor_head(tvb, offset, end, &outer)) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, offset, end - offset);
        return;
    }
    if (c4m02) {
        proto_item_set_generated(proto_tree_add_string(tree, hf_auth_moqt_revision, tvb,
                                                       offset, 0, "c4m-02"));
        if (outer.major != 5) {
            proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, offset, 1);
            return;
        }
        offset += outer.head_length;
        for (uint64_t i = 0; i < outer.value; i++) {
            auth_cbor_t key, scopes;

            if (!auth_cbor_head(tvb, offset, end, &key)) {
                break;
            }
            offset += key.head_length;
            if (key.major == 0 && key.value == 0 &&
                auth_cbor_head(tvb, offset, end, &scopes) && scopes.major == 4) {
                offset += scopes.head_length;
                for (uint64_t s = 0; s < scopes.value && offset >= 0; s++) {
                    auth_dissect_scope(tvb, pinfo, tree, offset, end);
                    offset = auth_cbor_skip(tvb, offset, end, 0);
                }
            } else {
                /* Other keys are reserved: the claims set is unacceptable. */
                proto_tree_add_expert_format(tree, pinfo, &ei_auth_malformed, tvb,
                                             key.start, key.head_length,
                                             "Reserved key in the moqt claim");
                offset = auth_cbor_skip(tvb, offset, end, 0);
            }
            if (offset < 0) {
                return;
            }
        }
        return;
    }
    /* c4m-01: an array of scopes, whose first element is itself an array. */
    if (outer.major == 4 && outer.value > 0 &&
        auth_cbor_head(tvb, offset + outer.head_length, end, &first) && first.major == 4) {
        auth_cbor_t actions;

        /* A c4m-00 scope starts with its actions array instead. */
        if (auth_cbor_head(tvb, offset + outer.head_length + first.head_length, end,
                           &actions) && actions.major == 4) {
            proto_item_set_generated(proto_tree_add_string(tree, hf_auth_moqt_revision,
                                                           tvb, offset, 0, "c4m-01"));
            offset += outer.head_length;
            for (uint64_t s = 0; s < outer.value && offset >= 0; s++) {
                auth_dissect_scope(tvb, pinfo, tree, offset, end);
                offset = auth_cbor_skip(tvb, offset, end, 0);
            }
            return;
        }
    }
    proto_item_set_generated(proto_tree_add_string(tree, hf_auth_moqt_revision, tvb,
                                                   offset, 0, "c4m-00"));
    auth_dissect_scope(tvb, pinfo, tree, offset, end);
}

static void
auth_add_time(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length,
              const auth_cbor_t *value)
{
    nstime_t t = { (time_t)(value->major == 0 ? (int64_t)MIN(value->value, INT64_MAX)
                                              : -1 - (int64_t)MIN(value->value, INT64_MAX - 1)),
                   0 };

    proto_tree_add_time(tree, hf, tvb, offset, length, &t);
}

/* A CWT claims set (RFC 8392): a map keyed by integers or strings. */
static void
auth_dissect_claims(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int end = tvb_reported_length(tvb), offset = 0;
    auth_cbor_t map;
    proto_tree *claims_tree;

    if (!auth_cbor_head(tvb, 0, end, &map) || map.major != 5) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, 0, end);
        return;
    }
    claims_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_auth_claims, NULL,
                                                "Claims (%" PRIu64 ")", map.value);
    offset = map.head_length;
    for (uint64_t i = 0; i < map.value; i++) {
        auth_cbor_t key, value;
        int64_t claim;
        int value_end, start = offset;
        proto_item *item;
        proto_tree *claim_tree;
        wmem_strbuf_t *text = wmem_strbuf_new(pinfo->pool, "");

        if (!auth_cbor_head(tvb, offset, end, &key)) {
            proto_tree_add_expert(claims_tree, pinfo, &ei_auth_malformed, tvb, offset,
                                  end - offset);
            return;
        }
        if (key.major == 0) {
            claim = (int64_t)MIN(key.value, INT64_MAX);
        } else if (key.major == 1) {
            claim = -1 - (int64_t)MIN(key.value, INT64_MAX - 1);
        } else {
            claim = INT64_MIN;  /* text keys are not decoded */
        }
        offset = key.major <= 1 ? offset + key.head_length
                                : auth_cbor_skip(tvb, offset, end, 0);
        value_end = offset >= 0 ? auth_cbor_skip(tvb, offset, end, 0) : -1;
        if (value_end < 0 || !auth_cbor_head(tvb, offset, end, &value)) {
            proto_tree_add_expert(claims_tree, pinfo, &ei_auth_malformed, tvb, start,
                                  end - start);
            return;
        }
        auth_cbor_text(text, tvb, pinfo, start, end, 0);
        item = proto_tree_add_int64(claims_tree, hf_auth_claim, tvb, start,
                                    value_end - start, claim);
        claim_tree = proto_item_add_subtree(item, ett_auth_claim);
        if (claim == INT64_MIN) {
            proto_item_set_text(item, "Claim %s", wmem_strbuf_get_str(text));
        }

        switch (claim) {
        case CLAIM_ISS:
        case CLAIM_SUB:
        case CLAIM_AUD:
            proto_item_append_text(item, " (%s)", claim == CLAIM_ISS ? "iss" :
                                   claim == CLAIM_SUB ? "sub" : "aud");
            if (value.major == 3) {
                proto_tree_add_item(claim_tree, claim == CLAIM_ISS ? hf_auth_iss :
                                    claim == CLAIM_SUB ? hf_auth_sub : hf_auth_aud,
                                    tvb, offset + value.head_length, (int)value.value,
                                    ENC_UTF_8);
            } else {
                wmem_strbuf_t *v = wmem_strbuf_new(pinfo->pool, "");

                auth_cbor_text(v, tvb, pinfo, offset, end, 0);
                proto_tree_add_string(claim_tree, hf_auth_value, tvb, offset,
                                      value_end - offset, wmem_strbuf_get_str(v));
            }
            break;
        case CLAIM_EXP:
        case CLAIM_NBF:
        case CLAIM_IAT:
            proto_item_append_text(item, " (%s)", claim == CLAIM_EXP ? "exp" :
                                   claim == CLAIM_NBF ? "nbf" : "iat");
            if (value.major <= 1) {
                auth_add_time(claim_tree, claim == CLAIM_EXP ? hf_auth_exp :
                              claim == CLAIM_NBF ? hf_auth_nbf : hf_auth_iat,
                              tvb, offset, value_end - offset, &value);
            }
            break;
        case CLAIM_CTI:
            proto_item_append_text(item, " (cti)");
            if (value.major == 2) {
                proto_tree_add_item(claim_tree, hf_auth_cti, tvb, offset + value.head_length,
                                    (int)value.value, ENC_NA);
            }
            break;
        case CLAIM_CATREPLAY:
            proto_item_append_text(item, " (catreplay)");
            if (value.major == 0) {
                proto_tree_add_uint64(claim_tree, hf_auth_catreplay, tvb, offset,
                                      value_end - offset, value.value);
            }
            break;
        case CLAIM_MOQT_01:
        case CLAIM_MOQT_02:
            proto_item_append_text(item, " (moqt)");
            auth_dissect_moqt_claim(tvb, pinfo, claim_tree, offset, value_end,
                                    claim == CLAIM_MOQT_02);
            break;
        case CLAIM_MOQT_REVAL_01:
        case CLAIM_MOQT_REVAL_02:
            proto_item_append_text(item, " (moqt-reval)");
            if (value.major == 0) {
                proto_tree_add_uint64(claim_tree, hf_auth_reval, tvb, offset,
                                      value_end - offset, value.value);
            }
            break;
        default: {
            wmem_strbuf_t *v = wmem_strbuf_new(pinfo->pool, "");

            if (claim == CLAIM_CNF) {
                proto_item_append_text(item, " (cnf)");
            } else if (claim == CLAIM_CATDPOP) {
                proto_item_append_text(item, " (catdpop)");
            }
            auth_cbor_text(v, tvb, pinfo, offset, value_end, 0);
            proto_tree_add_string(claim_tree, claim == CLAIM_CNF ? hf_auth_cnf : hf_auth_value,
                                  tvb, offset, value_end - offset, wmem_strbuf_get_str(v));
            break;
        }
        }
        offset = value_end;
    }
}

/*
 * A CWT: tags (61 for a CWT, then the COSE message type), a COSE array of
 * protected headers, unprotected headers, the payload and the signature or
 * tag. The payload of a signed or MACed CWT is the claims set.
 */
static void
auth_dissect_cwt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int end = tvb_reported_length(tvb), offset = 0;
    uint64_t cose_tag = 0;
    auth_cbor_t item;

    while (auth_cbor_head(tvb, offset, end, &item) && item.major == 6) {
        if (item.value != CWT_TAG) {
            cose_tag = item.value;
        }
        offset += item.head_length;
    }
    if (!auth_cbor_head(tvb, offset, end, &item) ||
        (offset == 0 && item.major != 4 && item.major != 5)) {
        /* Not even shaped like a CWT, e.g. a placeholder value. */
        proto_tree_add_expert(tree, pinfo, &ei_auth_not_cwt, tvb, 0, end);
        return;
    }
    if (item.major == 5) {
        /* An unprotected claims set. */
        auth_dissect_claims(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
        return;
    }
    if (item.major != 4 || (item.value != 3 && item.value != 4)) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, offset, end - offset);
        return;
    }
    if (cose_tag == 0) {
        /* Untagged: COSE_Encrypt0 has three elements, the others four. */
        cose_tag = item.value == 3 ? COSE_TAG_ENCRYPT0 : COSE_TAG_SIGN1;
    }
    proto_item_set_generated(proto_tree_add_uint(tree, hf_auth_cose_tag, tvb, 0, 0,
                                                 (uint32_t)MIN(cose_tag, UINT32_MAX)));
    if (cose_handle) {
        call_dissector(cose_handle, tvb, pinfo, tree);
    }
    if (cose_tag == COSE_TAG_ENCRYPT0) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_encrypted, tvb, 0, end);
        return;
    }
    offset += item.head_length;
    offset = auth_cbor_skip(tvb, offset, end, 0);                     /* protected */
    offset = offset >= 0 ? auth_cbor_skip(tvb, offset, end, 0) : -1; /* unprotected */
    if (offset < 0 || !auth_cbor_head(tvb, offset, end, &item) || item.major != 2 ||
        item.value > (uint64_t)(end - offset - item.head_length)) {
        proto_tree_add_expert(tree, pinfo, &ei_auth_malformed, tvb, 0, end);
        return;
    }
    auth_dissect_claims(tvb_new_subset_length(tvb, offset + item.head_length,
                                              (int)item.value),
                        pinfo, tree);
}

/* ------------------------------------------------------------------------- */
/* Token Types                                                               */
/* ------------------------------------------------------------------------- */

static int
dissect_moq_auth_cat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item = proto_tree_add_item(tree, proto_moq_auth, tvb, 0, -1, ENC_NA);
    proto_tree *auth_tree = proto_item_add_subtree(item, ett_auth);

    proto_item_append_text(item, ", Common Access Token");
    auth_dissect_cwt(tvb, pinfo, auth_tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC 9577 section 2.2 Token: token_type (16), nonce (32), challenge_digest
 * (32), token_key_id (Nid = 32), authenticator (Nk, by type).
 */
static int
dissect_moq_auth_privacy_pass(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              void *data _U_)
{
    int length = tvb_reported_length(tvb);
    proto_item *item = proto_tree_add_item(tree, proto_moq_auth, tvb, 0, -1, ENC_NA);
    proto_tree *auth_tree = proto_item_add_subtree(item, ett_auth);
    uint32_t token_type;
    int nk;

    proto_item_append_text(item, ", Privacy Pass Token");
    if (length < 2) {
        proto_tree_add_expert(auth_tree, pinfo, &ei_auth_malformed, tvb, 0, length);
        return length;
    }
    proto_tree_add_item_ret_uint(auth_tree, hf_auth_pp_token_type, tvb, 0, 2,
                                 ENC_BIG_ENDIAN, &token_type);
    switch (token_type) {
    case 0x0001: nk = 48;  break;
    case 0x0002: nk = 256; break;
    case 0x0005: nk = 64;  break;
    default:     nk = -1;  break;
    }
    if (nk < 0 || length < 2 + 96) {
        if (length > 2) {
            proto_tree_add_item(auth_tree, hf_auth_opaque, tvb, 2, -1, ENC_NA);
        }
        return length;
    }
    proto_tree_add_item(auth_tree, hf_auth_pp_nonce, tvb, 2, 32, ENC_NA);
    proto_tree_add_item(auth_tree, hf_auth_pp_challenge_digest, tvb, 34, 32, ENC_NA);
    proto_tree_add_item(auth_tree, hf_auth_pp_token_key_id, tvb, 66, 32, ENC_NA);
    item = proto_tree_add_item(auth_tree, hf_auth_pp_authenticator, tvb, 98, -1, ENC_NA);
    if (length - 98 != nk) {
        expert_add_info_format(pinfo, item, &ei_auth_pp_length,
                               "Authenticator is %d bytes; this token type has %d",
                               length - 98, nk);
    }
    return length;
}

static int
dissect_moq_auth_negotiated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            void *data _U_)
{
    int length = tvb_reported_length(tvb);
    proto_item *item;
    proto_tree *auth_tree;
    uint8_t form;

    if (!pref_libloc_forms || length < 1) {
        return 0;
    }
    form = tvb_get_uint8(tvb, 0);
    if (form < 0x01 || form > 0x03) {
        return 0;
    }
    item = proto_tree_add_item(tree, proto_moq_auth, tvb, 0, -1, ENC_NA);
    auth_tree = proto_item_add_subtree(item, ett_auth);
    proto_tree_add_item(auth_tree, hf_auth_libloc_form, tvb, 0, 1, ENC_NA);
    proto_item_append_text(item, ", %s (libloc)",
                           val_to_str_const(form, auth_libloc_form_vals, "Unknown"));
    if (form == 0x01) {
        if (length > 1) {
            proto_tree_add_item(auth_tree, hf_auth_opaque, tvb, 1, -1, ENC_NA);
        }
    } else {
        auth_dissect_cwt(tvb_new_subset_remaining(tvb, 1), pinfo, auth_tree);
    }
    return length;
}

void
proto_register_moq_auth(void)
{
    static hf_register_info hf[] = {
        { &hf_auth_libloc_form,
          { "libloc Token Form", "moq_auth.libloc_form",
            FT_UINT8, BASE_HEX, VALS(auth_libloc_form_vals), 0x0,
            "libloc's tag for a Token Type 0 (agreed out of band) value", HFILL }
        },
        { &hf_auth_cose_tag,
          { "COSE Message", "moq_auth.cose",
            FT_UINT32, BASE_DEC, VALS(auth_cose_tag_vals), 0x0, NULL, HFILL }
        },
        { &hf_auth_claim,
          { "Claim", "moq_auth.claim",
            FT_INT64, BASE_DEC, NULL, 0x0, "CWT claim key", HFILL }
        },
        { &hf_auth_iss,
          { "Issuer", "moq_auth.iss",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_sub,
          { "Subject", "moq_auth.sub",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_aud,
          { "Audience", "moq_auth.aud",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_exp,
          { "Expiration Time", "moq_auth.exp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_nbf,
          { "Not Before", "moq_auth.nbf",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_iat,
          { "Issued At", "moq_auth.iat",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_cti,
          { "CWT ID", "moq_auth.cti",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_cnf,
          { "Confirmation", "moq_auth.cnf",
            FT_STRING, BASE_NONE, NULL, 0x0, "Proof-of-possession key (jkt or ckt)", HFILL }
        },
        { &hf_auth_catreplay,
          { "Replay", "moq_auth.catreplay",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "0 permitted, 1 single use (one connection), 2 implementation defined", HFILL }
        },
        { &hf_auth_moqt_revision,
          { "Claim Layout", "moq_auth.moqt.revision",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "draft-ietf-moq-c4m revision the moqt claim follows", HFILL }
        },
        { &hf_auth_action,
          { "Action", "moq_auth.action",
            FT_UINT32, BASE_DEC, VALS(auth_action_vals), 0x0, NULL, HFILL }
        },
        { &hf_auth_ns_match,
          { "Namespace Match", "moq_auth.ns_match",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_track_match,
          { "Track Match", "moq_auth.track_match",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_reval,
          { "Revalidation Interval", "moq_auth.moqt_reval",
            FT_UINT64, BASE_DEC, NULL, 0x0, "Seconds", HFILL }
        },
        { &hf_auth_value,
          { "Value", "moq_auth.value",
            FT_STRING, BASE_NONE, NULL, 0x0, "In CBOR diagnostic notation", HFILL }
        },
        { &hf_auth_pp_token_type,
          { "Token Type", "moq_auth.privacy_pass.token_type",
            FT_UINT16, BASE_HEX, VALS(auth_pp_token_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_auth_pp_nonce,
          { "Nonce", "moq_auth.privacy_pass.nonce",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_pp_challenge_digest,
          { "Challenge Digest", "moq_auth.privacy_pass.challenge_digest",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_pp_token_key_id,
          { "Token Key ID", "moq_auth.privacy_pass.token_key_id",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_pp_authenticator,
          { "Authenticator", "moq_auth.privacy_pass.authenticator",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_auth_opaque,
          { "Opaque Value", "moq_auth.opaque",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_auth,
        &ett_auth_claims,
        &ett_auth_claim,
        &ett_auth_scope,
    };

    static ei_register_info ei[] = {
        { &ei_auth_malformed,
          { "moq_auth.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed token", EXPFILL }
        },
        { &ei_auth_not_cwt,
          { "moq_auth.not_cwt", PI_UNDECODED, PI_NOTE,
            "The Token Value is not a CBOR Web Token", EXPFILL }
        },
        { &ei_auth_encrypted,
          { "moq_auth.encrypted", PI_UNDECODED, PI_NOTE,
            "The claims of an encrypted CWT are not decoded", EXPFILL }
        },
        { &ei_auth_pp_length,
          { "moq_auth.privacy_pass.length", PI_MALFORMED, PI_WARN,
            "Unexpected authenticator length", EXPFILL }
        },
    };

    expert_module_t *expert_auth;
    module_t *auth_module;

    proto_moq_auth = proto_register_protocol("MOQT Authorization Token", "MOQT Auth",
                                             "moq_auth");
    proto_register_field_array(proto_moq_auth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_auth = expert_register_protocol(proto_moq_auth);
    expert_register_field_array(expert_auth, ei, array_length(ei));

    auth_module = prefs_register_protocol(proto_moq_auth, NULL);
    prefs_register_bool_preference(auth_module, "libloc_token_forms",
                                   "Decode libloc's Token Type 0 forms",
                                   "Read a leading 0x01, 0x02 or 0x03 in a Token Type 0 "
                                   "value as libloc's test token, CWT or claims set tag",
                                   &pref_libloc_forms);
}

void
proto_reg_handoff_moq_auth(void)
{
    dissector_add_uint("moqt.auth_token_type", MOQT_TOKEN_TYPE_CAT,
                       create_dissector_handle(dissect_moq_auth_cat, proto_moq_auth));
    dissector_add_uint("moqt.auth_token_type", MOQT_TOKEN_TYPE_PRIVACY_PASS,
                       create_dissector_handle(dissect_moq_auth_privacy_pass,
                                               proto_moq_auth));
    dissector_add_uint("moqt.auth_token_type", MOQT_TOKEN_TYPE_NEGOTIATED,
                       create_dissector_handle(dissect_moq_auth_negotiated, proto_moq_auth));
    cose_handle = find_dissector_add_dependency("cose", proto_moq_auth);
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
