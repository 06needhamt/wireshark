/* packet-moq-secobj.c
 * Routines for MOQ Secure Objects dissection and decryption
 * draft-ietf-moq-secure-objects-01
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A Secure Object is a MOQT Object whose payload is the AEAD ciphertext of
 *
 *   vi64(len(payload)) | payload | Encrypted Properties List (optional)
 *
 * Its Immutable Properties start with the Secure Object Key ID property
 * (type 0x02). Decryption needs the track's base key, which the
 * "moq_secobj_keys" table supplies per Key ID (and optionally per track):
 *
 *   moq_secret = HKDF-Extract("", track_base_key)
 *   moq_key    = HKDF-Expand(moq_secret, "MOQ 1.0 Secure Objects Secret key "
 *                            | Full Track Name | suite (16) | Key ID (64), Nk)
 *   moq_salt   = HKDF-Expand(moq_secret, "MOQ 1.0 Secret salt "
 *                            | Full Track Name | suite (16) | Key ID (64), Nn)
 *   nonce      = moq_salt XOR (Group ID (64) | Object ID (32))
 *   AAD        = Group ID (64) | Object ID (32) | Publisher Priority (8)
 *                | Serialized Immutable Properties
 *
 * The Full Track Name is the namespace field count and each field, then the
 * track name, length-prefixed with vi64s. As in the draft's Appendix B, each
 * Immutable Property is serialized for the AAD as a 16-bit type, a vi64
 * length and the value (an integer as its vi64). The AES-GCM suites use the
 * tag GCM produces; the AES-CTR suites use SFrame's construction, with the
 * first 16 bytes of moq_key for AES-CTR and the rest as the HMAC-SHA256 key
 * over AAD | nonce | ciphertext.
 *
 * A decrypted payload is offered again to the MOQT payload dissectors, so an
 * encrypted LOC or MSF Object decodes as its plaintext would.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <wsutil/wsgcrypt.h>

#include "packet-moqt.h"

void proto_register_moq_secobj(void);
void proto_reg_handoff_moq_secobj(void);

#define SECOBJ_PROP_KEY_ID           0x02
#define SECOBJ_PROP_ENCRYPTED_LIST   0x0a
#define SECOBJ_PROP_IMMUTABLE        0x0b
#define SECOBJ_PROP_PADDING          0x32
#define SECOBJ_PROP_DEFAULT_PRIORITY 0x0e
#define SECOBJ_DEFAULT_PRIORITY      128
#define SECOBJ_NONCE_LEN             12
#define SECOBJ_MAX_KEY_LEN           48

static int proto_moq_secobj;

static int hf_secobj_key_id;
static int hf_secobj_cipher_suite;
static int hf_secobj_group_id;
static int hf_secobj_object_id;
static int hf_secobj_priority;
static int hf_secobj_ciphertext;
static int hf_secobj_tag;
static int hf_secobj_plaintext_length;
static int hf_secobj_payload;
static int hf_secobj_epl_type;
static int hf_secobj_epl_length;
static int hf_secobj_epl_properties;
static int hf_secobj_padding_length;
static int hf_secobj_padding;
static int hf_secobj_trailing;

static int ett_secobj;
static int ett_secobj_plaintext;

static expert_field ei_secobj_no_key;
static expert_field ei_secobj_decrypt_failed;
static expert_field ei_secobj_malformed;
static expert_field ei_secobj_object_id;

static dissector_table_t moqt_track_name_table;
static heur_dissector_list_t moqt_payload_heur_list;

typedef struct {
    unsigned nh;        /* hash length: SHA-256 or SHA-512 */
    unsigned nk;        /* key length */
    unsigned nt;        /* tag length */
    bool ctr_hmac;
} secobj_suite_t;

static const value_string secobj_suite_vals[] = {
    { 0x0001, "AES_128_CTR_HMAC_SHA256_80" },
    { 0x0002, "AES_128_CTR_HMAC_SHA256_64" },
    { 0x0003, "AES_128_CTR_HMAC_SHA256_32" },
    { 0x0004, "AES_128_GCM_SHA256_128" },
    { 0x0005, "AES_256_GCM_SHA512_128" },
    { 0, NULL }
};

static const secobj_suite_t *
secobj_suite(unsigned id)
{
    static const secobj_suite_t suites[] = {
        { 32, 48, 10, true },
        { 32, 48,  8, true },
        { 32, 48,  4, true },
        { 32, 16, 16, false },
        { 64, 32, 16, false },
    };

    return id >= 1 && id <= array_length(suites) ? &suites[id - 1] : NULL;
}

/* ------------------------------------------------------------------------- */
/* Keys                                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *track_namespace;   /* '/'-joined, or empty for any */
    char *track_name;        /* empty for any */
    unsigned key_id;
    unsigned cipher_suite;
    unsigned char *base_key;
    unsigned base_key_len;
} secobj_key_t;

static secobj_key_t *secobj_keys;
static unsigned secobj_key_count;

UAT_CSTRING_CB_DEF(secobj_keys, track_namespace, secobj_key_t)
UAT_CSTRING_CB_DEF(secobj_keys, track_name, secobj_key_t)
UAT_DEC_CB_DEF(secobj_keys, key_id, secobj_key_t)
UAT_HEX_CB_DEF(secobj_keys, cipher_suite, secobj_key_t)
UAT_BUFFER_CB_DEF(secobj_keys, base_key, secobj_key_t, base_key, base_key_len)

static void *
secobj_key_copy(void *dest, const void *source, size_t len _U_)
{
    secobj_key_t *d = (secobj_key_t *)dest;
    const secobj_key_t *s = (const secobj_key_t *)source;

    d->track_namespace = g_strdup(s->track_namespace);
    d->track_name = g_strdup(s->track_name);
    d->key_id = s->key_id;
    d->cipher_suite = s->cipher_suite;
    d->base_key = (unsigned char *)g_memdup2(s->base_key, s->base_key_len);
    d->base_key_len = s->base_key_len;
    return d;
}

static bool
secobj_key_update(void *record, char **error)
{
    secobj_key_t *key = (secobj_key_t *)record;

    if (!secobj_suite(key->cipher_suite)) {
        *error = g_strdup("Cipher suite must be 1 to 5");
        return false;
    }
    if (key->base_key_len == 0) {
        *error = g_strdup("The track base key is empty");
        return false;
    }
    return true;
}

static void
secobj_key_free(void *record)
{
    secobj_key_t *key = (secobj_key_t *)record;

    g_free(key->track_namespace);
    g_free(key->track_name);
    g_free(key->base_key);
}

static const secobj_key_t *
secobj_find_key(const moqt_object_info_t *info, uint64_t key_id)
{
    for (unsigned i = 0; i < secobj_key_count; i++) {
        const secobj_key_t *key = &secobj_keys[i];

        if (key->key_id != key_id) {
            continue;
        }
        if (key->track_namespace && key->track_namespace[0] &&
            (!info->track_namespace || strcmp(key->track_namespace, info->track_namespace) != 0)) {
            continue;
        }
        if (key->track_name && key->track_name[0] &&
            (!info->track_name || strcmp(key->track_name, info->track_name) != 0)) {
            continue;
        }
        return key;
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Encodings                                                                 */
/* ------------------------------------------------------------------------- */

static void
secobj_append_vi64(wmem_array_t *out, uint64_t value)
{
    uint8_t buf[9];
    int length = 1;

    while (length < 8 && value >= (UINT64_C(1) << (7 * length))) {
        length++;
    }
    if (length == 8 && value >= (UINT64_C(1) << 56)) {
        buf[0] = 0xff;
        for (int i = 0; i < 8; i++) {
            buf[1 + i] = (uint8_t)(value >> (56 - 8 * i));
        }
        wmem_array_append(out, buf, 9);
        return;
    }
    for (int i = length - 1; i >= 0; i--) {
        buf[i] = (uint8_t)value;
        value >>= 8;
    }
    buf[0] |= (uint8_t)(0xff00 >> (length - 1));
    wmem_array_append(out, buf, (unsigned)length);
}

/* MOQT vi64 from a tvb; returns its length, 0 if truncated. */
static int
secobj_read_vi64(tvbuff_t *tvb, int offset, int end, uint64_t *value)
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
        return 9;
    }
    *value = first & (0xff >> length);
    for (int i = 1; i < length; i++) {
        *value = (*value << 8) | tvb_get_uint8(tvb, offset + i);
    }
    return length;
}

/* An integer in the session's encoding: QUIC varints before draft 17. */
static unsigned
secobj_read_int(const uint8_t *data, unsigned length, unsigned offset, unsigned draft,
                uint64_t *value)
{
    if (offset >= length) {
        return 0;
    }
    if (draft < 17) {
        unsigned size = 1u << (data[offset] >> 6);

        if (offset + size > length) {
            return 0;
        }
        *value = data[offset] & 0x3f;
        for (unsigned i = 1; i < size; i++) {
            *value = (*value << 8) | data[offset + i];
        }
        return size;
    } else {
        uint8_t first = data[offset];
        unsigned size = 1;

        while (size < 9 && (first & (0x100 >> size)) != 0) {
            size++;
        }
        if (offset + size > length) {
            return 0;
        }
        *value = size == 9 ? 0 : (uint64_t)(first & (0xff >> size));
        for (unsigned i = 1; i < size; i++) {
            *value = (*value << 8) | data[offset + i];
        }
        return size;
    }
}

typedef struct {
    uint64_t type;
    uint64_t integer;
    const uint8_t *data;
    unsigned length;
} secobj_prop_t;

/*
 * The Key-Value-Pairs of the IMMUTABLE block, delta-coded in the session's
 * integer encoding. Returns the number read, or -1 if malformed.
 */
static int
secobj_parse_immutable(const moqt_property_t *block, unsigned draft,
                       secobj_prop_t *props, int max)
{
    unsigned offset = 0, size;
    uint64_t type = 0, delta, value;
    int count = 0;

    while (offset < block->length) {
        if (count == max) {
            return -1;
        }
        size = secobj_read_int(block->data, block->length, offset, draft, &delta);
        if (size == 0 || delta > UINT64_MAX - type) {
            return -1;
        }
        offset += size;
        type += delta;
        size = secobj_read_int(block->data, block->length, offset, draft, &value);
        if (size == 0) {
            return -1;
        }
        offset += size;
        props[count] = (secobj_prop_t){ .type = type };
        if ((type & 1) == 0) {
            props[count].integer = value;
        } else {
            if (value > block->length - offset) {
                return -1;
            }
            props[count].data = block->data + offset;
            props[count].length = (unsigned)value;
            offset += (unsigned)value;
        }
        count++;
    }
    return count;
}

/* ------------------------------------------------------------------------- */
/* Decryption                                                                */
/* ------------------------------------------------------------------------- */

/* HKDF-Expand (RFC 5869); wsgcrypt's hkdf_expand stops at 48-byte hashes. */
static bool
secobj_hkdf_expand(int md, unsigned hash_len, const uint8_t *prk, const uint8_t *info,
                   unsigned info_len, uint8_t *out, unsigned out_len)
{
    uint8_t block[64];
    uint8_t *input = (uint8_t *)g_malloc(hash_len + info_len + 1);
    unsigned done = 0, previous = 0;
    uint8_t counter = 1;
    bool ok = true;

    while (ok && done < out_len) {
        memcpy(input, block, previous);
        memcpy(input + previous, info, info_len);
        input[previous + info_len] = counter++;
        ok = ws_hmac_buffer(md, block, input, previous + info_len + 1, prk, hash_len) == 0;
        memcpy(out + done, block, MIN(hash_len, out_len - done));
        done += hash_len;
        previous = hash_len;
    }
    g_free(input);
    return ok;
}

static bool
secobj_derive(const secobj_key_t *key, const secobj_suite_t *suite,
              const wmem_array_t *full_track_name, uint64_t key_id,
              uint8_t *moq_key, uint8_t *moq_salt)
{
    static const char key_label[] = "MOQ 1.0 Secure Objects Secret key ";
    static const char salt_label[] = "MOQ 1.0 Secret salt ";
    int md = suite->nh == 64 ? GCRY_MD_SHA512 : GCRY_MD_SHA256;
    uint8_t zeros[64] = { 0 }, prk[64], tail[10];
    unsigned ftn_len = wmem_array_get_count(full_track_name);
    const uint8_t *ftn = (const uint8_t *)wmem_array_get_raw(full_track_name);
    uint8_t *info = (uint8_t *)g_malloc(sizeof(key_label) + ftn_len + sizeof(tail));
    bool ok;

    tail[0] = (uint8_t)(key->cipher_suite >> 8);
    tail[1] = (uint8_t)key->cipher_suite;
    for (int i = 0; i < 8; i++) {
        tail[2 + i] = (uint8_t)(key_id >> (56 - 8 * i));
    }
    /* An absent salt is HashLen zeros (RFC 5869), the same HMAC key as "". */
    ok = hkdf_extract(md, zeros, suite->nh, key->base_key, key->base_key_len, prk) == 0;

    memcpy(info, key_label, sizeof(key_label) - 1);
    memcpy(info + sizeof(key_label) - 1, ftn, ftn_len);
    memcpy(info + sizeof(key_label) - 1 + ftn_len, tail, sizeof(tail));
    ok = ok && secobj_hkdf_expand(md, suite->nh, prk, info,
                                  (unsigned)(sizeof(key_label) - 1 + ftn_len + sizeof(tail)),
                                  moq_key, suite->nk);

    memcpy(info, salt_label, sizeof(salt_label) - 1);
    memcpy(info + sizeof(salt_label) - 1, ftn, ftn_len);
    memcpy(info + sizeof(salt_label) - 1 + ftn_len, tail, sizeof(tail));
    ok = ok && secobj_hkdf_expand(md, suite->nh, prk, info,
                                  (unsigned)(sizeof(salt_label) - 1 + ftn_len + sizeof(tail)),
                                  moq_salt, SECOBJ_NONCE_LEN);
    g_free(info);
    return ok;
}

/* Returns the plaintext, or NULL when authentication fails. */
static uint8_t *
secobj_decrypt(wmem_allocator_t *scope, const secobj_suite_t *suite,
               const uint8_t *moq_key, const uint8_t *nonce,
               const uint8_t *aad, unsigned aad_len,
               const uint8_t *ct, unsigned ct_len, const uint8_t *tag)
{
    uint8_t *pt = (uint8_t *)wmem_alloc(scope, MAX(ct_len, 1));
    gcry_cipher_hd_t handle;
    bool ok;

    if (!suite->ctr_hmac) {
        if (gcry_cipher_open(&handle, suite->nk == 32 ? GCRY_CIPHER_AES256 : GCRY_CIPHER_AES128,
                             GCRY_CIPHER_MODE_GCM, 0) != 0) {
            return NULL;
        }
        ok = gcry_cipher_setkey(handle, moq_key, suite->nk) == 0 &&
             gcry_cipher_setiv(handle, nonce, SECOBJ_NONCE_LEN) == 0 &&
             gcry_cipher_authenticate(handle, aad, aad_len) == 0 &&
             gcry_cipher_decrypt(handle, pt, ct_len, ct, ct_len) == 0 &&
             gcry_cipher_checktag(handle, tag, suite->nt) == 0;
        gcry_cipher_close(handle);
        return ok ? pt : NULL;
    } else {
        uint8_t counter[16] = { 0 }, mac[32];
        unsigned mac_input_len = aad_len + SECOBJ_NONCE_LEN + ct_len;
        uint8_t *mac_input = (uint8_t *)wmem_alloc(scope, mac_input_len);

        memcpy(mac_input, aad, aad_len);
        memcpy(mac_input + aad_len, nonce, SECOBJ_NONCE_LEN);
        memcpy(mac_input + aad_len + SECOBJ_NONCE_LEN, ct, ct_len);
        if (ws_hmac_buffer(GCRY_MD_SHA256, mac, mac_input, mac_input_len, moq_key + 16,
                           32) != 0 ||
            memcmp(mac, tag, suite->nt) != 0) {
            return NULL;
        }
        memcpy(counter, nonce, SECOBJ_NONCE_LEN);
        if (gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0) != 0) {
            return NULL;
        }
        ok = gcry_cipher_setkey(handle, moq_key, 16) == 0 &&
             gcry_cipher_setctr(handle, counter, sizeof(counter)) == 0 &&
             gcry_cipher_decrypt(handle, pt, ct_len, ct, ct_len) == 0;
        gcry_cipher_close(handle);
        return ok ? pt : NULL;
    }
}

/* ------------------------------------------------------------------------- */
/* Plaintext                                                                 */
/* ------------------------------------------------------------------------- */

/* Offer the decrypted payload to the MOQT payload dissectors once more. */
static void
secobj_dissect_inner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     const moqt_object_info_t *info)
{
    moqt_object_info_t inner = *info;
    moqt_property_t *props = wmem_alloc_array(pinfo->pool, moqt_property_t,
                                              MAX(info->property_count, 1));
    heur_dtbl_entry_t *entry;
    unsigned count = 0;

    /* Without IMMUTABLE the Object no longer looks secured. */
    for (unsigned i = 0; i < info->property_count; i++) {
        if (info->properties[i].type != SECOBJ_PROP_IMMUTABLE) {
            props[count++] = info->properties[i];
        }
    }
    inner.properties = props;
    inner.property_count = count;
    if (!inner.track_name ||
        !dissector_try_string_with_data(moqt_track_name_table, inner.track_name, tvb,
                                        pinfo, tree, true, &inner)) {
        dissector_try_heuristic(moqt_payload_heur_list, tvb, pinfo, tree, &entry, &inner);
    }
}

static void
secobj_dissect_plaintext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         const moqt_object_info_t *info)
{
    int end = tvb_reported_length(tvb), offset;
    proto_tree *pt_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_secobj_plaintext,
                                                 NULL, "Plaintext");
    proto_item *item;
    uint64_t length;
    int size;

    size = secobj_read_vi64(tvb, 0, end, &length);
    if (size == 0 || length > (uint64_t)(end - size)) {
        proto_tree_add_expert(pt_tree, pinfo, &ei_secobj_malformed, tvb, 0, end);
        return;
    }
    proto_tree_add_uint64(pt_tree, hf_secobj_plaintext_length, tvb, 0, size, length);
    offset = size;
    if (length > 0) {
        proto_tree_add_item(pt_tree, hf_secobj_payload, tvb, offset, (int)length, ENC_NA);
    }
    offset += (int)length;

    /* Encrypted Properties List, then Padding, if any (draft section 4). */
    if (end - offset >= 3 && tvb_get_ntohs(tvb, offset) == SECOBJ_PROP_ENCRYPTED_LIST) {
        uint64_t list_length;

        proto_tree_add_item(pt_tree, hf_secobj_epl_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        size = secobj_read_vi64(tvb, offset + 2, end, &list_length);
        if (size == 0 || list_length > (uint64_t)(end - offset - 2 - size)) {
            proto_tree_add_expert(pt_tree, pinfo, &ei_secobj_malformed, tvb, offset,
                                  end - offset);
            return;
        }
        proto_tree_add_uint64(pt_tree, hf_secobj_epl_length, tvb, offset + 2, size,
                              list_length);
        offset += 2 + size;
        if (list_length > 0) {
            proto_tree_add_item(pt_tree, hf_secobj_epl_properties, tvb, offset,
                                (int)list_length, ENC_NA);
        }
        offset += (int)list_length;
    }
    if (end - offset >= 4 && tvb_get_ntohs(tvb, offset) == SECOBJ_PROP_PADDING) {
        uint32_t pad;

        item = proto_tree_add_item_ret_uint(pt_tree, hf_secobj_padding_length, tvb,
                                            offset + 2, 2, ENC_BIG_ENDIAN, &pad);
        if (pad > (uint32_t)(end - offset - 4)) {
            expert_add_info(pinfo, item, &ei_secobj_malformed);
            return;
        }
        if (pad > 0) {
            proto_tree_add_item(pt_tree, hf_secobj_padding, tvb, offset + 4, (int)pad,
                                ENC_NA);
        }
        offset += 4 + (int)pad;
    }
    if (offset < end) {
        proto_tree_add_item(pt_tree, hf_secobj_trailing, tvb, offset, -1, ENC_NA);
    }
    if (length > 0) {
        secobj_dissect_inner(tvb_new_subset_length(tvb, size, (int)length), pinfo, tree,
                             info);
    }
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

static uint8_t
secobj_priority(const moqt_object_info_t *info)
{
    if (info->publisher_priority_known) {
        return info->publisher_priority;
    }
    for (unsigned i = 0; i < info->track_property_count; i++) {
        if (info->track_properties[i].type == SECOBJ_PROP_DEFAULT_PRIORITY) {
            return (uint8_t)MIN(info->track_properties[i].integer, 255);
        }
    }
    return SECOBJ_DEFAULT_PRIORITY;
}

static bool
dissect_secobj_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const moqt_object_info_t *info = (const moqt_object_info_t *)data;
    const moqt_property_t *block = NULL;
    secobj_prop_t props[32];
    const secobj_key_t *key;
    const secobj_suite_t *suite;
    proto_item *secobj_item, *item;
    proto_tree *secobj_tree;
    wmem_array_t *aad, *ftn;
    uint8_t moq_key[SECOBJ_MAX_KEY_LEN], moq_salt[SECOBJ_NONCE_LEN], nonce[SECOBJ_NONCE_LEN];
    uint8_t priority, *pt;
    uint64_t key_id;
    int count, length = tvb_reported_length(tvb), ct_len;

    if (!info) {
        return false;
    }
    for (unsigned i = 0; i < info->property_count; i++) {
        if (info->properties[i].type == SECOBJ_PROP_IMMUTABLE && info->properties[i].data) {
            block = &info->properties[i];
            break;
        }
    }
    if (!block) {
        return false;
    }
    count = secobj_parse_immutable(block, info->draft, props, (int)array_length(props));
    /* The Key ID must be the first Immutable Property. */
    if (count <= 0 || props[0].type != SECOBJ_PROP_KEY_ID) {
        return false;
    }
    key_id = props[0].integer;

    col_append_str(pinfo->cinfo, COL_INFO, " [Secure Object]");
    secobj_item = proto_tree_add_item(tree, proto_moq_secobj, tvb, 0, -1, ENC_NA);
    secobj_tree = proto_item_add_subtree(secobj_item, ett_secobj);
    item = proto_tree_add_uint64(secobj_tree, hf_secobj_key_id, tvb, 0, 0, key_id);
    proto_item_set_generated(item);
    proto_item_append_text(secobj_item, ", Key ID %" PRIu64, key_id);

    key = secobj_find_key(info, key_id);
    suite = key ? secobj_suite(key->cipher_suite) : NULL;
    if (!suite) {
        proto_tree_add_item(secobj_tree, hf_secobj_ciphertext, tvb, 0, -1, ENC_NA);
        proto_tree_add_expert(secobj_tree, pinfo, &ei_secobj_no_key, tvb, 0, 0);
        return true;
    }
    item = proto_tree_add_uint(secobj_tree, hf_secobj_cipher_suite, tvb, 0, 0,
                               key->cipher_suite);
    proto_item_set_generated(item);
    if (!info->group_id_known || !info->object_id_known || !info->track_name) {
        proto_tree_add_item(secobj_tree, hf_secobj_ciphertext, tvb, 0, -1, ENC_NA);
        proto_tree_add_expert_format(secobj_tree, pinfo, &ei_secobj_no_key, tvb, 0, 0,
                                     "The Object's track, Group ID or Object ID is "
                                     "unknown, so it cannot be decrypted");
        return true;
    }
    if (info->object_id > UINT32_MAX) {
        proto_tree_add_expert(secobj_tree, pinfo, &ei_secobj_object_id, tvb, 0, 0);
        return true;
    }
    if ((unsigned)length < suite->nt) {
        proto_tree_add_expert(secobj_tree, pinfo, &ei_secobj_malformed, tvb, 0, length);
        return true;
    }
    ct_len = length - (int)suite->nt;
    if (ct_len > 0) {
        proto_tree_add_item(secobj_tree, hf_secobj_ciphertext, tvb, 0, ct_len, ENC_NA);
    }
    proto_tree_add_item(secobj_tree, hf_secobj_tag, tvb, ct_len, (int)suite->nt, ENC_NA);

    /* Serialized Full Track Name. */
    ftn = wmem_array_new(pinfo->pool, 1);
    secobj_append_vi64(ftn, info->namespace_field_count);
    for (unsigned i = 0; i < info->namespace_field_count; i++) {
        secobj_append_vi64(ftn, info->namespace_fields[i].length);
        wmem_array_append(ftn, info->namespace_fields[i].data,
                          info->namespace_fields[i].length);
    }
    secobj_append_vi64(ftn, info->track_name_bytes.length);
    wmem_array_append(ftn, info->track_name_bytes.data, info->track_name_bytes.length);

    /* AAD and nonce. */
    priority = secobj_priority(info);
    aad = wmem_array_new(pinfo->pool, 1);
    for (int i = 0; i < 8; i++) {
        uint8_t b = (uint8_t)(info->group_id >> (56 - 8 * i));

        wmem_array_append_one(aad, b);
    }
    for (int i = 0; i < 4; i++) {
        uint8_t b = (uint8_t)(info->object_id >> (24 - 8 * i));

        wmem_array_append_one(aad, b);
    }
    wmem_array_append_one(aad, priority);
    for (int i = 0; i < count; i++) {
        uint8_t type[2] = { (uint8_t)(props[i].type >> 8), (uint8_t)props[i].type };

        wmem_array_append(aad, type, 2);
        if ((props[i].type & 1) == 0) {
            wmem_array_t *value = wmem_array_new(pinfo->pool, 1);

            secobj_append_vi64(value, props[i].integer);
            secobj_append_vi64(aad, wmem_array_get_count(value));
            wmem_array_append(aad, wmem_array_get_raw(value), wmem_array_get_count(value));
        } else {
            secobj_append_vi64(aad, props[i].length);
            wmem_array_append(aad, props[i].data, props[i].length);
        }
    }
    item = proto_tree_add_uint64(secobj_tree, hf_secobj_group_id, tvb, 0, 0, info->group_id);
    proto_item_set_generated(item);
    item = proto_tree_add_uint64(secobj_tree, hf_secobj_object_id, tvb, 0, 0, info->object_id);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(secobj_tree, hf_secobj_priority, tvb, 0, 0, priority);
    proto_item_set_generated(item);

    if (!secobj_derive(key, suite, ftn, key_id, moq_key, moq_salt)) {
        proto_tree_add_expert(secobj_tree, pinfo, &ei_secobj_decrypt_failed, tvb, 0, 0);
        return true;
    }
    for (int i = 0; i < SECOBJ_NONCE_LEN; i++) {
        uint8_t ctr = i < 8 ? (uint8_t)(info->group_id >> (56 - 8 * i))
                            : (uint8_t)(info->object_id >> (24 - 8 * (i - 8)));

        nonce[i] = moq_salt[i] ^ ctr;
    }
    pt = secobj_decrypt(pinfo->pool, suite, moq_key, nonce,
                        (const uint8_t *)wmem_array_get_raw(aad), wmem_array_get_count(aad),
                        tvb_get_ptr(tvb, 0, ct_len), (unsigned)ct_len,
                        tvb_get_ptr(tvb, ct_len, (int)suite->nt));
    if (!pt) {
        proto_tree_add_expert(secobj_tree, pinfo, &ei_secobj_decrypt_failed, tvb, 0, length);
        return true;
    }
    proto_item_append_text(secobj_item, ", decrypted");
    {
        tvbuff_t *pt_tvb = tvb_new_child_real_data(tvb, pt, (unsigned)ct_len, ct_len);

        add_new_data_source(pinfo, pt_tvb, "Secure Object plaintext");
        secobj_dissect_plaintext(pt_tvb, pinfo, secobj_tree, info);
    }
    return true;
}

void
proto_register_moq_secobj(void)
{
    static hf_register_info hf[] = {
        { &hf_secobj_key_id,
          { "Key ID", "moq_secobj.key_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Secure Object Key ID Immutable Property", HFILL }
        },
        { &hf_secobj_cipher_suite,
          { "Cipher Suite", "moq_secobj.cipher_suite",
            FT_UINT16, BASE_HEX, VALS(secobj_suite_vals), 0x0,
            "From the Secure Objects keys table", HFILL }
        },
        { &hf_secobj_group_id,
          { "AAD Group ID", "moq_secobj.aad.group_id",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_object_id,
          { "AAD Object ID", "moq_secobj.aad.object_id",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_priority,
          { "AAD Publisher Priority", "moq_secobj.aad.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_ciphertext,
          { "Ciphertext", "moq_secobj.ciphertext",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_tag,
          { "Authentication Tag", "moq_secobj.tag",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_plaintext_length,
          { "Payload Length", "moq_secobj.payload_length",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_payload,
          { "Payload", "moq_secobj.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Decrypted Object payload", HFILL }
        },
        { &hf_secobj_epl_type,
          { "Encrypted Properties List", "moq_secobj.epl.type",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_epl_length,
          { "Encrypted Properties Length", "moq_secobj.epl.length",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_epl_properties,
          { "Encrypted Properties", "moq_secobj.epl.properties",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_padding_length,
          { "Padding Length", "moq_secobj.padding.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_padding,
          { "Padding", "moq_secobj.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_secobj_trailing,
          { "Unparsed Plaintext", "moq_secobj.trailing",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_secobj,
        &ett_secobj_plaintext,
    };

    static ei_register_info ei[] = {
        { &ei_secobj_no_key,
          { "moq_secobj.no_key", PI_DECRYPTION, PI_NOTE,
            "No key for this Key ID in the Secure Objects keys table", EXPFILL }
        },
        { &ei_secobj_decrypt_failed,
          { "moq_secobj.decrypt_failed", PI_DECRYPTION, PI_WARN,
            "Decryption failed (wrong key or tampered Object)", EXPFILL }
        },
        { &ei_secobj_malformed,
          { "moq_secobj.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed Secure Object", EXPFILL }
        },
        { &ei_secobj_object_id,
          { "moq_secobj.object_id", PI_PROTOCOL, PI_ERROR,
            "Secure Object IDs must be below 2^32", EXPFILL }
        },
    };

    static uat_field_t key_fields[] = {
        UAT_FLD_CSTRING(secobj_keys, track_namespace, "Track Namespace",
                        "Namespace fields joined by '/'; empty for any"),
        UAT_FLD_CSTRING(secobj_keys, track_name, "Track Name", "Empty for any"),
        UAT_FLD_DEC(secobj_keys, key_id, "Key ID", "Secure Object Key ID"),
        UAT_FLD_HEX(secobj_keys, cipher_suite, "Cipher Suite", "1 to 5 (hexadecimal)"),
        UAT_FLD_BUFFER(secobj_keys, base_key, "Track Base Key", "In hexadecimal"),
        UAT_END_FIELDS
    };

    expert_module_t *expert_secobj;
    module_t *secobj_module;
    uat_t *keys_uat;

    proto_moq_secobj = proto_register_protocol("MOQ Secure Objects", "Secure Objects",
                                               "moq_secobj");
    proto_register_field_array(proto_moq_secobj, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_secobj = expert_register_protocol(proto_moq_secobj);
    expert_register_field_array(expert_secobj, ei, array_length(ei));

    secobj_module = prefs_register_protocol(proto_moq_secobj, NULL);
    keys_uat = uat_new("Secure Objects keys", sizeof(secobj_key_t), "moq_secobj_keys",
                       true, &secobj_keys, &secobj_key_count, UAT_AFFECTS_DISSECTION, NULL,
                       secobj_key_copy, secobj_key_update, secobj_key_free, NULL, NULL,
                       key_fields);
    prefs_register_uat_preference(secobj_module, "keys", "Track base keys",
                                  "Keys for decrypting MOQ Secure Objects", keys_uat);
}

void
proto_reg_handoff_moq_secobj(void)
{
    /*
     * Registered after the payload formats (handoffs run in name order and
     * heuristics run last registered first), so an encrypted Object is seen
     * here first and its plaintext is then offered to them.
     */
    heur_dissector_add("moqt.payload", dissect_secobj_heur, "MOQ Secure Objects",
                       "moq_secobj_moqt", proto_moq_secobj, HEURISTIC_ENABLE);
    moqt_track_name_table = find_dissector_table("moqt.track_name");
    moqt_payload_heur_list = find_heur_dissector_list("moqt.payload");
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
