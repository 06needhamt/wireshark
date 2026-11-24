/* packet-masque.c
 * Routines for MASQUE (proxying over HTTP) dissection
 *
 *  RFC 9298: Proxying UDP in HTTP (connect-udp)
 *  RFC 9484: Proxying IP in HTTP (connect-ip)
 *  draft-ietf-masque-connect-ethernet-18 (connect-ethernet)
 *  draft-ietf-masque-connect-udp-listen-16 (bound UDP proxying)
 *  draft-ietf-masque-connect-ip-dns-07 (DNS configuration for connect-ip)
 *  draft-ietf-masque-quic-proxy-09 and -10 (QUIC-aware proxying)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MASQUE requests are extended CONNECT requests whose upgrade token names the
 * proxied protocol. Their HTTP Datagrams (and DATAGRAM capsules) start with a
 * Context ID; Context ID 0 carries a UDP payload, an IP packet or an Ethernet
 * frame, and other Context IDs are registered by extensions. Bound UDP
 * proxying registers them with COMPRESSION_ASSIGN capsules: a context with IP
 * Version 0 carries the target address and port in front of each payload, and
 * one with IP Version 4 or 6 stands for a fixed address and port.
 *
 * The capsules of these protocols are registered in the "capsule.type"
 * table, and the datagram dissector in "http.connect.datagram".
 *
 * The capsule codepoints of connect-ip-dns and quic-proxy are provisional, as
 * implemented by libloc. QUIC-aware proxying in forwarded mode sends QUIC
 * packets outside HTTP, which is not dissected here.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/iana-info.h>
#include <epan/prefs.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>

#include "packet-http-capsule.h"

void proto_register_masque(void);
void proto_reg_handoff_masque(void);

/* RFC 9484, Section 4.7. */
#define CAPSULE_ADDRESS_ASSIGN          0x01
#define CAPSULE_ADDRESS_REQUEST         0x02
#define CAPSULE_ROUTE_ADVERTISEMENT     0x03
/* draft-ietf-masque-connect-udp-listen-16, Section 3. */
#define CAPSULE_COMPRESSION_ASSIGN      0x11
#define CAPSULE_COMPRESSION_ACK         0x12
#define CAPSULE_COMPRESSION_CLOSE       0x13
/* draft-ietf-masque-connect-ip-dns-07, Sections 3.4 and 4.1 (provisional). */
#define CAPSULE_DNS_ASSIGN              0x1ace79ec
#define CAPSULE_PREF64                  0x274c0fbc
/* draft-ietf-masque-quic-proxy-09, Section 9.5, and -10, Section 10.5. */
#define CAPSULE_QP09_BASE               0xffe800
#define CAPSULE_QP09_COUNT              10
#define CAPSULE_QP10_BASE               0xffe900
#define CAPSULE_QP10_COUNT              16

/* A bound UDP proxying context (draft-ietf-masque-connect-udp-listen-16). */
typedef struct {
    uint8_t  ip_version;            /* 0: uncompressed, 4 or 6: compressed. */
    uint8_t  address[16];
    uint16_t port;
} masque_context_t;

/* Per request state, kept in the slot provided by the HTTP dissector. */
typedef struct {
    wmem_map_t *contexts;           /* Context ID -> masque_context_t */
} masque_request_t;

static int proto_masque;

static int hf_masque_context_id;
static int hf_masque_payload;
static int hf_masque_target_host;
static int hf_masque_target_port;
static int hf_masque_ip_version;
static int hf_masque_ipv4;
static int hf_masque_ipv6;
static int hf_masque_udp_port;
static int hf_masque_request_id;
static int hf_masque_prefix_length;
static int hf_masque_start_ipv4;
static int hf_masque_start_ipv6;
static int hf_masque_end_ipv4;
static int hf_masque_end_ipv6;
static int hf_masque_ip_protocol;
static int hf_masque_dns_nameserver_count;
static int hf_masque_dns_priority;
static int hf_masque_dns_ipv4_count;
static int hf_masque_dns_ipv6_count;
static int hf_masque_dns_auth_domain;
static int hf_masque_dns_svc_params_length;
static int hf_masque_dns_svc_params;
static int hf_masque_dns_internal_count;
static int hf_masque_dns_search_count;
static int hf_masque_dns_internal_domain;
static int hf_masque_dns_search_domain;
static int hf_masque_domain_length;
static int hf_masque_pref64_prefix_length;
static int hf_masque_pref64_prefix;
static int hf_masque_qp_sequence;
static int hf_masque_qp_vcid_sequence;
static int hf_masque_qp_retire_prior_to;
static int hf_masque_qp_reason;
static int hf_masque_qp_cid_length;
static int hf_masque_qp_cid;
static int hf_masque_qp_vcid_length;
static int hf_masque_qp_vcid;
static int hf_masque_qp_srt_length;
static int hf_masque_qp_srt;
static int hf_masque_qp_max_ids;

static int ett_masque;
static int ett_masque_entry;

static expert_field ei_masque_malformed;
static expert_field ei_masque_unknown_context;
static expert_field ei_masque_context_zero;

static dissector_handle_t masque_datagram_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t eth_handle;
static dissector_table_t udp_port_table;

/* Hand Context ID 0 payloads of connect-udp to a dissector for the target port. */
static bool masque_try_udp_port;

static const value_string masque_ip_version_vals[] = {
    { 0, "Uncompressed" },
    { 4, "IPv4" },
    { 6, "IPv6" },
    { 0, NULL }
};

static const val64_string masque_qp_reason_vals[] = {
    { 0x00, "Default" },
    { 0x01, "Too Short" },
    { 0x02, "Conflict" },
    { 0, NULL }
};

/* QUIC-aware proxying capsule kinds, in libloc's numbering. */
typedef enum {
    QP_REGISTER_CLIENT_CID,
    QP_REGISTER_TARGET_CID,
    QP_ACK_CLIENT_CID,
    QP_ACK_CLIENT_VCID,
    QP_ACK_TARGET_CID,
    QP_REJECT_CLIENT_CID,
    QP_REJECT_TARGET_CID,
    QP_CLOSE_CLIENT_CID,            /* RETIRE_CLIENT_CID in draft 10 */
    QP_CLOSE_TARGET_CID,            /* RETIRE_TARGET_CID in draft 10 */
    QP_MAX_CONNECTION_IDS,
    QP_MAX_CLIENT_CIDS,
    QP_MAX_TARGET_CIDS,
    QP_NEW_TARGET_VCID,
    QP_NEW_CLIENT_VCID,
    QP_REJECT_CLIENT_VCID,
    QP_RETIRE_TARGET_VCID,
    QP_RETIRE_CLIENT_VCID,
} masque_qp_kind_t;

/* Draft 09: 0xffe800 + kind. */
static const masque_qp_kind_t masque_qp09_kinds[CAPSULE_QP09_COUNT] = {
    QP_REGISTER_CLIENT_CID, QP_REGISTER_TARGET_CID, QP_ACK_CLIENT_CID,
    QP_ACK_CLIENT_VCID, QP_ACK_TARGET_CID, QP_REJECT_CLIENT_CID,
    QP_REJECT_TARGET_CID, QP_CLOSE_CLIENT_CID, QP_CLOSE_TARGET_CID,
    QP_MAX_CONNECTION_IDS,
};

/* Draft 10, Table 4. */
static const masque_qp_kind_t masque_qp10_kinds[CAPSULE_QP10_COUNT] = {
    QP_REGISTER_CLIENT_CID, QP_REGISTER_TARGET_CID, QP_ACK_CLIENT_CID,
    QP_ACK_TARGET_CID, QP_REJECT_CLIENT_CID, QP_REJECT_TARGET_CID,
    QP_CLOSE_CLIENT_CID, QP_CLOSE_TARGET_CID, QP_MAX_CLIENT_CIDS,
    QP_MAX_TARGET_CIDS, QP_NEW_TARGET_VCID, QP_NEW_CLIENT_VCID,
    QP_ACK_CLIENT_VCID, QP_REJECT_CLIENT_VCID, QP_RETIRE_TARGET_VCID,
    QP_RETIRE_CLIENT_VCID,
};

static masque_request_t *
masque_request(http_capsule_info_t *info)
{
    masque_request_t *request;

    if (info == NULL || info->request_state == NULL) {
        return NULL;
    }
    request = (masque_request_t *)*info->request_state;
    if (request == NULL) {
        request = wmem_new0(wmem_file_scope(), masque_request_t);
        request->contexts = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        *info->request_state = request;
    }
    return request;
}

static int
masque_add_varint(tvbuff_t *tvb, proto_tree *tree, int offset, int hf, uint64_t *value)
{
    unsigned lenvar;
    uint64_t v;

    proto_tree_add_item_ret_varint(tree, hf, tvb, offset, -1, ENC_VARINT_QUIC, &v, &lenvar);
    if (lenvar == 0) {
        THROW(ReportedBoundsError);
    }
    if (value) {
        *value = v;
    }
    return (int)lenvar;
}

/*
 * An IP Version (8) and, for 4 or 6, an address of that family. Version 0
 * (no address) is valid only where allow_zero says so.
 */
static int
masque_add_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
              int hf_v4, int hf_v6, bool allow_zero, uint8_t *version_out, uint8_t *addr_out)
{
    proto_item *ti;
    uint32_t version;
    int start = offset;

    ti = proto_tree_add_item_ret_uint(tree, hf_masque_ip_version, tvb, offset, 1, ENC_NA, &version);
    offset++;
    if (version == 4) {
        proto_tree_add_item(tree, hf_v4, tvb, offset, 4, ENC_BIG_ENDIAN);
        if (addr_out) {
            tvb_memcpy(tvb, addr_out, offset, 4);
        }
        offset += 4;
    } else if (version == 6) {
        proto_tree_add_item(tree, hf_v6, tvb, offset, 16, ENC_NA);
        if (addr_out) {
            tvb_memcpy(tvb, addr_out, offset, 16);
        }
        offset += 16;
    } else if (version != 0 || !allow_zero) {
        expert_add_info_format(pinfo, ti, &ei_masque_malformed, "Invalid IP Version %u", version);
    }
    if (version_out) {
        *version_out = (uint8_t)version;
    }
    return offset - start;
}

/* RFC 9484, Section 4.7.1 and 4.7.2: Assigned or Requested Addresses. */
static int
dissect_masque_addresses(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    unsigned count = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_item *ti;
        proto_tree *entry_tree;
        uint64_t request_id;
        uint8_t version;
        int start = offset;

        entry_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_masque_entry, &ti,
                                                   "Address %u", ++count);
        offset += masque_add_varint(tvb, entry_tree, offset, hf_masque_request_id, &request_id);
        offset += masque_add_ip(tvb, pinfo, entry_tree, offset, hf_masque_ipv4, hf_masque_ipv6,
                                false, &version, NULL);
        if (version != 4 && version != 6) {
            break;
        }
        proto_tree_add_item(entry_tree, hf_masque_prefix_length, tvb, offset, 1, ENC_NA);
        offset++;
        proto_item_set_len(ti, offset - start);
        proto_item_append_text(ti, ": IPv%u, Request ID %" PRIu64, version, request_id);
    }
    return tvb_captured_length(tvb);
}

/* RFC 9484, Section 4.7.3: IP Address Ranges. */
static int
dissect_masque_route_advertisement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   void *data _U_)
{
    int offset = 0;
    unsigned count = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_item *ti;
        proto_tree *entry_tree;
        uint32_t protocol;
        uint8_t version;
        int start = offset;

        entry_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_masque_entry, &ti,
                                                   "Range %u", ++count);
        offset += masque_add_ip(tvb, pinfo, entry_tree, offset, hf_masque_start_ipv4,
                                hf_masque_start_ipv6, false, &version, NULL);
        if (version == 4) {
            proto_tree_add_item(entry_tree, hf_masque_end_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        } else if (version == 6) {
            proto_tree_add_item(entry_tree, hf_masque_end_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
        } else {
            break;
        }
        proto_tree_add_item_ret_uint(entry_tree, hf_masque_ip_protocol, tvb, offset, 1, ENC_NA,
                                     &protocol);
        offset++;
        proto_item_set_len(ti, offset - start);
        proto_item_append_text(ti, ": IPv%u, protocol %u", version, protocol);
    }
    return tvb_captured_length(tvb);
}

/* draft-ietf-masque-connect-udp-listen-16, Section 3.1. */
static int
dissect_masque_compression_assign(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    masque_request_t *request = masque_request((http_capsule_info_t *)data);
    masque_context_t context = { 0 };
    proto_item *ti;
    uint64_t context_id;
    int offset = 0;

    ti = proto_tree_get_parent(tree);
    offset += masque_add_varint(tvb, tree, offset, hf_masque_context_id, &context_id);
    offset += masque_add_ip(tvb, pinfo, tree, offset, hf_masque_ipv4, hf_masque_ipv6,
                            true, &context.ip_version, context.address);
    if (context.ip_version == 4 || context.ip_version == 6) {
        uint32_t port;

        proto_tree_add_item_ret_uint(tree, hf_masque_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN,
                                     &port);
        context.port = (uint16_t)port;
        offset += 2;
    }
    if (context_id == 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_masque_context_zero, tvb, 0, offset,
                                     "Context ID 0 cannot be assigned");
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_masque_malformed, tvb, offset, -1,
                                     "Unexpected data after the assignment");
    }
    proto_item_append_text(ti, ": Context ID %" PRIu64 " (%s)", context_id,
                           val_to_str_const(context.ip_version, masque_ip_version_vals, "Invalid"));

    if (request && !PINFO_FD_VISITED(pinfo) && context_id != 0) {
        uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
        masque_context_t *stored = wmem_new(wmem_file_scope(), masque_context_t);

        *key = context_id;
        *stored = context;
        wmem_map_insert(request->contexts, key, stored);
    }
    return tvb_captured_length(tvb);
}

/* COMPRESSION_ACK and COMPRESSION_CLOSE carry a Context ID only. */
static int
dissect_masque_compression_context(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   void *data _U_)
{
    uint64_t context_id;
    int offset;

    offset = masque_add_varint(tvb, tree, 0, hf_masque_context_id, &context_id);
    proto_item_append_text(proto_tree_get_parent(tree), ": Context ID %" PRIu64, context_id);
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_masque_malformed, tvb, offset, -1,
                                     "Unexpected data after the Context ID");
    }
    return tvb_captured_length(tvb);
}

/* Domain { Domain Length (i), Domain Name (..) } */
static int
masque_add_domain(tvbuff_t *tvb, proto_tree *tree, int offset, int hf)
{
    uint64_t length;
    int start = offset;

    offset += masque_add_varint(tvb, tree, offset, hf_masque_domain_length, &length);
    if (length > (uint64_t)tvb_reported_length_remaining(tvb, offset)) {
        THROW(ReportedBoundsError);
    }
    proto_tree_add_item(tree, hf, tvb, offset, (int)length, ENC_UTF_8);
    offset += (int)length;
    return offset - start;
}

/* draft-ietf-masque-connect-ip-dns-07, Section 3.4: DNS Configuration. */
static int
dissect_masque_dns_assign(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    uint64_t nameservers, internal, search;
    int offset = 0;

    if (tvb_reported_length(tvb) == 0) {
        proto_item_append_text(proto_tree_get_parent(tree), ": no DNS service");
        return 0;
    }
    offset += masque_add_varint(tvb, tree, offset, hf_masque_dns_nameserver_count, &nameservers);
    for (uint64_t i = 0; i < nameservers; i++) {
        proto_item *ti;
        proto_tree *ns_tree;
        uint64_t count, length;
        int start = offset;

        ns_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_masque_entry, &ti,
                                                "Nameserver %" PRIu64, i + 1);
        proto_tree_add_item(ns_tree, hf_masque_dns_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        offset += masque_add_varint(tvb, ns_tree, offset, hf_masque_dns_ipv4_count, &count);
        for (uint64_t j = 0; j < count; j++) {
            proto_tree_add_item(ns_tree, hf_masque_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        offset += masque_add_varint(tvb, ns_tree, offset, hf_masque_dns_ipv6_count, &count);
        for (uint64_t j = 0; j < count; j++) {
            proto_tree_add_item(ns_tree, hf_masque_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        offset += masque_add_domain(tvb, ns_tree, offset, hf_masque_dns_auth_domain);
        offset += masque_add_varint(tvb, ns_tree, offset, hf_masque_dns_svc_params_length, &length);
        if (length > (uint64_t)tvb_reported_length_remaining(tvb, offset)) {
            THROW(ReportedBoundsError);
        }
        if (length > 0) {
            proto_tree_add_item(ns_tree, hf_masque_dns_svc_params, tvb, offset, (int)length, ENC_NA);
        }
        offset += (int)length;
        proto_item_set_len(ti, offset - start);
    }
    offset += masque_add_varint(tvb, tree, offset, hf_masque_dns_internal_count, &internal);
    for (uint64_t i = 0; i < internal; i++) {
        offset += masque_add_domain(tvb, tree, offset, hf_masque_dns_internal_domain);
    }
    offset += masque_add_varint(tvb, tree, offset, hf_masque_dns_search_count, &search);
    for (uint64_t i = 0; i < search; i++) {
        offset += masque_add_domain(tvb, tree, offset, hf_masque_dns_search_domain);
    }
    proto_item_append_text(proto_tree_get_parent(tree), ": %" PRIu64 " nameserver%s",
                           nameservers, plurality(nameservers, "", "s"));
    return offset;
}

/* draft-ietf-masque-connect-ip-dns-07, Section 4.1: NAT64 Prefixes. */
static int
dissect_masque_pref64(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    while (tvb_reported_length_remaining(tvb, offset) >= 13) {
        proto_tree_add_item(tree, hf_masque_pref64_prefix_length, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_masque_pref64_prefix, tvb, offset + 1, 12, ENC_NA);
        offset += 13;
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_masque_malformed, tvb, offset, -1,
                                     "A NAT64 Prefix is 13 bytes");
    }
    return tvb_captured_length(tvb);
}

/* A Connection ID with a varint length, or the rest of the value. */
static int
masque_add_cid(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_length, int hf_value,
               bool length_prefixed)
{
    uint64_t length;
    int start = offset;

    if (length_prefixed) {
        offset += masque_add_varint(tvb, tree, offset, hf_length, &length);
        if (length > (uint64_t)tvb_reported_length_remaining(tvb, offset)) {
            THROW(ReportedBoundsError);
        }
    } else {
        length = (uint64_t)tvb_reported_length_remaining(tvb, offset);
    }
    if (length > 0) {
        proto_tree_add_item(tree, hf_value, tvb, offset, (int)length, ENC_NA);
    }
    offset += (int)length;
    return offset - start;
}

static int
dissect_masque_quic_proxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool draft10,
                          masque_qp_kind_t kind)
{
    int offset = 0;

    if (!draft10) {
        switch (kind) {
        case QP_REGISTER_CLIENT_CID:
        case QP_REJECT_CLIENT_CID:
        case QP_REJECT_TARGET_CID:
        case QP_CLOSE_CLIENT_CID:
        case QP_CLOSE_TARGET_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_reason, NULL);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_cid, false);
            break;
        case QP_REGISTER_TARGET_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_reason, NULL);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_cid_length, hf_masque_qp_cid, true);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_srt_length, hf_masque_qp_srt, true);
            break;
        case QP_ACK_CLIENT_CID:
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_cid_length, hf_masque_qp_cid, true);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_vcid_length, hf_masque_qp_vcid, true);
            break;
        case QP_ACK_CLIENT_VCID:
        case QP_ACK_TARGET_CID:
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_cid_length, hf_masque_qp_cid, true);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_vcid_length, hf_masque_qp_vcid, true);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_srt_length, hf_masque_qp_srt, true);
            break;
        case QP_MAX_CONNECTION_IDS:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_max_ids, NULL);
            break;
        default:
            break;
        }
    } else {
        switch (kind) {
        case QP_REGISTER_CLIENT_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_cid, false);
            break;
        case QP_REGISTER_TARGET_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_cid_length, hf_masque_qp_cid, true);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_srt, false);
            break;
        case QP_ACK_CLIENT_CID:
        case QP_ACK_TARGET_CID:
        case QP_CLOSE_CLIENT_CID:
        case QP_CLOSE_TARGET_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            break;
        case QP_REJECT_CLIENT_CID:
        case QP_REJECT_TARGET_CID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_reason, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            break;
        case QP_MAX_CLIENT_CIDS:
        case QP_MAX_TARGET_CIDS:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_max_ids, NULL);
            break;
        case QP_NEW_TARGET_VCID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_vcid_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_retire_prior_to, NULL);
            offset += masque_add_cid(tvb, tree, offset, hf_masque_qp_vcid_length, hf_masque_qp_vcid, true);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_srt, false);
            break;
        case QP_NEW_CLIENT_VCID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_vcid_sequence, NULL);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_vcid, false);
            break;
        case QP_ACK_CLIENT_VCID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_vcid_sequence, NULL);
            offset += masque_add_cid(tvb, tree, offset, -1, hf_masque_qp_srt, false);
            break;
        case QP_REJECT_CLIENT_VCID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_reason, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_vcid_sequence, NULL);
            break;
        case QP_RETIRE_TARGET_VCID:
        case QP_RETIRE_CLIENT_VCID:
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_sequence, NULL);
            offset += masque_add_varint(tvb, tree, offset, hf_masque_qp_vcid_sequence, NULL);
            break;
        default:
            break;
        }
    }
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert_format(tree, pinfo, &ei_masque_malformed, tvb, offset, -1,
                                     "Unexpected data at the end of the capsule");
    }
    return tvb_captured_length(tvb);
}

static int
dissect_masque_qp09(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_,
                    void *cb_data)
{
    return dissect_masque_quic_proxy(tvb, pinfo, tree, false,
                                     masque_qp09_kinds[GPOINTER_TO_UINT(cb_data)]);
}

static int
dissect_masque_qp10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_,
                    void *cb_data)
{
    return dissect_masque_quic_proxy(tvb, pinfo, tree, true,
                                     masque_qp10_kinds[GPOINTER_TO_UINT(cb_data)]);
}

/*
 * The target of a connect-udp request, from the default URI template
 * "/.well-known/masque/udp/{target_host}/{target_port}/" (RFC 9298, Section 2).
 */
static bool
masque_udp_target(wmem_allocator_t *scope, const char *path, const char **host, uint16_t *port)
{
    static const char prefix[] = "/.well-known/masque/udp/";
    char **parts;

    if (path == NULL || strncmp(path, prefix, strlen(prefix)) != 0) {
        return false;
    }
    parts = wmem_strsplit(scope, path + strlen(prefix), "/", 3);
    if (parts[0] == NULL || parts[1] == NULL) {
        return false;
    }
    *host = parts[0];
    /* A bound request may use the wildcard "*" (percent-encoded) instead. */
    if (!ws_strtou16(parts[1], NULL, port)) {
        *port = 0;
    }
    return true;
}

/* The wildcard target of a bound UDP proxying request. */
static bool
masque_is_wildcard(const char *host)
{
    return host && (strcmp(host, "%2A") == 0 || strcmp(host, "%2a") == 0 ||
                    strcmp(host, "*") == 0);
}

static void
masque_dissect_udp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           proto_tree *masque_tree, uint16_t port)
{
    if (masque_try_udp_port && port != 0 &&
        dissector_try_uint(udp_port_table, port, tvb, pinfo, tree)) {
        return;
    }
    proto_tree_add_item(masque_tree, hf_masque_payload, tvb, 0, -1, ENC_NA);
}

/* The payload of an HTTP Datagram on a MASQUE request. */
static int
dissect_masque_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    http_capsule_info_t *info = (http_capsule_info_t *)data;
    const char *protocol = info ? info->protocol : NULL;
    proto_item *ti;
    proto_tree *masque_tree;
    uint64_t context_id;
    int offset;
    tvbuff_t *payload_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MASQUE");
    ti = proto_tree_add_item(tree, proto_masque, tvb, 0, -1, ENC_NA);
    masque_tree = proto_item_add_subtree(ti, ett_masque);
    if (protocol) {
        proto_item_append_text(ti, ", %s", protocol);
    }
    offset = masque_add_varint(tvb, masque_tree, 0, hf_masque_context_id, &context_id);
    payload_tvb = tvb_new_subset_remaining(tvb, offset);

    if (protocol && strcmp(protocol, "connect-udp") == 0) {
        masque_request_t *request = masque_request(info);
        const char *host = NULL;
        uint16_t port = 0;

        if (context_id == 0) {
            if (masque_udp_target(pinfo->pool, info->path, &host, &port)) {
                ti = proto_tree_add_string(masque_tree, hf_masque_target_host, tvb, 0, 0, host);
                proto_item_set_generated(ti);
                if (port != 0) {
                    ti = proto_tree_add_uint(masque_tree, hf_masque_target_port, tvb, 0, 0, port);
                    proto_item_set_generated(ti);
                }
            }
            if (info->connect_udp_bind && masque_is_wildcard(host)) {
                proto_tree_add_expert_format(masque_tree, pinfo, &ei_masque_context_zero, tvb, 0,
                                             offset, "Context ID 0 cannot be used on a "
                                             "wildcard bound UDP request");
            }
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "UDP Proxying Payload (%d bytes)",
                                tvb_reported_length(payload_tvb));
            masque_dissect_udp_payload(payload_tvb, pinfo, tree, masque_tree, port);
            return tvb_captured_length(tvb);
        }

        masque_context_t *context = request ? (masque_context_t *)
            wmem_map_lookup(request->contexts, &context_id) : NULL;

        if (context == NULL) {
            proto_tree_add_expert(masque_tree, pinfo, &ei_masque_unknown_context, tvb, 0, offset);
            proto_tree_add_item(masque_tree, hf_masque_payload, payload_tvb, 0, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }
        if (context->ip_version == 0) {
            /* draft-ietf-masque-connect-udp-listen-16, Section 4, Figure 4. */
            uint8_t version;
            uint32_t udp_port;
            int header = masque_add_ip(payload_tvb, pinfo, masque_tree, 0, hf_masque_ipv4,
                                       hf_masque_ipv6, false, &version, NULL);

            proto_tree_add_item_ret_uint(masque_tree, hf_masque_udp_port, payload_tvb, header, 2,
                                         ENC_BIG_ENDIAN, &udp_port);
            header += 2;
            port = (uint16_t)udp_port;
            payload_tvb = tvb_new_subset_remaining(payload_tvb, header);
        } else {
            port = context->port;
            if (context->ip_version == 4) {
                ws_in4_addr v4;

                memcpy(&v4, context->address, 4);
                ti = proto_tree_add_ipv4(masque_tree, hf_masque_ipv4, tvb, 0, 0, v4);
            } else {
                ti = proto_tree_add_ipv6(masque_tree, hf_masque_ipv6, tvb, 0, 0,
                                         (const ws_in6_addr *)context->address);
            }
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(masque_tree, hf_masque_udp_port, tvb, 0, 0, port);
            proto_item_set_generated(ti);
        }
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                            "Bound UDP Payload (Context ID %" PRIu64 ", port %u)",
                            context_id, port);
        masque_dissect_udp_payload(payload_tvb, pinfo, tree, masque_tree, port);
        return tvb_captured_length(tvb);
    }

    if (context_id != 0) {
        /* Registered by an extension that is not dissected here. */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Context ID %" PRIu64, context_id);
        proto_tree_add_item(masque_tree, hf_masque_payload, payload_tvb, 0, -1, ENC_NA);
        return tvb_captured_length(tvb);
    }
    if (protocol && strcmp(protocol, "connect-ip") == 0 &&
        tvb_reported_length(payload_tvb) > 0) {
        /* RFC 9484, Section 6: a full IP packet. */
        uint8_t version = tvb_get_uint8(payload_tvb, 0) >> 4;

        if (version == 4 || version == 6) {
            call_dissector(version == 4 ? ip_handle : ipv6_handle, payload_tvb, pinfo, tree);
            return tvb_captured_length(tvb);
        }
    } else if (protocol && strcmp(protocol, "connect-ethernet") == 0) {
        call_dissector(eth_handle, payload_tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }
    proto_tree_add_item(masque_tree, hf_masque_payload, payload_tvb, 0, -1, ENC_NA);
    return tvb_captured_length(tvb);
}

void
proto_register_masque(void)
{
    static hf_register_info hf[] = {
        { &hf_masque_context_id,
          { "Context ID", "masque.context_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_payload,
          { "Payload", "masque.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_target_host,
          { "Target Host", "masque.target.host",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "From the request's URI template", HFILL }
        },
        { &hf_masque_target_port,
          { "Target Port", "masque.target.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "From the request's URI template", HFILL }
        },
        { &hf_masque_ip_version,
          { "IP Version", "masque.ip.version",
            FT_UINT8, BASE_DEC, VALS(masque_ip_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_masque_ipv4,
          { "IP Address", "masque.ip.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_ipv6,
          { "IP Address", "masque.ip.addr6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_udp_port,
          { "UDP Port", "masque.udp.port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_request_id,
          { "Request ID", "masque.request_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_prefix_length,
          { "IP Prefix Length", "masque.ip.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_start_ipv4,
          { "Start IP Address", "masque.route.start",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_start_ipv6,
          { "Start IP Address", "masque.route.start6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_end_ipv4,
          { "End IP Address", "masque.route.end",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_end_ipv6,
          { "End IP Address", "masque.route.end6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_ip_protocol,
          { "IP Protocol", "masque.route.ip_protocol",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
            "0 allows all protocols", HFILL }
        },
        { &hf_masque_dns_nameserver_count,
          { "Nameserver Count", "masque.dns.nameserver_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_priority,
          { "Service Priority", "masque.dns.priority",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_ipv4_count,
          { "IPv4 Address Count", "masque.dns.ipv4_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_ipv6_count,
          { "IPv6 Address Count", "masque.dns.ipv6_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_auth_domain,
          { "Authentication Domain Name", "masque.dns.auth_domain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_svc_params_length,
          { "Service Parameters Length", "masque.dns.svc_params_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_svc_params,
          { "Service Parameters", "masque.dns.svc_params",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "SvcParams in the wire format of RFC 9460", HFILL }
        },
        { &hf_masque_dns_internal_count,
          { "Internal Domain Count", "masque.dns.internal_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_search_count,
          { "Search Domain Count", "masque.dns.search_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_internal_domain,
          { "Internal Domain", "masque.dns.internal_domain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_dns_search_domain,
          { "Search Domain", "masque.dns.search_domain",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_domain_length,
          { "Domain Length", "masque.dns.domain_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_pref64_prefix_length,
          { "Prefix Length", "masque.pref64.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_pref64_prefix,
          { "Prefix", "masque.pref64.prefix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The highest 96 bits of the NAT64 prefix", HFILL }
        },
        { &hf_masque_qp_sequence,
          { "Connection ID Sequence Number", "masque.qp.sequence",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_vcid_sequence,
          { "Virtual Connection ID Sequence Number", "masque.qp.vcid_sequence",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_retire_prior_to,
          { "Retire Prior To", "masque.qp.retire_prior_to",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_reason,
          { "Reason", "masque.qp.reason",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(masque_qp_reason_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_cid_length,
          { "Connection ID Length", "masque.qp.cid_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_cid,
          { "Connection ID", "masque.qp.cid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_vcid_length,
          { "Virtual Connection ID Length", "masque.qp.vcid_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_vcid,
          { "Virtual Connection ID", "masque.qp.vcid",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_srt_length,
          { "Stateless Reset Token Length", "masque.qp.srt_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_srt,
          { "Stateless Reset Token", "masque.qp.srt",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_masque_qp_max_ids,
          { "Maximum Connection IDs", "masque.qp.max_ids",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_masque,
        &ett_masque_entry,
    };

    static ei_register_info ei[] = {
        { &ei_masque_malformed,
          { "masque.malformed", PI_MALFORMED, PI_WARN,
            "Malformed MASQUE capsule or datagram", EXPFILL }
        },
        { &ei_masque_unknown_context,
          { "masque.context_id.unknown", PI_SEQUENCE, PI_NOTE,
            "Context ID not registered by a capsule seen so far", EXPFILL }
        },
        { &ei_masque_context_zero,
          { "masque.context_id.zero", PI_PROTOCOL, PI_WARN,
            "Context ID 0 is not allowed here", EXPFILL }
        },
    };

    module_t *masque_module;
    expert_module_t *expert_masque;

    proto_masque = proto_register_protocol("Multiplexed Application Substrate over QUIC "
                                           "Encryption", "MASQUE", "masque");
    proto_register_field_array(proto_masque, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_masque = expert_register_protocol(proto_masque);
    expert_register_field_array(expert_masque, ei, array_length(ei));

    masque_module = prefs_register_protocol(proto_masque, NULL);
    prefs_register_bool_preference(masque_module, "try_udp_port",
        "Dissect proxied UDP payloads by target port",
        "Whether to hand UDP payloads of connect-udp requests to the dissector "
        "registered for the target's UDP port",
        &masque_try_udp_port);

    masque_datagram_handle = register_dissector("masque.datagram", dissect_masque_datagram,
                                                proto_masque);
}

void
proto_reg_handoff_masque(void)
{
    static const char *const protocols[] = {
        "connect-udp", "connect-ip", "connect-ethernet",
    };

    for (unsigned i = 0; i < array_length(protocols); i++) {
        dissector_add_string("http.connect.datagram", protocols[i], masque_datagram_handle);
    }

    dissector_add_uint("capsule.type", CAPSULE_ADDRESS_ASSIGN,
                       create_dissector_handle(dissect_masque_addresses, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_ADDRESS_REQUEST,
                       create_dissector_handle(dissect_masque_addresses, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_ROUTE_ADVERTISEMENT,
                       create_dissector_handle(dissect_masque_route_advertisement, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_COMPRESSION_ASSIGN,
                       create_dissector_handle(dissect_masque_compression_assign, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_COMPRESSION_ACK,
                       create_dissector_handle(dissect_masque_compression_context, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_COMPRESSION_CLOSE,
                       create_dissector_handle(dissect_masque_compression_context, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_DNS_ASSIGN,
                       create_dissector_handle(dissect_masque_dns_assign, proto_masque));
    dissector_add_uint("capsule.type", CAPSULE_PREF64,
                       create_dissector_handle(dissect_masque_pref64, proto_masque));
    for (unsigned i = 0; i < CAPSULE_QP09_COUNT; i++) {
        dissector_add_uint("capsule.type", CAPSULE_QP09_BASE + i,
                           create_dissector_handle_with_data(dissect_masque_qp09, proto_masque,
                                                             GUINT_TO_POINTER(i)));
    }
    for (unsigned i = 0; i < CAPSULE_QP10_COUNT; i++) {
        dissector_add_uint("capsule.type", CAPSULE_QP10_BASE + i,
                           create_dissector_handle_with_data(dissect_masque_qp10, proto_masque,
                                                             GUINT_TO_POINTER(i)));
    }

    ip_handle = find_dissector_add_dependency("ip", proto_masque);
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_masque);
    eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_masque);
    udp_port_table = find_dissector_table("udp.port");
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
