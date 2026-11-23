/* packet-http-capsule.h
 * HTTP Capsule Protocol (RFC 9297) handoff
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_HTTP_CAPSULE_H__
#define __PACKET_HTTP_CAPSULE_H__

#include <epan/packet.h>

/*
 * Passed as the "data" argument to the "capsule" dissector, and on to
 * the dissectors registered in the "capsule.type" table.
 */
typedef struct _http_capsule_info {
    /* The upgrade token of the extended CONNECT request (":protocol"), if any. */
    const char         *protocol;
    /*
     * Dissects the payload of a DATAGRAM capsule (RFC 9297, Section 3.5), the
     * same as the payload of an HTTP Datagram on this request stream. NULL
     * shows the payload as data.
     */
    dissector_handle_t  datagram_handle;
    void               *datagram_data;
    bool                from_server;
} http_capsule_info_t;

#endif /* __PACKET_HTTP_CAPSULE_H__ */
