/*
 * Copy of
 * dnscrypt-proxy/src/plugins/example-ldns-aaaa-blocking/example-ldns-aaaa-blocking.c
 *
 * Return empty request to AAAA queries. No parameters.
 */

#include <stdint.h>

#ifdef _WIN32
# include <ws2tcpip.h>
#endif

#include <dnscrypt/plugin.h>
#include <ldns/ldns.h>

#ifndef MERGED

DCPLUGIN_MAIN(__FILE__);

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Directly return an empty response to AAAA queries";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    (void) dcplugin;
    (void) argc;
    (void) argv;

    return 0;
}

#endif	/* MERGED */

static DCPluginSyncFilterResult
empty_aaa_sync_pre(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    ldns_pkt                 *packet;
    ldns_rr_list             *questions;
    uint8_t                  *wire_data;
    DCPluginSyncFilterResult  result = DCP_SYNC_FILTER_RESULT_OK;

    wire_data = dcplugin_get_wire_data(dcp_packet);
    ldns_wire2pkt(&packet, wire_data, dcplugin_get_wire_data_len(dcp_packet));
    if (packet == NULL) {
        return DCP_SYNC_FILTER_RESULT_ERROR;
    }
    questions = ldns_pkt_question(packet);
    if (ldns_rr_list_rr_count(questions) == (size_t) 1U &&
        ldns_rr_get_type(ldns_rr_list_rr(questions,
                                         (size_t) 0U)) == LDNS_RR_TYPE_AAAA) {
        LDNS_QR_SET(wire_data);
        LDNS_RA_SET(wire_data);
        result = DCP_SYNC_FILTER_RESULT_DIRECT;
    }
    ldns_pkt_free(packet);

    return result;
}

#ifndef MERGED

DCPluginSyncFilterResult
dcplugin_sync_pre_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
	return empty_aaa_sync_pre(dcplugin, dcp_packet);
}

#endif
