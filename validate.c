/*
 * DNS name validating plugin for dnscrypt
 *
 * Validate query against RFC 1035 specification, section 2.3.1,
 * or return NXDOMAIN
 *
 * Useful eg. to prevent resolving user@host.typo unless caught by other means.
 */

#include <dnscrypt/plugin.h>

#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <ldns/ldns.h>

#include "common.h"

DCPLUGIN_MAIN(__FILE__);

#undef DEBUG_OUTPUT

#define PLUGIN_VERSION 1

#ifndef putc_unlocked
# define putc_unlocked(c, stream) putc((c), (stream))
#endif

const char *dcplugin_description(DCPlugin *const dcplugin)
{
	return "Validate queries against RFC 1035";
}

const char *dcplugin_long_description(DCPlugin *const dcplugin)
{
	return
	    "Validate queries against RFC 1035"
	    "\n"
	    "blah\n"
	    "\n"
	    "# dnscrypt-proxy --plugin=libdcplugin_validate.so";
}

int dcplugin_init(DCPlugin *const dcplugin, int argc, char *argv[])
{
#ifdef DEBUG_OUTPUT
	FILE *fp;

	if ((fp = fopen("/tmp/valid.txt", "a")) == NULL) {
		return -1;
	}
	dcplugin_set_user_data(dcplugin, fp);

	dccommon_print_ts(fp);
	fprintf(fp, "Validating plugin initialized (V%d)\n", PLUGIN_VERSION);
	fflush(fp);
#endif

	return 0;
}

int dcplugin_destroy(DCPlugin *const dcplugin)
{
#ifdef DEBUG_OUTPUT
	FILE *const fp = dcplugin_get_user_data(dcplugin);

	dccommon_print_ts(fp);
	fputs("Validating plugin finished\n", fp);
	fflush(fp);
	fclose(fp);
#endif

	return 0;
}

static int validate(const unsigned char *str, const size_t size, int first)
{
	int i;

	for (i = 0; i < size; i++) {
		switch (str[i]) {
		case '-':	if (!first) return 0;
		case 'a'...'z':
		case 'A'...'Z':
		case '0'...'9':	break;
		default:	return 0;
		}
	}

	return 1;
}

DCPluginSyncFilterResult dcplugin_sync_pre_filter(DCPlugin *dcplugin,
		DCPluginDNSPacket *dcp_packet)
{
#ifdef DEBUG_OUTPUT
	FILE *fp = dcplugin_get_user_data(dcplugin);
#endif
	const unsigned char *wire_data =
	    dcplugin_get_wire_data(dcp_packet);
	size_t wire_data_len = dcplugin_get_wire_data_len(dcp_packet);
	size_t i = (size_t)12U;
	size_t csize = (size_t)0U;
	unsigned short type;
	unsigned char c;
	int first = 1;
	unsigned class = 0;
	unsigned ttl = 0;
	unsigned rdlength = 0;

#ifdef DEBUG_OUTPUT
	fprintf(fp, "pre-filter\n");
#endif

	if (wire_data_len < 15U || wire_data[4] != 0U
	    || wire_data[5] != 1U) {
		return DCP_SYNC_FILTER_RESULT_ERROR;
	}

	if (wire_data[i] == 0U)
		return DCP_SYNC_FILTER_RESULT_OK;

#ifdef DEBUG_OUTPUT
	dccommon_print_ts(fp);
#endif

	while (i < wire_data_len && (csize = wire_data[i]) != 0U &&
	       csize < wire_data_len - i) {
		int j;

		i++;
#ifdef DEBUG_OUTPUT
		fprintf(fp, "validate ");
		for (j = 0; j < csize; j++)
			fputc(wire_data[i + j], fp);
		fputc('\n', fp);
#endif
		if (!validate(&wire_data[i], csize, first)) {
			LDNS_RCODE_SET(dcplugin_get_wire_data(dcp_packet),
					LDNS_RCODE_FORMERR);
#ifdef DEBUG_OUTPUT
			fprintf(fp, "Validation failed\n");
			fflush(fp);
#endif
			return DCP_SYNC_FILTER_RESULT_DIRECT;
		}
		first = 0;
		i += csize;
	}
#ifdef DEBUG_OUTPUT
	fprintf(fp, "Validation OK\n");
	fflush(fp);
#endif

	return DCP_SYNC_FILTER_RESULT_OK;
}

DCPluginSyncFilterResult dcplugin_sync_post_filter(DCPlugin *dcplugin,
		DCPluginDNSPacket *dcp_packet)
{
	return DCP_SYNC_FILTER_RESULT_OK;
}
