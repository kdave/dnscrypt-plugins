/*
 * Logging plugin for dnscrypt
 *
 * Based on dnscrypt-proxy/src/plugins/example-logging/example-logging.c
 * further enhanced
 *
 * Usage:
 * # dnscrypt-proxy --plugin=libdcplugin_logger.so,/var/log/dnscrypt-query.log
 *
 * Output:
 * 2001-02-03 12:34:56 (981200096) - example.com   [A]
 */

#include <dnscrypt/plugin.h>

#include <ctype.h>
#include <stdio.h>
#include <time.h>

#include "common.h"

#ifndef MERGED

DCPLUGIN_MAIN(__FILE__);

#define PLUGIN_VERSION 8

#ifndef putc_unlocked
# define putc_unlocked(c, stream) putc((c), (stream))
#endif

const char *dcplugin_description(DCPlugin * const dcplugin)
{
	return "Log client queries";
}

const char *dcplugin_long_description(DCPlugin * const dcplugin)
{
	return
	    "Log client queries\n"
	    "\n"
	    "This plugin logs the client queries to the log file, with timestamps\n"
	    "\n"
	    "  # dnscrypt-proxy --plugin=libdcplugin_logger.so,/var/log/dnscrypt-query.log";
}

int dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
	FILE *fp;

	if (argc != 2U) {
		return -1;
	} else {
		if ((fp = fopen(argv[1], "a")) == NULL) {
			return -1;
		}
	}
	dcplugin_set_user_data(dcplugin, fp);

	dccommon_print_ts(fp);
	fprintf(fp, "Logger plugin initialized (V%d)\n", PLUGIN_VERSION);
	fflush(fp);

	return 0;
}

int dcplugin_destroy(DCPlugin * const dcplugin)
{
	FILE *const fp = dcplugin_get_user_data(dcplugin);

	dccommon_print_ts(fp);
	fputs("Logger plugin finished\n", fp);
	fflush(fp);
	fclose(fp);

	return 0;
}

#endif	/* MERGED */

static int string_fprint(FILE * const fp, const unsigned char *str,
		const size_t size)
{
	int c;
	size_t i = (size_t)0U;

	while (i < size) {
		c = (int) str[i++];
		if (!isprint(c)) {
			fprintf(fp, "\\x%02x", (unsigned int) c);
		} else if (c == '\\') {
			putc_unlocked(c, fp);
		}
		putc_unlocked(c, fp);
	}

	return 0;
}

static DCPluginSyncFilterResult logger_sync_pre(DCPlugin * dcplugin,
		DCPluginDNSPacket * dcp_packet)
{
	FILE *fp = dcplugin_get_user_data(dcplugin);
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

	if (wire_data_len < 15U || wire_data[4] != 0U
	    || wire_data[5] != 1U) {
		return DCP_SYNC_FILTER_RESULT_ERROR;
	}
	dccommon_print_ts(fp);
	/* fprintf(fp, "L=%d ", wire_data_len); */

	if (wire_data[i] == 0U)
		putc_unlocked('.', fp);

	while (i < wire_data_len && (csize = wire_data[i]) != 0U &&
	       csize < wire_data_len - i) {
		i++;
		if (first != 0)
			first = 0;
		else
			putc_unlocked('.', fp);
		string_fprint(fp, &wire_data[i], csize);
		i += csize;
	}
	type = 0U;
	if (i < wire_data_len - 2U) {
		type = (wire_data[i + 1U] << 8) + wire_data[i + 2U];
		i += 2;
	}

	switch (type) {
	case 0x01: fputs("\t[A]", fp); break;
	case 0x02: fputs("\t[NS]", fp); break;
	case 0x05: fputs("\t[CNAME]", fp); break;
	case 0x06: fputs("\t[SOA]", fp); break;
	case 0x0c: fputs("\t[PTR]", fp); break;
	case 0x0f: fputs("\t[MX]", fp); break;
	case 0x10: fputs("\t[TXT]", fp); break;
	case 0x18: fputs("\t[SIG]", fp); break;
	case 0x19: fputs("\t[KEY]", fp); break;
	case 0x1c: fputs("\t[AAAA]", fp); break;
	case 0x21: fputs("\t[SRV]", fp); break;
	case 0x2B: fputs("\t[DS]", fp); break;
	case 0x2E: fputs("\t[RRSIG]", fp); break;
	case 0x2F: fputs("\t[NSEC]", fp); break;
	case 0x30: fputs("\t[DNSKEY]", fp); break;
	case 0x32: fputs("\t[NSEC3]", fp); break;
	default:
		fprintf(fp, "\t[0x%02hX]", type);
	}

	/*
	if (i < wire_data_len - 2U) {
		class = (wire_data[i + 1U] << 8) + wire_data[i + 2U];
		i += 2;
		if (class == 0x01) {
			fputs(" IN", fp);
		}
	} else {
		fputs(" !CLASS", fp);
	}

	if (i < wire_data_len - 4U) {
		ttl =   (wire_data[i + 1U] << 24) +
			(wire_data[i + 2U] << 16) +
			(wire_data[i + 3U] <<  8) +
			 wire_data[i + 4U];
		i += 4;
		fprintf(fp, " TTL=%u", ttl);
	} else {
		fputs(" !TTL", fp);
	}

	if (i < wire_data_len - 2U) {
		rdlength = (wire_data[i + 1U] << 8) + wire_data[i + 2U];
		i += 2;
		fprintf(fp, " RDL=%u", rdlength);
	} else {
		fputs(" !RDL", fp);
	}

	fprintf(fp, " REM=%d\n", wire_data_len - i);

	if (i < wire_data_len - rdlength) {
		i += rdlength;
	}
	*/

	fputc('\n', fp);
	fflush(fp);

	return DCP_SYNC_FILTER_RESULT_OK;
}

#ifndef MERGED

DCPluginSyncFilterResult dcplugin_sync_pre_filter(DCPlugin * dcplugin,
		DCPluginDNSPacket * dcp_packet)
{
	return logger_sync_pre(dcplugin, dcp_packet);
}

DCPluginSyncFilterResult dcplugin_sync_post_filter(DCPlugin * dcplugin,
		DCPluginDNSPacket * dcp_packet)
{
	return DCP_SYNC_FILTER_RESULT_OK;
}

#endif	/* MERGED */
