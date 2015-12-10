/*
 * Combined functionality into one plugin
 */

#define MERGED

#include <dnscrypt/plugin.h>
#include "common.h"

#include "blacklist.c"
#include "empty-aaaa.c"
#include "logger.c"
#include "validate.c"

DCPLUGIN_MAIN(__FILE__);

const char *dcplugin_description(DCPlugin *const dcplugin)
{
	return "All-in-one plugin: validate, empty-aaaa, logger, blacklist";
}

const char *dcplugin_long_description(DCPlugin *const dcplugin)
{
	return
	    "All-in-one plugin: validate, empty-aaaa, logger, blacklist";
	    "\n"
	    "blah\n"
	    "\n"
	    "# dnscrypt-proxy --plugin=libdcplugin_all_in_one.so";
}

int dcplugin_init(DCPlugin *const dcplugin, int argc, char *argv[])
{
	return 0;
}

int dcplugin_destroy(DCPlugin *const dcplugin)
{
	return 0;
}

