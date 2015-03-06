#include <time.h>
#include "common.h"

void dccommon_print_ts(FILE *fp)
{
	struct tm *tm;
	time_t now;
	char buf[128];

	now = time(NULL);
	tm = localtime(&now);

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S (%s) - ", tm);
	fputs(buf, fp);
}

