pkglib_LTLIBRARIES = 		\
	libdcplugin_logger.la	\
        libdcplugin_validate.la	\
        libdcplugin_blacklist.la	\
        libdcplugin_empty_aaaa.la	\
        libdcplugin_all_in_one.la

libdcplugin_logger_la_LIBTOOLFLAGS = --tag=disable-static
libdcplugin_logger_la_SOURCES = logger.c common.c
libdcplugin_logger_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        -avoid-version \
        -export-dynamic \
        -module \
        -no-undefined
libdcplugin_logger_la_CPPFLAGS = \
        $(LTDLINCL) \
        -I../../include

libdcplugin_validate_la_LIBTOOLFLAGS = --tag=disable-static
libdcplugin_validate_la_SOURCES = validate.c common.c
libdcplugin_validate_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        -avoid-version \
        -export-dynamic \
        -module \
        -no-undefined
libdcplugin_validate_la_CPPFLAGS = \
        $(LTDLINCL) \
        -I../../include

libdcplugin_blacklist_la_LIBTOOLFLAGS = --tag=disable-static
libdcplugin_blacklist_la_SOURCES = blacklist.c common.c
libdcplugin_blacklist_la_LIBADD = @LDNS_LIBS@
libdcplugin_blacklist_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        -avoid-version \
        -export-dynamic \
        -module \
        -no-undefined
libdcplugin_blacklist_la_CPPFLAGS = \
        $(LTDLINCL) \
        -I../../include

libdcplugin_empty_aaaa_la_LIBTOOLFLAGS = --tag=disable-static
libdcplugin_empty_aaaa_la_SOURCES = empty-aaaa.c
libdcplugin_empty_aaaa_la_LIBADD = @LDNS_LIBS@
libdcplugin_empty_aaaa_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        -avoid-version \
        -export-dynamic \
        -module \
        -no-undefined
libdcplugin_empty_aaaa_la_CPPFLAGS = \
        $(LTDLINCL) \
        -I../../include

libdcplugin_all_in_one_la_LIBTOOLFLAGS = --tag=disable-static
libdcplugin_all_in_one_la_SOURCES = all-in-one.c
libdcplugin_all_in_one_la_LIBADD = @LDNS_LIBS@
libdcplugin_all_in_one_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        -avoid-version \
        -export-dynamic \
        -module \
        -no-undefined
libdcplugin_all_in_one_la_CPPFLAGS = \
        $(LTDLINCL) \
        -I../../include

collect: all
	mkdir -p .built-so
	cp -v .libs/*.so .built-so

# FIXME: correct lib dir
refresh: collect
	cd .built-so && sudo cp -v *.so /usr/lib64/dnscrypt-proxy
