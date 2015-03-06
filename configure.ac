AC_INIT([dnscrypt-plugins], [0.1])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
AC_PROG_CC

AC_CHECK_HEADERS([dnscrypt/plugin.h])

use_ldns=no
AC_CHECK_HEADER([ldns/ldns.h], [
  AC_CHECK_LIB(ldns, ldns_wire2pkt, [
    AC_DEFINE(USE_LDNS,[1],[define to use the ldns library])
    LDNS_LIBS=-lldns
    use_ldns=yes
  ])
], [ ],
[#include <sys/types.h>
 #include <stdlib.h>
 #include <stdint.h>
 #ifdef HAVE_WS2TCPIP_H
 # include <ws2tcpip.h>
 #endif
])
AM_CONDITIONAL(USE_LDNS, test x$use_ldns = xyes)
AC_SUBST([LDNS_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
