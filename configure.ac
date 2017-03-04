#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2012-2017, The Trusted Domain Project.  All rights reserved.

# Acceptable arguments to configure are:
# 	The usual CC= etc.
# 	--with-wall forces CC=gcc -Wall

# SPF support:
# Define --with-spf to include either internal OR libspf2 support.  For libspf2
# support, also define these:
#	--with-spf2-include=path
#	--with-spf2-lib=path

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 1)
m4_define([VERSION_MAJOR_REV], 3)
m4_define([VERSION_MINOR_REV], 2)
m4_define([VERSION_PATCH], 0)

#
# Library version
#       - bump "current" and reset "revision" with API changes
#       - bump "revision" with internal source code changes
#

m4_define([LIBVERSION_CURRENT], 2)
m4_define([LIBVERSION_REVISION], 2)
m4_define([LIBVERSION_AGE], 0)

#
# Autotools setup
#
AC_INIT([OpenDMARC], [VERSION_RELEASE.VERSION_MAJOR_REV.VERSION_MINOR_REV], [bcx+libdmarc@bcx.com])
AC_CONFIG_AUX_DIR(build-aux)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS(build-config.h)

AC_CONFIG_MACRO_DIR([m4])

#
# Hexadecimal version, for use in generating dmarc.h
#
HEX_VERSION=$(printf %08x $(( ((VERSION_RELEASE << 8 | VERSION_MAJOR_REV) << 8 | VERSION_MINOR_REV) << 8 | VERSION_PATCH )))
AC_SUBST([HEX_VERSION])

#
# library version, passed to libtool
#
LIBOPENDMARC_VERSION_INFO=$(printf %d:%d:%d LIBVERSION_CURRENT LIBVERSION_REVISION LIBVERSION_AGE)
AC_SUBST([LIBOPENDMARC_VERSION_INFO])

#
# Checks for programs
#
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

AC_ARG_WITH([installdir],
        AC_HELP_STRING([--with-installdir=/path], [(default =/usr/local)]),
		LIBDMARC_BASE=$withval, LIBDMARC_BASE=/usr/local/)
AC_SUBST(LIBDMARC_DIR, $LIBDMARC_BASE)

#
# Check for how to compile threaded stuff
#
AX_PTHREAD


AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS(stdio.h)
AC_CHECK_HEADERS(syslog.h)
AC_CHECK_HEADERS(sysexits.h)
AC_CHECK_HEADERS(poll.h)
AC_CHECK_HEADERS(time.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(errno.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(arpa/inet.h sys/socket.h netdb.h sys/ioctl.h)
AC_CHECK_HEADERS(iso/limits_iso.h)

AC_CHECK_HEADERS([netinet/in.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
])
AC_CHECK_HEADERS([arpa/nameser.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
])
AC_CHECK_HEADERS([resolv.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
])
AC_CHECK_LIB(socket, connect)
AC_CHECK_LIB(resolv, hstrerror, , , [-lnsl -lsocket])
AC_CHECK_LIB(resolv, inet_aton, , , [-lnsl -lsocket])
AC_SEARCH_LIBS(res_ninit, resolv,
	AC_DEFINE(HAVE_RES_NINIT, 1,
	[Define to 1 if you have the `res_ninit()' function.]))
AC_CHECK_LIB(idn, idn_free)
AC_CHECK_LIB(rt, nanosleep)
AC_SEARCH_LIBS(inet_addr, nsl)
AC_SEARCH_LIBS(freehostent, resolv)
AC_SEARCH_LIBS(inet_pton, resolv,
               AC_DEFINE(HAVE_INET_PTON, 1,
                         [Define to 1 if you have the `inet_pton()' function.]))
AC_SEARCH_LIBS(inet_ntop, resolv,
               AC_DEFINE(HAVE_INET_NTOP, 1,
                        [Define to 1 if you have the `inet_ntop()' function.]))
AC_SEARCH_LIBS(getipnodebyname, resolv,
               AC_DEFINE(HAVE_GETADDRINFO, 1,
                         [Define to 1 if you have the `getipnodebyname()' function.]))

AC_HEADER_RESOLV

AC_C_BIGENDIAN
AC_STRUCT_TM
AC_C_CONST
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(unsigned long long)
AC_CHECK_SIZEOF(void *)

AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_SEARCH_LIBS(strlcat, bsd strl,
	AC_DEFINE(HAVE_STRLCAT, 1,
	[Define to 1 if you have the `strlcat()' function.]))
AC_SEARCH_LIBS(strlcpy, bsd strl,
	AC_DEFINE(HAVE_STRLCPY, 1,
	[Define to 1 if you have the `strlcpy()' function.]))

AC_CHECK_FUNCS(basename)
AC_CHECK_FUNCS(syslog)
AC_CHECK_FUNCS(cuserid)
AC_CHECK_FUNCS(memset bzero, break)
AC_CHECK_FUNCS(memcpy bcopy, break)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(strchr)
AC_CHECK_FUNCS(strrchr)
AC_CHECK_FUNCS(strdup)
AC_CHECK_FUNCS(strpbrk)
AC_CHECK_FUNCS(inet_ntoa)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strncasecmp)

AC_CHECK_HEADERS(signal.h)
AC_CHECK_HEADERS(regex.h)

bsdstrl_h_found="no"
strl_h_found="no"
AC_CHECK_HEADERS([bsd/string.h], [bsdstrl_h_found="yes"])
AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])

# we need to include <strl.h> if an installed strl.h was found and no
# bsd/string.h was found
if test x"$strl_h_found" = x"yes" -a x"$bsdstrl_h_found" = x"no"
then
        AC_DEFINE([USE_STRL_H], 1,
                  [Define to 1 if you need to include <strl.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

if test x"$bsdstrl_h_found" = x"yes"
then
        AC_DEFINE([USE_BSD_H], 1,
                  [Define to 1 if you need to include <bsd/string.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

# Use opendmarc strl if neither a system strl nor libbsd are found
if test x"$strl_h_found" = x"no" -a x"$bsdstrl_h_found" = x"no"
then
        AC_DEFINE([USE_DMARCSTRL_H], 1,
                  [Define to 1 if you need to include <opendmarc_strl.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

AC_PROG_LN_S
AC_CHECK_PROG(miltertest, miltertest, "yes", "no")
AC_SUBST(ac_aux_dir)

AC_ARG_WITH([wall],
	AC_HELP_STRING([--with-wall], [(no default)]),
	CC="gcc -Wall",)


#
# See if we will need -lresolv
#
dnscheck='
#include "confdefs.h" 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h> 
int main() {
res_mkquery (0, 0, 0, 0, 0, 0, 0, 0, 0);
dn_expand (0, 0, 0, 0, 0);
dn_skipname (0, 0);
dn_comp (0, 0, 0, 0, 0);
return 0;
}'
AC_MSG_CHECKING([whether the resolver works without -lresolv])
LIBRESOLV=
AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
])] , [
	AC_MSG_RESULT(yes)
] , [
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([whether the resolver works with -lresolv])
	saved_LIBS="$LIBS"
	LIBS=-lresolv
	AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
	])] , [
		AC_MSG_RESULT(yes)
		LIBRESOLV=-lresolv
	] , [
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([need workable resolver library])
	])
	LIBS="$saved_LIBS"
])
AC_SUBST([LIBRESOLV])
 
# 
# --with-sql-backend -- configures some defaults for DB access
# 
AC_ARG_WITH([sql-backend],
            AS_HELP_STRING([--with-sql-backend],
                           [selection of SQL backend in use]),
            [SQL_BACKEND="$withval"], [SQL_BACKEND="mysql"])
if test x"$SQL_BACKEND" = x"yes"
then
	SQL_BACKEND="mysql"
fi
AC_SUBST(SQL_BACKEND)
AC_DEFINE_UNQUOTED(SQL_BACKEND, "$SQL_BACKEND", [default SQL back-end])

AC_ARG_WITH([spf],
	AC_HELP_STRING([--with-spf], [enable SPF checking]),
	AC_DEFINE(WITH_SPF, 1, [Define to 1 if you want SPF support.]),
	[])

AC_ARG_WITH([spf2-include],
	AC_HELP_STRING([--with-spf2-include], [path to libspf2 includes]),
	SPF2_INCLUDE="$withval",
	[])
AC_ARG_WITH([spf2-lib],
	AC_HELP_STRING([--with-spf2-lib], [path to libspf2 libraries]),
	SPF2_LIB="$withval",
	[])
use_spf="no"
if test "x$SPF2_INCLUDE" != "x" -a "x$SPF2_LIB" != "x"
then
	use_spf="yes"
	if test -f ${SPF2_INCLUDE}/spf.h
	then
		AC_DEFINE(HAVE_SPF2_H, 1,
			[Define to 1 if you have libspf2's `spf.h'])
		spf2_include="-I $SPF2_INCLUDE"
		saved_CFLAGS="$CFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CFLAGS="$spf2_include $saved_CFLAGS"
		LDFLAGS="$saved_LDFLAGS -L${SPF2_LIB}"
	fi
	AC_SEARCH_LIBS(SPF_record_new, spf2)
	AC_SEARCH_LIBS(SPF_server_new, spf2)
fi

AM_CONDITIONAL([USE_SPF], [test x"$use_spf" = x"yes"])

#
# opendmarc
# 
AC_ARG_ENABLE([filter],
              AS_HELP_STRING([--disable-filter],
                             [do not compile the opendmarc filter]),
              [enable_filter=$enableval],
              [enable_filter=yes])
AM_CONDITIONAL([BUILD_FILTER], [test x"$enable_filter" != x"no"])

AC_ARG_ENABLE([live-tests],
              AS_HELP_STRING([--enable-live-tests],
                             [enable live unit tests]),
              [enable_live_tests=$enableval],
              [enable_live_tests=no])
AM_CONDITIONAL([LIVE_TESTS], [test x"$enable_live_tests" = x"yes"])

AC_ARG_ENABLE([filter-tests],
              AS_HELP_STRING([--enable-filter-tests],
                             [enable Lua-based filter unit tests]),
              [enable_filter_tests=$enableval],
              [enable_filter_tests=no])
AM_CONDITIONAL([FILTER_TESTS], [test x"$enable_filter_tests" = x"yes"])
if test x"$enable_filter_tests" = x"yes" -a x"$miltertest" != x"yes"
then
	AC_MSG_ERROR([miltertest is required for filter tests])
fi

#
# libmilter
#
AC_MSG_CHECKING([for milter library and includes])
AC_ARG_WITH([milter],
            AS_HELP_STRING([--with-milter],
                           [location of milter includes and library]),
            [milterpath="$withval"], [milterpath="auto"])

if test x"$enable_filter" = x"no"
then
	milterpath="no"
fi

if test "$milterpath" = "auto" -o "$milterpath" = "yes"
then
	milterdirs="/usr/local /opt/local /usr"
	for d in $milterdirs
	do
		if test -f $d/include/libmilter/mfapi.h
		then
			milterpath=$d
			break
		fi
	done
fi
case "$milterpath" in
	no)
		if test x"$enable_filter" = x"yes"
		then
			AC_MSG_ERROR([milter is required])
		fi
		AC_MSG_RESULT(disabled)
		;;
	auto)
		AC_MSG_ERROR([milter not found])
		;;
	*/*)
		if ! test -f $milterpath/include/libmilter/mfapi.h
		then
			AC_MSG_ERROR([milter includes not found at $milterpath])
		fi
		AC_MSG_RESULT([$milterpath])
		;;
	*)
		AC_MSG_ERROR([milter not found])
		;;
esac

LIBMILTER_INCDIRS=""
LIBMILTER_LIBDIRS=""
LIBMILTER_LIBS=""

if test x"$milterpath" != x"no"
then
	LIBMILTER_INCDIRS="-I$milterpath/include"

	saved_CC="$CC"
	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	CC="$PTHREAD_CC"
	LIBS="$PTHREAD_LIBS $saved_LIBS"
	CPPFLAGS="$LIBMILTER_INCDIRS $saved_CPPFLAGS"
	CFLAGS="$PTHREAD_CFLAGS $saved_CFLAGS"
	LDFLAGS="$PTHREAD_CFLAGS $saved_LDFLAGS"

	breakloop="no"
	for d in lib lib/libmilter
	do
		unset ac_cv_search_smfi_register
		LDFLAGS="$PTHREAD_CFLAGS -L$milterpath/$d $saved_LDFLAGS"
		AC_SEARCH_LIBS([smfi_register], [milter],
		               [
		               	LIBMILTER_LIBDIRS="-L$milterpath/$d"
		               	LIBMILTER_LIBS="-lmilter"
		               	breakloop="yes"
		               ])

		AC_CHECK_FUNC([smfi_insheader],
			      AC_DEFINE([HAVE_SMFI_INSHEADER], 1,
					[Define if libmilter has smfi_insheader()]))

		AC_CHECK_FUNC([smfi_opensocket],
			      AC_DEFINE([HAVE_SMFI_OPENSOCKET], 1,
					[Define if libmilter has smfi_opensocket()]))

		AC_CHECK_FUNC([smfi_progress],
			      AC_DEFINE([HAVE_SMFI_PROGRESS], 1,
					[Define if libmilter has smfi_progress()]))

		AC_CHECK_FUNC([smfi_setsymlist],
			      AC_DEFINE([HAVE_SMFI_SETSYMLIST], 1,
					[Define if libmilter has smfi_setsymlist()]))

		AC_CHECK_FUNC([smfi_version],
			      AC_DEFINE([HAVE_SMFI_VERSION], 1,
					[Define if libmilter has smfi_version()]))

		if test x"$breakloop" = x"yes"
		then
			break
		fi
	done
	if test x"$LIBMILTER_LIBDIRS" = x""
	then
		AC_MSG_WARN([libmilter not found])
	fi

	CC="$saved_CC"
	CPPFLAGS="$saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi

AC_SUBST(LIBMILTER_INCDIRS)
AC_SUBST(LIBMILTER_LIBDIRS)
AC_SUBST(LIBMILTER_LIBS)

#
# Final substitutions
# 
CPPFLAGS="$CPPFLAGS -DCONFIG_BASE=\\\"$sysconfdir\\\""
test "x$prefix" = xNONE && prefix=$ac_default_prefix
SYSCONFDIR=`eval echo "$sysconfdir"`
AC_SUBST([SYSCONFDIR])

#
# Generate files
#
AC_OUTPUT([ Makefile
	contrib/Makefile
	contrib/init/Makefile
	contrib/init/generic/Makefile
	contrib/init/redhat/Makefile
		contrib/init/redhat/opendmarc
	contrib/rddmarc/Makefile
	contrib/service/Makefile
		contrib/service/opendmarc.service
	contrib/spec/Makefile
		contrib/spec/opendmarc.spec
	db/Makefile
	docs/Makefile
	libopendmarc/Makefile
	libopendmarc/tests/Makefile
	libopendmarc/tests/testfiles/Makefile
	libopendmarc/docs/Makefile
	opendmarc/Makefile
		opendmarc/opendmarc.conf.5
		opendmarc/opendmarc.8
		opendmarc/opendmarc-check.8
	opendmarc/tests/Makefile
	reports/Makefile
		reports/opendmarc-expire
		reports/opendmarc-expire.8
		reports/opendmarc-import
		reports/opendmarc-import.8
		reports/opendmarc-importstats.8
		reports/opendmarc-params
		reports/opendmarc-params.8
		reports/opendmarc-reports
		reports/opendmarc-reports.8
	])

# @end1
