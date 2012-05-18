#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2012 The OpenDMARC Project.  All rights reserved.
# 
# $Id$

# Acceptable arguments to configure are:
# 	The usual CC= etc.
# 	--with-wall forces CC=gcc -Wall

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 0)
m4_define([VERSION_MAJOR_REV], 1)
m4_define([VERSION_MINOR_REV], 0)
m4_define([VERSION_PATCH], 0)

#
# Library version
#       - bump "current" and reset "revision" with API changes
#       - bump "revision" with internal source code changes
#
m4_define([LIBVERSION_CURRENT], 0)
m4_define([LIBVERSION_REVISION], 1)
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
ACLOCAL_AMFLAGS=-I m4

#
# Hexadecimal version, for use in generating dmarc.h
#
HEX_VERSION=$(printf %08x $(( ((VERSION_RELEASE << 8 | VERSION_MAJOR_REV) << 8 | VERSION_MINOR_REV)
<< 8| VERSION_PATCH )))
AC_SUBST([HEX_VERSION])

#
# library version, passed to libtool
#
LIBOPENDKIM_VERSION_INFO=$(printf %d:%d:%d LIBVERSION_CURRENT LIBVERSION_REVISION LIBVERSION_AGE)
AC_SUBST([LIBOPENDKIM_VERSION_INFO])

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


AC_CHECK_HEADERS(arpa/inet.h sys/socket.h netdb.h sys/ioctl.h)
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
]
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

AC_PROG_LN_S
AC_PROG_RANLIB
AC_SUBST(ac_aux_dir)

AC_ARG_WITH([wall],
	AC_HELP_STRING([--with-wall], [(no default)]),
	CC="gcc -Wall",)

AC_OUTPUT([ Makefile
	docs/Makefile
	libopendmarc/Makefile
	libopendmarc/tests/Makefile
	], [test -z "$CONFIG_HEADERS" || echo timestamp > stamp-h.in])
# @end1
