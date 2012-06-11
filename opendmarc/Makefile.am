# Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.85 2010/10/28 04:12:55 cm-msk Exp $

sbin_PROGRAMS = opendmarc
opendmarc_SOURCES = config.c config.h opendmarc.c opendmarc.h \
	opendmarc-ar.c opendmarc-ar.h opendmarc-config.h
opendmarc_CC = $(PTHREAD_CC)
opendmarc_CFLAGS = $(PTHREAD_CFLAGS) 
opendmarc_CPPFLAGS = $(LIBMILTER_INCDIRS) -I$(srcdir)/../libopendmarc
opendmarc_LDFLAGS = $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS)
opendmarc_LDADD = ../libopendmarc/libopendmarc.la $(LIBMILTER_LIBS) $(PTHREAD_LIBS)

# XXX
# man_MANS = opendmarc.conf.5 opendmarc.8
