# Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.
#
# $Id: Makefile.am,v 1.85 2010/10/28 04:12:55 cm-msk Exp $

if FILTER_TESTS
SUBDIRS=tests
endif

dist_doc_DATA = opendmarc.conf.sample

sbin_PROGRAMS = opendmarc opendmarc-check

opendmarc_SOURCES = config.c config.h opendmarc.c opendmarc.h \
	opendmarc-ar.c opendmarc-ar.h opendmarc-config.h \
	opendmarc-dstring.c opendmarc-dstring.h \
	parse.c parse.h test.c test.h util.c util.h
opendmarc_CC = $(PTHREAD_CC)
opendmarc_CFLAGS = $(PTHREAD_CFLAGS) 
opendmarc_CPPFLAGS = $(LIBMILTER_INCDIRS) -I$(srcdir)/../libopendmarc
opendmarc_LDFLAGS = $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS)
opendmarc_LDADD = ../libopendmarc/libopendmarc.la $(LIBMILTER_LIBS) $(PTHREAD_LIBS) $(LIBRESOLV)

opendmarc_check_SOURCES = opendmarc-check.c
opendmarc_check_CPPFLAGS = -I$(srcdir)/../libopendmarc
opendmarc_check_LDADD = ../libopendmarc/libopendmarc.la $(LIBRESOLV)

man_MANS = opendmarc.conf.5 opendmarc.8 opendmarc-check.8
