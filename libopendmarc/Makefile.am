SUBDIRS=tests docs
INCLUDES		= -I. -I..
LDADD = ./libopendmarc.la
lib_LTLIBRARIES = libopendmarc.la
libopendmarc_la_SOURCES	= dmarc.h \
                          opendmarc_dns.c \
			  opendmarc_xml.c \
			  opendmarc_tld.c \
			  opendmarc_policy.c \
			  opendmarc_util.c \
			  opendmarc_hash.c \
			  opendmarc_strl.c \
                          opendmarc_strl.h \
                          opendmarc_internal.h
