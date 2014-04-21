SUBDIRS=tests docs
AM_CPPFLAGS = -I. -I..
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
			  opendmarc_spf.c \
			  opendmarc_spf_dns.c \
                          opendmarc_internal.h
libopendmarc_la_LDFLAGS = -version-info $(LIBOPENDMARC_VERSION_INFO)
libopendmarc_includedir = $(includedir)/opendmarc
libopendmarc_include_HEADERS = dmarc.h
