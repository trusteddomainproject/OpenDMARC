INCLUDES		= -I. -I..
lib_LTLIBRARIES = libopendmarc.la
libopendmarc_la_SOURCES	= opendmarc_dns.c \
			  opendmarc_xml.c \
			  opendmarc_tld.c \
			  opendmarc_policy.c \
			  opendmarc_util.c \
			  opendmarc_hash.c

test:
	cd tests; $(MAKE) clean
	cd tests; $(MAKE)
	cd tests; $(MAKE) test
