INCLUDES		= -I. -I..
lib_LTLIBRARIES = libopendmarc.la
libopendmarc_la_SOURCES	= opendmarc_dns.c \
			  opendmarc_xml.c

test:
	cd tests; $(MAKE) clean
	cd tests; $(MAKE)
	cd tests; $(MAKE) test
