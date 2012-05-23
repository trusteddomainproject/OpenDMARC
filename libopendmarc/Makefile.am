
INCLUDES		= -I. -I..
nobase_pkglib_LIBRARIES	= libopendmarc.a
libopendmarc_a_SOURCES	= opendmarc_dns.c \
			  opendmarc_xml.c

test:
	cd tests; $(MAKE) clean
	cd tests; $(MAKE)
	cd tests; $(MAKE) test
