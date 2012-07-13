SUBDIRS=testfiles
LDADD = ../libopendmarc.la $(LIBRESOLV)
AM_CPPFLAGS = -I..

check_PROGRAMS		 = test_tld test_finddomain \
				test_dmarc_parse test_xml_parse
if LIVE_TESTS
check_PROGRAMS           += test_dns_lookup
endif

test_dns_lookup_SOURCES  = test_dns_lookup.c

test_tld_SOURCES         = test_tld.c

test_finddomain_SOURCES  = test_finddomain.c

test_dmarc_parse_SOURCES = test_dmarc_parse.c

test_xml_parse_SOURCES   = test_xml_parse.c

TESTS = $(check_PROGRAMS)
