SUBDIRS=testfiles
LDADD = ../libopendmarc.la $(LIBRESOLV)
AM_CPPFLAGS = -I..

check_PROGRAMS		 = test_tld test_finddomain \
				test_dmarc_parse test_dmarc_fetch test_xml_parse test_alignment
if LIVE_TESTS
check_PROGRAMS           += test_dns_lookup
endif

test_dns_lookup_SOURCES  = test_dns_lookup.c

test_tld_SOURCES         = test_tld.c

test_finddomain_SOURCES  = test_finddomain.c

test_dmarc_parse_SOURCES = test_dmarc_parse.c

test_dmarc_fetch_SOURCES = test_dmarc_fetch.c

test_xml_parse_SOURCES   = test_xml_parse.c

test_xml_alignment_SOURCES   = test_alignment.c

TESTS = $(check_PROGRAMS)

EXTRA_DIST	= testfiles/effective_tld_names.dat \
		  testfiles/126.com!example.com!1337270400!1337356799.20120518126.xml \
		  testfiles/bad.com!example.com!1337140800!1337227200.xml
