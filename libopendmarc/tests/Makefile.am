SUBDIRS=testfiles
LDADD = ../libopendmarc.la $(LIBRESOLV)
AM_CPPFLAGS = -I.. -I../..

check_PROGRAMS		 = test_tld \
			   test_finddomain \
			   test_dmarc_parse \
			   test_dmarc_fetch \
			   test_xml_parse \
			   test_parse_to_buf \
			   test_alignment
if LIVE_TESTS
#check_PROGRAMS           += test_dns_lookup
#test_dns_lookup_SOURCES  = test_dns_lookup.c
if USE_SPF
check_PROGRAMS           += test_spf
test_spf_SOURCES         = test_spf.c
endif
endif

test_tld_SOURCES         = test_tld.c

test_finddomain_SOURCES  = test_finddomain.c

test_dmarc_parse_SOURCES = test_dmarc_parse.c

test_parse_to_buf_SOURCES = test_parse_to_buf.c

test_dmarc_fetch_SOURCES = test_dmarc_fetch.c

test_xml_parse_SOURCES   = test_xml_parse.c


test_alignment_SOURCES   = test_alignment.c

TESTS = $(check_PROGRAMS)

EXTRA_DIST	= testfiles/effective_tld_names.dat \
		  testfiles/good.com!example.com!1337270400!1337356799.xml \
		  testfiles/bad.com!example.com!1337140800!1337227200.xml
