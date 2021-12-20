# $Id: Makefile.am,v 1.30 2010/09/13 05:32:21 cm-msk Exp $

check_SCRIPTS = 

if LIVE_TESTS
check_SCRIPTS += t-verify-multi-from-reject t-verify-multi-from-malformed \
	t-verify-nodata t-verify-nodata-reject \
	t-verify-unspec t-verify-received-spf-good t-verify-received-spf-bad \
	t-verify-self-spf
endif

TESTS = $(check_SCRIPTS)

EXTRA_DIST = \
	t-verify-nodata t-verify-nodata.conf t-verify-nodata.lua \
	t-verify-nodata-reject t-verify-nodata-reject.conf \
		t-verify-nodata-reject.lua \
	t-verify-unspec t-verify-unspec.conf t-verify-unspec.lua \
	t-verify-received-spf-good t-verify-received-spf-good.conf \
		t-verify-received-spf-good.lua \
	t-verify-received-spf-bad t-verify-received-spf-bad.conf \
		t-verify-received-spf-bad.lua \
	t-verify-self-spf t-verify-self-spf.conf t-verify-self-spf.lua \
	t-verify-multi-from-reject t-verify-multi-from-reject.conf \
		t-verify-multi-from-reject.lua \
	t-verify-multi-from-malformed t-verify-multi-from-malformed.conf \
		t-verify-multi-from-malformed.lua

MOSTLYCLEANFILES=
