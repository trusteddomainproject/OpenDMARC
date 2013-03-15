# $Id: Makefile.am,v 1.30 2010/09/13 05:32:21 cm-msk Exp $

check_SCRIPTS = 

if LIVE_TESTS
check_SCRIPTS += t-verify-nodata t-verify-nodata-reject t-verify-unspec
endif

TESTS = $(check_SCRIPTS)

EXTRA_DIST = \
	t-verify-nodata t-verify-nodata.conf t-verify-nodata.lua \
	t-verify-nodata-reject t-verify-nodata-reject.conf \
		t-verify-nodata-reject.lua \
	t-verify-unspec t-verify-unspec.conf t-verify-unspec.lua

MOSTLYCLEANFILES=
