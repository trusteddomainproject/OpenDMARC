-- Copyright (c) 2026, The Trusted Domain Project.  All rights reserved.

-- Test that X-DKIM-Canonicalized-Header/-Body staging headers (as added by
-- an upstream OpenDKIM's AddCanonicalizedData directive, RFC 9991) are
-- stripped from the outgoing message before final delivery, unconditionally
-- -- ReadCanonicalizedData is deliberately NOT set in the .conf for this
-- test, since stripping must happen regardless of whether this filter is
-- configured to read them.

mt.echo("*** canonicalized-data header stripping test")

-- setup
sock = "unix:" .. mt.getcwd() .. "/t-verify-canondata.sock"
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendmarc", "-l", "-c", "t-verify-canondata.conf",
               "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.05)
if conn == nil then
	error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost2", "127.0.0.2") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-canondata")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers, including the staging headers an upstream OpenDKIM would
-- have added
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user@example.com") ~= nil then
	error("mt.header(From) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(From) unexpected reply")
end
if mt.header(conn, "To", "user@example.com") ~= nil then
	error("mt.header(To) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(To) unexpected reply")
end
if mt.header(conn, "Date", "Tue, 22 Dec 2009 13:04:12 -0800") ~= nil then
	error("mt.header(Date) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Date) unexpected reply")
end
if mt.header(conn, "Subject", "DMARC test") ~= nil then
	error("mt.header(Subject) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Subject) unexpected reply")
end
if mt.header(conn, "X-DKIM-Canonicalized-Header",
             "d=example.com; s=sel; b=AAAAformattingexample") ~= nil then
	error("mt.header(X-DKIM-Canonicalized-Header) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(X-DKIM-Canonicalized-Header) unexpected reply")
end
if mt.header(conn, "X-DKIM-Canonicalized-Body",
             "d=example.com; s=sel; b=BBBBformattingexample") ~= nil then
	error("mt.header(X-DKIM-Canonicalized-Body) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(X-DKIM-Canonicalized-Body) unexpected reply")
end

-- send EOH
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eoh() unexpected reply")
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eom() unexpected reply")
end

-- verify the staging headers did NOT survive to the outgoing message
if mt.getheader(conn, "X-DKIM-Canonicalized-Header", 0) ~= nil then
	error("X-DKIM-Canonicalized-Header was not stripped")
end
if mt.getheader(conn, "X-DKIM-Canonicalized-Body", 0) ~= nil then
	error("X-DKIM-Canonicalized-Body was not stripped")
end

mt.disconnect(conn)
