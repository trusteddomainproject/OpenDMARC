-- Copyright (c) 2012, The Trusted Domain Project.  All rights reserved.

-- Test message from paypal.com with no DKIM or SPF DATA
-- 
-- Confirms that a message with no authentication data claiming to be from a
-- "p=reject" domain will provoke a rejection.  This variant confirms a
-- reject request from the filter rather than checking production of an
-- Authentication-Results field.

mt.echo("*** no data reject test (rejection)")

-- setup
sock = "unix:" .. mt.getcwd() .. "/t-verify-nodata-reject.sock"
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendmarc", "-c", "t-verify-nodata-reject.conf",
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
mt.macro(conn, SMFIC_MAIL, "i", "t-verify-nodata-reject")
if mt.mailfrom(conn, "user@paypal.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user@paypal.com") ~= nil then
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
if mt.getreply(conn) ~= SMFIR_REPLYCODE then
	error("mt.eom() unexpected reply")
end

mt.disconnect(conn)
