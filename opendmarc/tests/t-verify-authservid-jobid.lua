-- Copyright (c) 2026, The Trusted Domain Project.  All rights reserved.

-- Verifies that when AuthservIDWithJobID is set, the authserv-id in both
-- the spf= and dmarc= Authentication-Results headers is a properly quoted
-- RFC 8601 / RFC 2045 token of the form "authservid/jobid" rather than
-- the invalid unquoted form authservid/jobid (where "/" is a tspecial).

mt.echo("*** authserv-id with job ID quoting test")

-- setup
sock = "unix:" .. mt.getcwd() .. "/t-verify-authservid-jobid.sock"
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

mt.startfilter(binpath .. "/opendmarc", "-l", "-c",
               "t-verify-authservid-jobid.conf", "-p", sock)

conn = mt.connect(sock, 40, 0.05)
if conn == nil then
	error("mt.connect() failed")
end

if mt.conninfo(conn, "localhost2", "66.220.149.251") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

mt.macro(conn, SMFIC_MAIL, "i", "testjobid")
if mt.mailfrom(conn, "user@trusteddomain.org") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

if mt.header(conn, "From", "user@trusteddomain.org") ~= nil then
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

if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eoh() unexpected reply")
end

if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

if not mt.eom_check(conn, MT_HDRINSERT, "Authentication-Results") and
   not mt.eom_check(conn, MT_HDRADD, "Authentication-Results") then
	error("no Authentication-Results added")
end

-- every A-R header must use the quoted authserv-id form;
-- the unquoted form with a bare slash is an RFC violation
n = 0
unquoted_found = 0
quoted_found = 0
while true do
	ar = mt.getheader(conn, "Authentication-Results", n)
	if ar == nil then
		break
	end
	if string.find(ar, '"testhost/testjobid"', 1, true) ~= nil then
		quoted_found = quoted_found + 1
	end
	if string.find(ar, "testhost/testjobid", 1, true) ~= nil and
	   string.find(ar, '"testhost/testjobid"', 1, true) == nil then
		unquoted_found = unquoted_found + 1
	end
	n = n + 1
end

if quoted_found == 0 then
	error("authserv-id with job ID not properly quoted (expected \"testhost/testjobid\")")
end
if unquoted_found > 0 then
	error("authserv-id with job ID present in invalid unquoted form (RFC 8601 violation)")
end

mt.disconnect(conn)
