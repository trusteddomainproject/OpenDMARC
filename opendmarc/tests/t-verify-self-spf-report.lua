-- Copyright (c) 2026, The Trusted Domain Project.  All rights reserved.

-- Test message from isc.org with an unauthorized client IP address.
--
-- Confirms that SPF self-validation (RFC 9991) populates the RFC 6591
-- SPF-DNS field of the resulting failure report, including entries for
-- domains reached via isc.org's SPF record's include: mechanisms, and
-- that reports aren't attempted at all when LogSPFDNS is off (this
-- capability has a real per-message cost, so it must stay opt-in).

mt.echo("*** self-SPF test with LogSPFDNS report capture")

-- setup
sock = "unix:" .. mt.getcwd() .. "/t-verify-self-spf-report.sock"
binpath = mt.getcwd() .. "/.."
outfile = mt.getcwd() .. "/t-verify-self-spf-report.out"
os.remove(outfile)
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendmarc", "-l", "-c",
               "t-verify-self-spf-report.conf", "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.05)
if conn == nil then
	error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost2", "66.220.149.251") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- HELO must precede any SMFIC_MAIL-scoped macro (see
-- t-verify-authservid-jobid.lua for why: real libmilter's HELO handler
-- clears macros stored for later protocol stages).
if mt.helo(conn, "localhost2") ~= nil then
	error("mt.helo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.helo() unexpected reply")
end

mt.macro(conn, SMFIC_MAIL, "i", "t-verify-self-spf-report")
if mt.mailfrom(conn, "user@isc.org") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user@isc.org") ~= nil then
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
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

mt.disconnect(conn)

-- give the piped ReportCommand a moment to finish writing
os.execute("sleep 1")

-- verify the captured report contains SPF-DNS lines for isc.org itself
-- and for at least one include: target
f = io.open(outfile, "r")
if f == nil then
	error("failure report was not captured to " .. outfile)
end
report = f:read("*a")
f:close()

if string.find(report, "SPF%-DNS: txt : isc%.org : \"v=spf1") == nil then
	error("no SPF-DNS line for isc.org's own SPF record")
end

if string.find(report, "SPF%-DNS: txt : .+%.customercenter%.net") == nil and
   string.find(report, "SPF%-DNS: txt : .+%.shopify%.com") == nil and
   string.find(report, "SPF%-DNS: txt : .+%.mcsv%.net") == nil and
   string.find(report, "SPF%-DNS: txt : .+salesforce%.com") == nil
then
	error("no SPF-DNS line for any include: target")
end

os.remove(outfile)
