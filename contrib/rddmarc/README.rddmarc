These are little scripts to parse DMARC reports.

The first, rddmarc, is a perl script that take an incoming DMARC
summary report email, extracts and unpacks the gzip or ZIP file,
parses the XML, and puts the parts about received mail into a MySQL
database.  The database is set up to handle reports about multiple
domains from multiple reporters. It's handling reports from Google,
Yahoo, xs4all and Netease.  

It expects filenames on the command line, each of which contains a
mail message, but it'd easy enough to adjust it to read stdin or
anywhere else.

It works great on FreeBSD, can probably be made to work on linux with
modest effort, no clue about other systems.  It needs the
MIME::Parser, XML::Simple, and DBI perl modules and the freeware unzip
program to extract stuff from the gzip or ZIP file.

It now handles both IPv4 and IPv6 addresses.  If you have been
running the ipv4 version, see mkdmarc for instructions on how
to update your database.  The file mysql_ip6.c is a plugin for a
mysql server to add some IPv6 formatting functions that can be
handy when analyzing the reports.  It's not needed for rddmarc.

The second is a python script to parse failure reports.  It expects
file names on the command line, or if no arguments, it reads stdin. It
needs the usual MySQLdb module.  It handles reports from Netease,
which are currently the only ones I'm getting.

mkdmarc - SQL to create the tables

rddmarc - the script to parse summary reports (Perl)

dmarcfail.py - the script to parse failure reports (python)

mysql_ip6.c - C language source for MySQL plugin for IPv6
	formatting functions
