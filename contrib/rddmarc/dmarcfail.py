#!/usr/local/bin/python
# $Header: /home/johnl/hack/dmarc/RCS/dmarcfail.py,v 1.1 2012/07/12 03:59:29 johnl Exp $
# parse DMARC failure reports, add it to the mysql database
# optional arguments are names of files containing ARF messages,
# otherwise it reads stdin

# Copyright 2012, Taughannock Networks. All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:

# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.

# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import re
import email
import time
import MySQLdb

db = MySQLdb.connect(user='dmarc',passwd='xxx',db='dmarc', use_unicode=True)
MySQLdb.paramstyle='format'

def dmfail(h,f):
    e = email.message_from_file(h)
    if(e.get_content_type() != "multipart/report"):
        print f,"is not a report"
        return

    for p in e.get_payload():
        if(p.get_content_type() == "message/feedback-report"):
            r = email.parser.Parser()
            fr = r.parsestr(p.get_payload()[0].as_string(), True)
            fx = re.search(r'<(.+?)@(.+?)>', fr['original-mail-from'])
            origbox,origdom = fx.group(1,2)
            arr = int(email.utils.mktime_tz(email.utils.parsedate_tz(fr['arrival-date'])))
            
        elif(p.get_content_type() == "message/rfc822" or
            p.get_content_type() == "text/rfc822-headers"):
            
            m = email.message_from_string(p.get_payload())
            frombox = fromdom = None
            fx = re.search(r'<(.+?)@(.+?)>', m['from'])
            if(fx): frombox,fromdom = fx.group(1,2)
            else:
                t = re.sub(m['from'],r"\s+|\([^)]*\)","")
                fx = re.match(r'(.+?)@(.+?)', t)
                if(fx): frombox,fromdom = fx.group(1,2)

    # OK, parsed it, now add an entry to the database
    c = db.cursor()
    c.execute("""INSERT INTO failure(serial,org,bouncedomain,bouncebox,fromdomain,
        frombox,arrival,sourceip,headers)
        VALUES(NULL,%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),INET_ATON(%s),%s)""",
        (fr['reported-domain'],origdom,origbox,fromdom,frombox,arr,fr['source-ip'],m.as_string()))
    print "Inserted failure report %s" % c.lastrowid
    c.close()

#################################################################################################
if __name__ == "__main__":
    import sys
    
    if(len(sys.argv) < 2):
        dmfail(sys.stdin,"stdin");
    else:
        for f in sys.argv[1:]:
            h = open(f)
            dmfail(h, f)
            h.close()
