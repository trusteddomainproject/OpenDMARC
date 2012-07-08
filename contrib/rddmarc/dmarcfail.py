#!/usr/local/bin/python
# parse a DMARC failure report, add it to the mysql database

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
    #print fr['reported-domain'],origdom,origbox,fromdom,frombox,arr,fr['source-ip'],"==="
    #print m.as_string()
    #print "==="
    c = db.cursor()
    c.execute("""INSERT INTO failure(serial,org,bouncedomain,bouncebox,fromdomain,
        frombox,arrival,sourceip,headers)
        VALUES(NULL,%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),INET_ATON(%s),%s)""",
        (fr['reported-domain'],origdom,origbox,fromdom,frombox,arr,fr['source-ip'],m.as_string()))
    print "Inserted failure report %s" % c.lastrowid
    c.close()

    
if __name__ == "__main__":
    import sys
    
    if(len(sys.argv) < 2):
        dmfail(sys.stdin,"stdin");
    else:
        for f in sys.argv[1:]:
            h = open(f)
            dmfail(h, f)
            h.close()
            


