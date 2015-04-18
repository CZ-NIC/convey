#!/usr/bin/python
# -*- coding: utf-8 -*-

import httplib
from pprint import pprint
import codecs
from optparse import OptionParser
import re
import sys

HOST = 'otrs.nic.cz'
BASEURI = '/otrs/index.pl'

TICKETEMAIL = 'abuse@csirt.cz'
FROMADDR = "\"CSIRT.CZ Abuse Team\" <abuse@csirt.cz>"
SIGNKEYID = "PGP::Detached::B187176C"
RECORD_LABEL = "%(FILENAME)s"

DEBUG = False

re_title = re.compile('<title>([^<]*)</title>')



def post_multipart(host, selector, fields, files, cookies):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files.
    Return an appropriate httplib.HTTPResponse object.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    protocol = host.split(':')[0]
    h = httplib.HTTPSConnection(host)
    if DEBUG:
        h.debuglevel = 100
    h.putrequest('POST', selector)
    h.putheader('Content-Type', content_type)
    h.putheader('Content-Length', str(len(body)))
    for key, value in cookies:
        h.putheader(key, value)
    h.endheaders()
    h.send(body)
    response = h.getresponse()
    return response

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files.
    Return (content_type, body) ready for httplib.HTTPConnection instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_---$---'
    CRLF = '\r\n'
    l = []
    for (key, value) in fields:
        l.append('--' + BOUNDARY)
        l.append('Content-Disposition: form-data; name="%s"' % key)
        l.append('')
        l.append(value)
    for (key, filename, value) in files:
        l.append('--' + BOUNDARY)
        l.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        l.append('')
        l.append(value)
    l.append('--' + BOUNDARY + '--')
    l.append('')
    body = CRLF.join(l)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def check_record (record, lineno):
    valid = ('CONTACTS' in record)
    if not valid:
        print >>sys.stderr, "Line %d: Record missing CONTACTS field" %lineno
    return valid


def read_records(filename):
    """Read a file in Debian stanza format and return list of records.

    Records are separated by at least one empty line. Each record 
    contains several (at least one) fields, consisting of
    'key: value' pairs.
    Fields have to start at the first column.
    Lines  beginning with a space are continuation lines and are\
    joined to the previous line. Lines beginning with '#' are
    comments and are ignored.

    Example:
    CONTACTS: john.doe@example.com
    NETWORK: EXAMPLE-COM

    CONTACTS: jane.doe@example.com
    NETWORK: EXAMPLE-COM
    FILENAME: example.com.txt
    """

    f = open(filename, "r")

    records = []
    record = {}
    key = None
    lineno = 0
    was_quit = False
    errors = 0

    while not was_quit:
        lineno += 1
        line = f.readline()
        was_quit = not line

        line = line.rstrip()

        if line == '':
            if record:
                if check_record(record, lineno):
                    records.append (record)
                else:
                    errors += 1
                record = {}
                key = None
            continue

        elif line.startswith('#'):
            continue

        elif line.startswith(' '):
            if key:
                record[key] = record[key] + line
            else:
                print >>sys.stderr, "Line %d: Continuation at start of record: %s" %(lineno, line)
                errors += 1

        elif line.find(': ') >= 0:
            key, value = line.split(': ')
            record[key] = value

        else:
            print >>sys.stderr, "Line %d: Field has to be 'key: value': %s" %(lineno, line)
            errors += 1


    f.close()

    if errors:
        print >>sys.stderr, "\nErrors encountered, exiting!\n"
        sys.exit(1)

    else:
        return records


def check_response(response):
    if DEBUG:
        print >>sys.stderr, "Response:\n", response

    mo = re_title.search(response)
    if not mo:
        print >>sys.stderr, "Unrecognized response"
        return False

    title = mo.group(1)

    if title in ('Forward - Ticket -  OTRS', 'Předat - Tiket -  OTRS'):
        return True

    elif title == 'Login - OTRS':
        print >>sys.stderr, "Not logged in or wrong session cookie"
        return False

    elif title in ('Fatal Error - Frontend -  OTRS' , 'Fatal Error - Rozhraní -  OTRS'):
        print >>sys.stderr, "Bad CSRF token"
        return False

    else:
        print >>sys.stderr, "Unrecognized response:", title
        return False

    
def main():
    global DEBUG

    parser = OptionParser()
    parser.add_option("--id", dest="ticketid", help="ticket id (short numeric from URL) [required]")
    parser.add_option("--num", dest="ticketnum", help="ticket num (long #) [required]")
    parser.add_option("--cookie", dest="cookie", help="content of Session cookie [required]")
    parser.add_option("--token", dest="token", help="content of ChallengeToken [required]")
    parser.add_option("--list", dest="auslist", default="contacts", help="file with domain/ip/contact info")
    parser.add_option("--message", dest="body", default="body", help="subject and body text template")
    parser.add_option("--label", dest="label", default=RECORD_LABEL, help="record label template")
    parser.add_option("--debug", dest="debug", action='store_true', default=DEBUG, help="print debug output")
    (opts, args) = parser.parse_args()

    auslist = opts.auslist
    body = opts.body
    ticketid = opts.ticketid or parser.error("ticket id (short one) required")
    ticketnum = opts.ticketnum or parser.error("ticket num (long one) required")
    cookie = opts.cookie or parser.error("authentization cookie required")
    token = opts.token or parser.error("challenge token required")
    record_label = opts.label
    DEBUG = opts.debug

    bodyfile = open(body, "r")
    subjecttext = bodyfile.readline()
    bodytext = bodyfile.read()
    bodyfile.close()


    records = read_records(auslist)

    for r in records:
        r["TICKETNUM"] = ticketnum

    for l in records:
        subject = subjecttext % l
        body = bodytext % l
        fields = (
            ("Action", "AgentTicketForward"),
            ("Subaction", "SendEmail"),
            ("TicketID", str(ticketid)),
            ("Email", TICKETEMAIL),
            ("From", FROMADDR),
            ("To", l["CONTACTS"]),
            ("Subject", subject),
            ("SignKeyID", SIGNKEYID),
            ("Body", body),
            ("ArticleTypeID", "1"),   # mail-external
            ("ComposeStateID", "4"),  # open
            ("ChallengeToken", token),
        )
        if 'FILENAME' in l and l['FILENAME']:
            files = (
                ("FileUpload", l["FILENAME"], open(l["FILENAME"]).read()),
            )
        else:
            files = ()

        cookies = (
            ('Cookie', 'Session=%s' % cookie),
        )

        if DEBUG:
            print >>sys.stderr, 'Fields:', fields
            print >>sys.stderr, 'Files:', files
            print >>sys.stderr, 'Cookies:', cookies

        print record_label % l

        #print encode_multipart_formdata(fields, files)
        res = post_multipart(HOST, BASEURI, fields=fields, files=files, cookies=cookies)

        if not res or not check_response (res.read()):
            sys.exit(1)


main()
sys.exit(0)
