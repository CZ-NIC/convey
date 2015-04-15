# Vychazi z auscert-send.6.py pro Python2.
import http.client
from optparse import OptionParser
import re
import sys

HOST = 'otrs.nic.cz'
BASEURI = '/otrs/index.pl'

TICKETEMAIL = 'abuse@csirt.cz'
FROMADDR = "\"CSIRT.CZ Abuse Team\" <abuse@csirt.cz>"
SIGNKEYID = "PGP::Detached::B187176C"
#RECORD_LABEL = "%(FILENAME)s"

DEBUG = False

re_title = re.compile('<title>([^<]*)</title>')

class MailSender():

    def _post_multipart(host, selector, fields, files, cookies):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return an appropriate http.client.HTTPResponse object.
        """
        content_type, body = MailSender._encode_multipart_formdata(fields, files)
        protocol = host.split(':')[0]
        h = http.client.HTTPSConnection(host)
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

    def _encode_multipart_formdata(fields, files):
        """
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for http.client.HTTPConnection instance
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


    def _check_record (record, lineno):
        valid = ('CONTACTS' in record)
        if not valid:
            print (str(sys.stderr) + " Line {}: Record missing CONTACTS field ".format(lineno))
        return valid



    def _check_response(response):
        if DEBUG:
            print (str(sys.stderr) + " Response:\n " + response)

        mo = re_title.search(response)
        if not mo:
            print (str(sys.stderr) + " Unrecognized response")
            return False

        title = mo.group(1)

        if title in ('Forward - Ticket -  OTRS', 'Předat - Tiket -  OTRS'):
            return True

        elif title == 'Login - OTRS':
            print (str(sys.stderr) + " Not logged in or wrong session cookie")
            return False

        elif title in ('Fatal Error - Frontend -  OTRS', 'Fatal Error - Rozhraní -  OTRS'):
            print (str(sys.stderr) + " Bad CSRF token")
            return False

        else:
            print (str(sys.stderr) + " Unrecognized response: " + title)
            return False

    # posle objekt mailList (mailCz ci mailWorld)
    def sendList(mailList):
        global DEBUG

        
        for mail in mailList.mails:            
            attachmentName = "priloha" # XX

            textVars = {}
            textVars["CONTACTS"] = mail
            textVars["FILENAME"] = attachmentName
            textVars["TICKETNUM"] = MailSender.ticketnum
            subject = mailList.getSubject() % textVars
            body = mailList.getBody() % textVars # formatovat sablonu textu, ex: kde se v body vyskytuje {FILENAME}, nahradi se jmenem souboru
            if subject == False or body == False:
                print("Chybí subject nebo body text mailu.")
                return False

            fields = (
                      ("Action", "AgentTicketForward"),
                      ("Subaction", "SendEmail"),
                      ("TicketID", str(ticketid)),
                      ("Email", TICKETEMAIL),
                      ("From", FROMADDR),
                      ("To", "edvard.rejthar+otrs_test@nic.cz"), # XXX sem ma prijit mail, po otestovani
                      ("Subject", subject),
                      ("SignKeyID", SIGNKEYID),
                      ("Body", body),
                      ("ArticleTypeID", "1"), # mail-external
                      ("ComposeStateID", "4"), # open
                      ("ChallengeToken", token),
                      )

            # load souboru k zaslani
            if attachmentName and len(mailList.mails[mail]) > 0 :
                files = (("FileUpload", attachmentName, "XXX soubor logu, dostat z parseSource generateFiles"),)
            else:
                files = ()

            cookies = (('Cookie', 'Session=%s' % cookie),)

            if DEBUG:
                print (str(sys.stderr) + ' Fields: '+ str(fields))
                print (str(sys.stderr) + ' Files: '+ str(files))
                print (str(sys.stderr) + ' Cookies: '+ str(cookies))

            #print record_label % lrecord

            print("XX Zamezeno poslani")
            return True
            #print encode_multipart_formdata(fields, files)
            res = MailSender._post_multipart(HOST, BASEURI, fields=fields, files=files, cookies=cookies)

            if not res or not MailSender._check_response (res.read()):
                sys.exit(1)

    ticketid = False
    ticketnum = False
    cookie = False
    token = False


    def _loginCheck():
        return False #XX
        pass

    def assureTokens():
        # XXX checknout prihlaseni do OTRS,
        if (MailSender.cookie == False) or (MailSender.token == False) or MailSender._loginCheck() == False:
            # jestli neprojde, požádat o údaje
            # ulozit  cookie a token do config filu
            pass
        while True:
            if MailSender.ticketid == False:
                sys.stdout.write("Ticket id: ")
                MailSender.ticketid = input()
            if MailSender.ticketnum == False:
                sys.stdout.write("Ticket num: ")
                MailSender.ticketnum = input()

            return True # XX pridat potvrzeni (nize)
            sys.stdout.write("Ticket id = {}, ticket num = {}, is that correct? [y]/n".format(MailSender.ticketid, MailSender.ticketnum))
            if input() in ("y", "Y", ""):
                return True
            else:
                continue