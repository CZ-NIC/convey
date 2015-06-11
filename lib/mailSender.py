# Vychazi z auscert-send.6.py pro Python2.
import http.client
from optparse import OptionParser
import re
import sys
import logging

HOST = 'otrs.nic.cz'
BASEURI = '/otrs/index.pl'

TICKETEMAIL = 'abuse@csirt.cz'
FROMADDR = "\"CSIRT.CZ Abuse Team\" <abuse@csirt.cz>"
SIGNKEYID = "PGP::Detached::B187176C"
#RECORD_LABEL = "%(FILENAME)s"

DEBUG = False
logging.basicConfig(filename='mailSender.log',level=logging.DEBUG)

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
        body = bytes(body,"UTF-8")
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
        response = response.decode("UTF-8")
        if DEBUG:
            logging.info(str(sys.stderr) + " Response:\n " + response)

        with open( "test.html", "w" ) as output:
            output.write(response)

        mo = re_title.search(response)
        if not mo:
            logging.warning(str(sys.stderr) + " Unrecognized response")
            logging.error(response)
            return False

        title = mo.group(1)

        if title in ('Forward - Ticket -  OTRS', 'Předat - Tiket -  OTRS'):
            return True

        elif title == 'Login - OTRS':
            logging.warning(str(sys.stderr) + "\n\n *** Not logged in or wrong session cookie ***")
            print("\n\n *** Not logged in or wrong session cookie ***") # XX: logging.warning se mi kdoviproc neukazuje na konzoli, mozna jen v nb
            return False

        elif title in ('Fatal Error - Frontend -  OTRS', 'Fatal Error - Rozhraní -  OTRS'):
            logging.warning(str(sys.stderr) + "\n\n *** Bad CSRF token ***")
            print("BAD CSRF")  # XX: logging.warning se mi kdoviproc neukazuje na konzoli, mozna jen v nb
            return False

        else:
            logging.warning(str(sys.stderr) + " Unrecognized response: " + title)
            logging.error(response)
            return False

    # posle objekt mailList (mailCz ci mailWorld)
    def sendList(mailList, csv):
        global DEBUG
        
        sentMails = 0
        logging.info("sending mails from list...")

        for mail in mailList.mails:
            

            textVars = {}
            textVars["CONTACTS"] = mail
            textVars["FILENAME"] = csv.attachmentName
            textVars["TICKETNUM"] = csv.ticketnum
            subject = mailList.getSubject() % textVars
            body = mailList.getBody() % textVars # formatovat sablonu textu, ex: kde se v body vyskytuje {FILENAME}, nahradi se jmenem souboru
            if subject == "" or body == "":
                print("Chybí subject nebo body text mailu.")
                return False            

            fields = (
                      ("Action", "AgentTicketForward"),
                      ("Subaction", "SendEmail"),
                      ("TicketID", str(csv.ticketid)),
                      ("Email", TICKETEMAIL),
                      ("From", FROMADDR),
                      ("To", "edvard.rejthar+otrs_test@nic.cz"), # XXX sem ma prijit mail (nebo maily oddelene carkou ci strednikem, primo z whois), po otestovani. XX Jdou pouzit maily oddelene strednikem i vice stredniky? mail;mail2;;mail3 (kvuli retezeni v cc pro pripad, ze je vic domen)
                      ("Subject", subject),
                      ("SignKeyID", SIGNKEYID),
                      ("Body", body),
                      ("ArticleTypeID", "1"), # mail-external
                      ("ComposeStateID", "4"), # open
                      ("ChallengeToken", csv.token),
                      )            
            if mailList.mails[mail].cc:
               fields += (("Cc", mailList.mails[mail].cc),)
            
            # load souboru k zaslani
            contents = csv.ips2logfile(mailList.mails[mail])
            
            logging.info("mail {}".format(mail))            
            print(mail)
            #print(mailList.mails[mail])
            print(contents[:100] + " (sample)")# XX vypis zaznamu mozna zpomaluje skript
            
            if csv.attachmentName and contents != "":
                files = (("FileUpload", csv.attachmentName, contents),)
            else:
                files = ()

            cookies = (('Cookie', 'Session=%s' % csv.cookie),)

            if DEBUG:
                print (str(sys.stderr) + ' Fields: '+ str(fields))
                print (str(sys.stderr) + ' Files: '+ str(files))
                print (str(sys.stderr) + ' Cookies: '+ str(cookies))

            #print record_label % lrecord

            
            #print encode_multipart_formdata(fields, files)
            #import pdb;pdb.set_trace();
            res = MailSender._post_multipart(HOST, BASEURI, fields=fields, files=files, cookies=cookies)
            if not res or not MailSender._check_response (res.read()):
                print("Zaslání se nezdařilo, viz mailSender.log.")
                break
            else:
                sentMails += 1

        print("\nPosláno {}/{} mailů.".format(sentMails,len(mailList.mails)))
        return len(mailList.mails) == sentMails

    def askValue(value, description = ""):
        if value == False or (sys.stdout.write('Change {} ({})? y/[n]'.format(description,value)) and (input() in ("Y", "y"))):
                sys.stdout.write("{}: ".format(description))
                value = input()
        return value

    def assureTokens(csv):        
        """ Checknout prihlasovaci udaje k OTRS """
        # XX: cookie a token by se mohly nacitat/ukladat z config file
        # # aktuální cookie z OTRS (doplní se samo) cookie =
        # aktuální token (doplní se sám) token =        
        force = False
        while True:
            if(force or csv.ticketid == False or csv.ticketnum == False or csv.cookie == False or csv.token == False or csv.attachmentName == False):
                csv.ticketid = MailSender.askValue(csv.ticketid, "ticket url-id")
                csv.ticketnum = MailSender.askValue(csv.ticketnum,"ticket long-num")
                csv.cookie = MailSender.askValue(csv.cookie,"cookie")
                csv.token = MailSender.askValue(csv.token,"token")
                csv.attachmentName = MailSender.askValue(csv.attachmentName,"attachment name")

            sys.stdout.write("Ticket id = {}, ticket num = {}, cookie = {}, token = {}, attachmentName = {}.\nWas that correct? [y]/n".format(csv.ticketid, csv.ticketnum, csv.cookie, csv.token, csv.attachmentName))
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue