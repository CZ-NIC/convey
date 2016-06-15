# Send mails throught OTRS
import http.client
from lib.config import Config
import logging
from optparse import OptionParser
import re
import sys



#RECORD_LABEL = "%(FILENAME)s"
#logging.FileHandler('mailSender.log', 'a')

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
        body = bytes(body, "UTF-8")
        protocol = host.split(':')[0]        
        h = http.client.HTTPSConnection(host)        
        if Config.isTesting():
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
        if Config.isTesting():
            logging.info(str(sys.stderr) + " Response:\n " + response)

        with open("test.html", "w") as output:
            output.write(response)

        mo = re_title.search(response)
        if not mo:
            logging.warning(str(sys.stderr) + " Unrecognized response")
            logging.error(response)
            return False

        title = mo.group(1)
        #import ipdb;ipdb.set_trace()
        if title in ('Forward - Ticket -  OTRS', b'P\xc5\x99edat - Tiket -  OTRS'.decode("utf-8")): # XX r with caron make nb-python fail. Does this work?
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
    
    def sendList(registry, csv):
        """ Send a registry (abusemails or csirtmails) """
        if not Config.get("otrs_enabled", "OTRS"):
            print("OTRS is the only implemented option of sending now. Error.")
            return False

        if not len(registry.records):
            print("... done. (No mails in the list, nothing to send.)")
            return True
        
        sentMails = 0
        logging.info("sending mails from list...")    

        for mail, cc, contents in registry.getMails(): #Xrecords.items():
            textVars = {}
            textVars["CONTACTS"] = mail
            textVars["FILENAME"] = csv.attachmentName
            textVars["TICKETNUM"] = csv.ticketnum
            subject = registry.mailDraft.getSubject() % textVars
            body = registry.mailDraft.getBody() % textVars # format mail template, ex: {FILENAME} in the body will be transformed by the filename
            if subject == "" or body == "":
                print("Missing subject or mail body text.")
                return False            

            if Config.isTesting():
                mailFinal = Config.get('testingMail')
                body = "This is testing mail only from Convey. Don't be afraid, it wasn't delivered to {} .\n".format(mail) + body
                print("***************************************\n*** TESTING MOD - mails will be sent to mail {} ***\n (For turning off testing mode set testing = False in config.ini.)".format(mailFinal))
            else:
                mailFinal = mail

            fields = (
                      ("Action", "AgentTicketForward"),
                      ("Subaction", "SendEmail"),
                      ("TicketID", str(csv.ticketid)),
                      ("Email", Config.get("ticketemail", "OTRS")),
                      ("From", Config.get("fromaddr", "OTRS")),
                      ("To", mailFinal), # X "edvard.rejthar+otrs_test@nic.cz" sem ma prijit mail (nebo maily oddelene carkou ci strednikem, primo z whois), po otestovani. XX Jdou pouzit maily oddelene strednikem i vice stredniky? mail;mail2;;mail3 (kvuli retezeni v cc pro pripad, ze je vic domen)
                      ("Subject", subject),
                      ("SignKeyID", Config.get("signkeyid", "OTRS")),
                      ("Body", body),
                      ("ArticleTypeID", "1"), # mail-external
                      ("ComposeStateID", "4"), # open
                      ("ChallengeToken", csv.token),
                      )

            if Config.isTesting() == False:
                if cc: # X mailList.mails[mail]
                    fields += (("Cc", cc),)
            
            # load souboru k zaslani
            #contents = registryRecord.getFileContents() #csv.ips2logfile(mailList.mails[mail])
            
            logging.info("mail {}".format(mail))            
            print(mail)            
            
            if csv.attachmentName and contents != "":
                files = (("FileUpload", csv.attachmentName, contents),)
            else:
                files = ()

            cookies = (('Cookie', 'Session=%s' % csv.cookie),)

            if Config.isTesting():
                print(" Testing info:")                
                print (' Fields: ' + str(fields))
                print (' Files: ' + str(files))
                print (' Cookies: ' + str(cookies))
                # str(sys.stderr)
            
            #print encode_multipart_formdata(fields, files)

            res = MailSender._post_multipart(Config.get("host", "OTRS"),
                                             Config.get("baseuri", "OTRS"),
                                             fields=fields,
                                             files=files,
                                             cookies=cookies)
            if not res or not MailSender._check_response (res.read()):
                print("Sending failure, see convey.log.")
                break
            else:
                sentMails += 1

        print("\nSent: {}/{} mails.".format(sentMails, len(registry.records)))
        return sentMails == len(registry.records)

    def askValue(value, description=""):
        sys.stdout.write('Change {} ({})? [s]kip or paste it: '.format(description, value))
        t = input()        
        if not t or t.lower() == "s":
            if not value:
                print("Attention, there should not be an empty value.")
            return value
        else:
            return t

    def assureTokens(csv):        
        """ Checknout OTRS credentials """        
        force = False
        while True:
            if(force or csv.ticketid == False or csv.ticketnum == False or csv.cookie == False or csv.token == False or csv.attachmentName == False):
                csv.ticketid = MailSender.askValue(csv.ticketid, "ticket url-id")
                csv.ticketnum = MailSender.askValue(csv.ticketnum, "ticket long-num")
                csv.cookie = MailSender.askValue(csv.cookie, "cookie")
                csv.token = MailSender.askValue(csv.token, "token")
                csv.attachmentName = MailSender.askValue(csv.attachmentName, "attachment name")
                if csv.attachmentName[-4:] != ".txt":
                    csv.attachmentName += ".txt"

            sys.stdout.write("Ticket id = {}, ticket num = {}, cookie = {}, token = {}, attachmentName = {}.\nWas that correct? [y]/n ".format(csv.ticketid, csv.ticketnum, csv.cookie, csv.token, csv.attachmentName))
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue