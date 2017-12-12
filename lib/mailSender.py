# Send mails throught OTRS
import http.client
from lib.config import Config
import logging
from optparse import OptionParser
import re
import sys
import smtplib
from email.mime.text import MIMEText

re_title = re.compile('<title>([^<]*)</title>')

class MailSender():

    def _post_multipart(host, selector, fields, files, cookies):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return an appropriate http.client.HTTPResponse object.
        """

        import ssl; ssl._create_default_https_context = ssl._create_unverified_context  # XX once upon a day (10.2.2017), the certificate stopped working or whatever. This is an ugly solution - i think we may delete this line in few weeks

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
        if b'P\xc5\x99edat - Tiket -  OTRS'.decode("utf-8") in title or 'Forward - Ticket -  OTRS' in title: # XX r with caron make nb-python fail. 2nd: once, the subject was: <title>20160715228000147 - Předat - Tiket -  OTRS</title>
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

    def sendList(csv, mails, mailDraft, totalCount, method="smtp"):
        """ Send a registry (abusemails or csirtmails)

            method - smtp OR otrs
        """
        if method == "otrs" and not Config.get("otrs_enabled", "OTRS"):
            print("OTRS is the only implemented option of sending now. Error.")
            return False

        if not totalCount:
            print("... done. (No mails in the list, nothing to send.)")
            return True

        sentMails = 0
        logging.info("sending mails from list...")

        if method == "smtp":
            MailSender.smtpObj = smtplib.SMTP(Config.get("host", "SMTP"))
        for mail, cc, contents in mails: #Xregistry.getMails():
            textVars = {}
            textVars["CONTACTS"] = mail
            textVars["FILENAME"] = csv.attachmentName
            textVars["TICKETNUM"] = csv.otrs_ticketnum
            subject = mailDraft.getSubject() % textVars
            body = mailDraft.getBody() % textVars # format mail template, ex: {FILENAME} in the body will be transformed by the filename
            if subject == "" or body == "":
                print("Missing subject or mail body text.")
                return False

            if Config.isTesting():
                mailFinal = Config.get('testingMail')
                body = "This is testing mail only from Convey. Don't be afraid, it wasn't delivered to {} .\n".format(mail) + body
                print("***************************************\n*** TESTING MOD - mails will be sent to mail {} ***\n (For turning off testing mode set testing = False in config.ini.)".format(mailFinal))
            else:
                mailFinal = mail

            from email.utils import parseaddr
            # check e-mail is valid
            if not '@' in parseaddr(mailFinal)[1]:
                # XXX shouldnt we check all mails are valid before?
                # XXX a tohle stejne nefunguje, prosel mail s diakritikou
                print("ERRONEOUS EMAIL!")
                print(mailFinal)
                logging.error("erroneous mail {}".format(mailFinal))
                continue

            logging.info("mail {}".format(mail))
            if method == "smtp":
                if MailSender.smtpSend(subject, body, mailFinal):
                    sentMails += 1
                    logging.info("ok {}".format(mail))
            else:
                fields = (
                          ("Action", "AgentTicketForward"),
                          ("Subaction", "SendEmail"),
                          ("TicketID", str(csv.otrs_ticketid)),
                          ("Email", Config.get("ticketemail", "SMTP")),
                          ("From", Config.get("fromaddr", "SMTP")),
                          ("To", mailFinal), # X "edvard.rejthar+otrs_test@nic.cz" sem ma prijit mail (nebo maily oddelene carkou ci strednikem, primo z whois), po otestovani. XX Jdou pouzit maily oddelene strednikem i vice stredniky? mail;mail2;;mail3 (kvuli retezeni v cc pro pripad, ze je vic domen)
                          ("Subject", subject),
                          ("Body", body),
                          ("ArticleTypeID", "1"), # mail-external
                          ("ComposeStateID", "4"), # open
                          ("ChallengeToken", csv.otrs_token),
                          )

                try:
                    fields += ("SignKeyID", Config.get("signkeyid", "OTRS"))
                except KeyError:
                    pass

                if Config.isTesting() == False:
                    if cc: # X mailList.mails[mail]
                        fields += (("Cc", cc),)

                # load souboru k zaslani
                #contents = registryRecord.getFileContents() #csv.ips2logfile(mailList.mails[mail])

                logging.info("mail {}".format(mail))
                #print(mail)

                if csv.attachmentName and contents != "":
                    files = (("FileUpload", csv.attachmentName, contents),)
                else:
                    files = ()

                cookies = (('Cookie', 'Session=%s' % csv.otrs_cookie),)

                if Config.isTesting():
                    print(" **** Testing info:")
                    print (' ** Fields: ' + str(fields))
                    print (' ** Files: ' + str(files))
                    print (' ** Cookies: ' + str(cookies))
                    # str(sys.stderr)

                #print encode_multipart_formdata(fields, files)

                res = MailSender._post_multipart(Config.get("host", "SMTP"),
                                                 Config.get("baseuri", "OTRS"),
                                                 fields=fields,
                                                 files=files,
                                                 cookies=cookies)
                if not res or not MailSender._check_response (res.read()):
                    print("Sending failure, see convey.log.")
                    break
                else:
                    sentMails += 1

        if method == "smtp":
            MailSender.smtpObj.quit()
        print("\nSent: {}/{} mails.".format(sentMails, totalCount))
        return sentMails == totalCount

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
            if(force or csv.otrs_ticketid == False or csv.otrs_ticketnum == False or csv.otrs_cookie == False or csv.otrs_token == False or csv.attachmentName == False):
                csv.otrs_ticketid = MailSender.askValue(csv.otrs_ticketid, "ticket url-id")
                csv.otrs_ticketnum = MailSender.askValue(csv.otrs_ticketnum, "ticket long-num")
                csv.otrs_cookie = MailSender.askValue(csv.otrs_cookie, "cookie")
                csv.otrs_token = MailSender.askValue(csv.otrs_token, "token")
                csv.attachmentName = MailSender.askValue(csv.attachmentName, "attachment name")
                if csv.attachmentName[-4:] != ".txt":
                    csv.attachmentName += ".txt"

            sys.stdout.write("Ticket id = {}, ticket num = {}, cookie = {}, token = {}, attachmentName = {}.\nWas that correct? [y]/n ".format(csv.otrs_ticketid, csv.otrs_ticketnum, csv.otrs_cookie, csv.otrs_token, csv.attachmentName))
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue

    def smtpSend(subject, body, mailFinal):
        sender = Config.get("ticketemail", "SMTP")

        message = MIMEText(body)
        message["Subject"] = subject
        message["From"] = Config.get("fromaddr", "SMTP")
        message["To"] = mailFinal

        try:
           #smtpObj.send_message(sender, mailFinal, MIMEText(message,"plain","utf-8"))
           MailSender.smtpObj.send_message(message)

           #print ("Successfully sent email")
           return 1
        except Exception as e:
            print(e)
            import ipdb; ipdb.set_trace()
            print ("Error: unable to send email")