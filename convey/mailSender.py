# Send mails throught OTRS
import http.client
import logging
import re
import smtplib
import sys
from abc import abstractmethod, ABC
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate
from socket import gaierror

from validate_email import validate_email

from .config import Config

re_title = re.compile('<title>([^<]*)</title>')
logger = logging.getLogger(__name__)

class MailSender(ABC):
    def __init__(self, parser):
        self.parser = parser

    def start(self):
        pass

    def stop(self):
        pass

    @abstractmethod
    def process(self):
        pass

    def send_list(self, mails, mailDraft, method="smtp"):
        # def send_list(self, mails, mailDraft, totalCount, method="smtp"):
        """ Send a registry (abusemails or csirtmails)

            method - smtp OR otrs
        """
        # if method == "otrs" and not Config.get("otrs_enabled", "OTRS"):
        #    print("OTRS is the only implemented option of sending now. Error.")
        #    return False

        # if not total_count:
        #    print("... done. (No mails in the list, nothing to send.)")
        #    return True

        sent_mails = 0
        total_count = 0

        if self.start() is False:
            return False
        for attachment_object, email_to, email_cc, attachement_contents in mails:  # Xregistry.getMails():
            text_vars = {"CONTACTS": email_to, "FILENAME": self.parser.attachment_name, "TICKETNUM": self.parser.otrs_num}
            subject = mailDraft.get_subject() % text_vars
            body = mailDraft.get_body() % text_vars  # format mail template, ex: {FILENAME} in the body will be transformed by the filename
            if subject == "" or body == "":
                print("Missing subject or mail body text.")
                return False

            if Config.is_testing():
                intended_to = email_to
                email_to = Config.get('testing_mail')
                body = "This is testing mail only from Convey. Don't be afraid, it wasn't delivered to: {}\n".format(
                    intended_to) + body
            else:
                intended_to = None

            if not validate_email(email_to):
                logger.error("Erroneous e-mail: {}".format(email_to))
                continue

            if self.process(subject, body, email_to, email_cc, attachement_contents):
                sent_mails += 1
                logger.info("Sent: {}".format(email_to))
                attachment_object.sent = True
            else:
                logger.error("Error sending: {}".format(email_to))
                attachment_object.sent = False
            total_count += 1
        self.stop()

        print("\nSent: {}/{} mails.".format(sent_mails, total_count))
        return sent_mails == total_count


class MailSenderOtrs(MailSender):

    def _post_multipart(self, host, selector, fields, files, cookies):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return an appropriate http.client.HTTPResponse object.
        """

        # import ssl; ssl._create_default_https_context = ssl._create_unverified_context  # XX once upon a day (10.2.2017), the certificate stopped working or whatever. This is an ugly solution - i think we may delete this line in few weeks

        content_type, body = self._encode_multipart_formdata(fields, files)
        body = bytes(body, "UTF-8")
        protocol = host.split(':')[0]
        h = http.client.HTTPSConnection(host)
        if Config.is_debug():
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

    @staticmethod
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

    @staticmethod
    def _check_record(record, lineno):
        valid = ('CONTACTS' in record)
        if not valid:
            print(str(sys.stderr) + " Line {}: Record missing CONTACTS field ".format(lineno))
        return valid

    @staticmethod
    def _check_response(response):
        response = response.decode("UTF-8")
        if Config.is_testing():
            logger.info(str(sys.stderr) + " Response length:\n " + str(len(response)))

        mo = re_title.search(response)
        if not mo:
            logger.warning(str(sys.stderr) + " Unrecognized response")
            logger.error(response)
            return False

        title = mo.group(1)
        if b'P\xc5\x99edat - Tiket -  OTRS'.decode(
                "utf-8") in title or 'Forward - Ticket -  OTRS' in title:  # XX r with caron make nb-python fail. 2nd: once, the subject was: <title>20160715228000147 - Předat - Tiket -  OTRS</title>
            return True

        elif title == 'Login - OTRS':
            logger.warning(str(sys.stderr) + "\n\n *** Not logged in or wrong session cookie ***")
            return False

        elif title in ('Fatal Error - Frontend -  OTRS', 'Fatal Error - Rozhraní -  OTRS'):
            logger.warning(str(sys.stderr) + "\n\n *** Bad CSRF token ***")
            return False

        else:
            logger.warning(str(sys.stderr) + " Unrecognized response: " + title)
            logger.error(response)
            return False

    def ask_value(self, value, description=""):
        sys.stdout.write('Change {} ({})? [s]kip or paste it: '.format(description, value))
        t = input()
        if not t or t.lower() == "s":
            if not value:
                print("Attention, there should not be an empty value.")
            return value
        else:
            return t

    def assure_tokens(self):
        """ Check and update by dialog OTRS credentials """
        force = False
        while True:
            if (
                    force or not self.parser.otrs_id or not self.parser.otrs_num or not self.parser.otrs_cookie or not self.parser.otrs_token or not self.parser.attachment_name):
                self.parser.otrs_id = self.ask_value(self.parser.otrs_id, "ticket url-id")
                self.parser.otrs_num = self.ask_value(self.parser.otrs_num, "ticket long-num")
                self.parser.otrs_cookie = self.ask_value(self.parser.otrs_cookie, "cookie")
                self.parser.otrs_token = self.ask_value(self.parser.otrs_token, "token")
                self.parser.attachment_name = self.ask_value(self.parser.attachment_name, "attachment name")
                if self.parser.attachment_name[-4:] != ".txt":
                    self.parser.attachment_name += ".txt"

            sys.stdout.write(
                "Ticket id = {}, ticket num = {}, cookie = {}, token = {}, attachment_name = {}.\nWas that correct? [y]/n ".format(
                    self.parser.otrs_id, self.parser.otrs_num, self.parser.otrs_cookie, self.parser.otrs_token, self.parser.attachment_name))
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue

    def process(self, subject, body, mail_final, cc, attachment_contents):
        fields = (
            ("Action", "AgentTicketForward"),
            ("Subaction", "SendEmail"),
            ("TicketID", str(self.parser.otrs_id)),
            ("Email", Config.get("email_from", "SMTP")),
            ("From", Config.get("email_from_name", "SMTP")),
            ("To", mail_final),  # mails can be delimited by comma or semicolon
            ("Subject", subject),
            ("Body", body),
            ("ArticleTypeID", "1"),  # mail-external
            ("ComposeStateID", "4"),  # open
            ("ChallengeToken", self.parser.otrs_token),
        )

        try:
            fields += ("SignKeyID", Config.get("signkeyid", "OTRS")),
        except KeyError:
            pass

        if not Config.is_testing():
            if cc:  # X mailList.mails[mail]
                fields += ("Cc", cc),

        # load souboru k zaslani
        # attachment_contents = registryRecord.getFileContents() #csv.ips2logfile(mailList.mails[mail])

        if self.parser.attachment_name and attachment_contents != "":
            files = (("FileUpload", self.parser.attachment_name, attachment_contents),)
        else:
            files = ()

        cookies = (('Cookie', 'Session=%s' % self.parser.otrs_cookie),)

        if Config.is_testing():
            print(" **** Testing info:")
            print(' ** Fields: ' + str(fields))
            #print(' ** Files length: ', len(files))
            print(' ** Cookies: ' + str(cookies))
            # str(sys.stderr)

        host = Config.get("otrs_host", "OTRS")
        selector = Config.get("baseuri", "OTRS")
        try:
            res = self._post_multipart(host,
                                       selector,
                                       fields=fields,
                                       files=files,
                                       cookies=cookies)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            print("\nE-mail couldn't be send to the host {}{} with the fields {}. Are you allowed to send from this e-mail etc?".format(host, selector, fields))
            input("Program now ends.")
            quit()
        if not res or not self._check_response(res.read()):
            print("Sending failure, see convey.log.")
            return False
        else:
            return True


class MailSenderSmtp(MailSender):
    smtp: smtplib.SMTP

    def start(self):
        try:
            self.smtp = smtplib.SMTP(Config.get("smtp_host", "SMTP"))
        except (gaierror, ConnectionRefusedError) as e:
            print("Can't connect to SMTP server", e)
            return False

    def stop(self):
        self.smtp.quit()

    def process(self, subject, body, email_to, cc, contents):
        base_msg = MIMEMultipart()
        base_msg.attach(MIMEText(body, "html", "utf-8"))

        if contents:
            attachment = MIMEApplication(contents, "text/csv")
            attachment.add_header("Content-Disposition", "attachment",
                                  filename=self.parser.attachment_name)  # XX? 'proki_{}.zip'.format(time.strftime("%Y%m%d"))
            base_msg.attach(attachment)
        """ may be used tested code from Proki
        if self.parameters.gpg:
            msg = MIMEMultipart(_subtype="signed", micalg="pgp-sha1", protocol="application/pgp-signature")
            s = base_msg.as_string().replace('\n', '\r\n')
            signature = self._sign(s)

            if not signature:
                print("Failed to sign the message for {}".format(email_to))
                return False
            signature_msg = Message()
            signature_msg['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
            signature_msg['Content-Description'] = 'OpenPGP digital signature'
            signature_msg.set_payload(signature)
            msg.attach(base_msg)
            msg.attach(signature_msg)
        else:
            msg = base_msg
        """
        msg = base_msg

        sender = Config.get("email_from", "SMTP")
        recipients = [email_to]
        if cc and not Config.is_testing():
            msg["Cc"] = cc
            recipients.append[cc]

        msg["Subject"] = subject
        msg["From"] = Config.get("email_from_name", "SMTP")
        msg["To"] = email_to
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid()
        try:
            self.smtp.sendmail(sender, recipients, msg.as_string().encode('ascii'))
            # self.smtp.send_message(sender, recipients, MIMEText(message, "plain", "utf-8"))
        except (smtplib.SMTPSenderRefused, Exception) as e:
            logger.error("{} → {} error: {}".format(sender, " + ".join(recipients), e))
            # if Config.is_debug(): import ipdb; ipdb.set_trace()
            return False
        else:
            return True
