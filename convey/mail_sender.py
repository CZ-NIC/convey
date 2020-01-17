# Send mails throught OTRS
import http.client
import logging
import re
import smtplib
import sys
from abc import abstractmethod, ABC
from pathlib import Path
from socket import gaierror

from envelope import envelope
from validate_email import validate_email

from .config import Config
from .contacts import Attachment

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

    def send_list(self, mails, attach=True):
        """ Send a bunch of e-mail messages

            @type attach: bool Attach the file to the message. XX not used yet but should be working
        """
        sent_mails = 0
        total_count = 0

        if self.start() is False:
            return False
        for a in mails:
            # text_vars = {"CONTACTS": email_to, "FILENAME": self.parser.attachment_name, "TICKETNUM": self.parser.otrs_num}
            a: Attachment
            email_to = a.mail
            email_cc = a.cc
            attachment_path = a.path
            e: envelope = a.get_draft().get_envelope()
            if b"{ATTACHMENT}" in e._message:
                # XXX document this: if you write {ATTACHMENT} in the body,
                #  this will be replaced with the attachment contents and the attachment will no be included
                # XX .replace("\n", "<br>\n") OTRS sending sends text/plain – cannot have br conversion
                #   SMTP sending sends both text/plain+html – sometimes needs and sometimes forbids br conversion,
                #   depending on the envelope nl2br detection
                #   XX maybe envelope could expose nl2br and mime as envelope().data.mime
                #   along with .data.subject so that user can see directly?
                e._message = e._message.replace(b"{ATTACHMENT}",
                                                attachment_path.read_bytes().replace(b"\n", b"<br>\n"))
                attachment_path = None
            if e._message == b"" or e._subject == "":
                print("Missing subject or mail body text.")
                return False

            if a.sent:
                # XX this should be known in the dialog before, user should know earlier how many e-mails will be skipped
                print(f"Already sent to {email_to}, skipping!")
                continue

            if not attach:
                attachment_path = None

            if Config.is_testing():
                e._to.clear()
                e._cc.clear()
                e._bcc.clear()
                email_cc = False
                intended_to = email_to
                email_to = Config.get('testing_mail')
                e._message = bytes(f"This is testing mail only from Convey." \
                                   f" Don't be afraid, it wasn't delivered to: {intended_to}\r\n", "utf-8") + e._message

            if not validate_email(email_to):
                logger.error("Erroneous e-mail: {}".format(email_to))
                continue

            status = False
            # noinspection PyBroadException
            try:
                status = self.process(e, email_to, email_cc, attachment_path)
            except KeyboardInterrupt:
                status = "interrupted"
                total_count += len([x for x in mails])
                break
            except:
                # if something fails (attachment FileNotFoundError, any other error),
                # we want tag the previously sent e-mails so that they will not be resend next time
                pass
            finally:
                if status:
                    t = "Marking as sent" if status == "interrupted" else "Sent"
                    logger.warning(f"{t}: {email_to}")
                    sent_mails += 1
                    a.sent = True
                else:
                    logger.error(f"Error sending: {email_to}")
                    a.sent = False
                total_count += 1
        self.stop()

        if status == "interrupted":
            print(f"Interrupted! We cannot be sure if the e-mail {email_to} was sent but it is probable.")

        print("\nSent: {}/{} mails.".format(sent_mails, total_count))
        if sent_mails != total_count:
            print("Couldn't send all abroad mails. (Details in convey.log.)")


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
                    self.parser.otrs_id, self.parser.otrs_num, self.parser.otrs_cookie, self.parser.otrs_token,
                    self.parser.attachment_name))
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue

    def process(self, e: envelope, email_to, email_cc, attachment_path: Path):
        fields = (
            ("Action", "AgentTicketForward"),
            ("Subaction", "SendEmail"),
            ("TicketID", str(self.parser.otrs_id)),
            ("Email", Config.get("email_from", "SMTP")),
            ("From", Config.get("email_from_name", "SMTP")),
            ("To", email_to),  # mails can be delimited by comma or semicolon
            ("Subject", e._subject),
            ("Body", e._message.decode()),
            ("ArticleTypeID", "1"),  # mail-external
            ("ComposeStateID", "4"),  # open
            ("ChallengeToken", self.parser.otrs_token),
        )

        try:
            fields += ("SignKeyID", Config.get("signkeyid", "OTRS")),
        except KeyError:
            pass

        if email_cc:
            fields += ("Cc", email_cc),

        # load souboru k zaslani
        # attachment_contents = registryRecord.getFileContents() #csv.ips2logfile(mailList.mails[mail])

        attachment_contents = attachment_path.read_text()
        if self.parser.attachment_name and attachment_contents != "":
            files = (("FileUpload", self.parser.attachment_name, attachment_contents),)
        else:
            files = ()

        cookies = (('Cookie', 'Session=%s' % self.parser.otrs_cookie),)

        if Config.is_testing():
            print(" **** Testing info:")
            print(' ** Fields: ' + str(fields))
            # print(' ** Files length: ', len(files))
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
            print(
                "\nE-mail couldn't be send to the host {}{} with the fields {}. Are you allowed to send from this e-mail etc?".format(
                    host, selector, fields))
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

    def process(self, o, email_to, email_cc, path):
        sender = Config.get("email_from_name", "SMTP")
        o.from_(sender)
        o.to(email_to)
        o.smtp(self.smtp)

        if path:
            o.attach(path, "text/csv", self.parser.attachment_name)
        if email_cc:
            o.cc(email_cc)

        return bool(o.send(True))
