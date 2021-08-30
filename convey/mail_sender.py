import http.client
import logging
import re
import smtplib
import sys
from abc import abstractmethod, ABC
from socket import gaierror

from validate_email import validate_email

from envelope import Envelope
from .attachment import Attachment
from .config import Config

re_title = re.compile('<title>([^<]*)</title>')
logger = logging.getLogger(__name__)

OTRS_VERSION = 6

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

    def send_list(self, mails):
        """ Send a bunch of e-mail messages 
        :type mails: Union[list, generator]
        """
        sent_mails = 0
        total_count = 0
        status = None

        if self.start() is False:
            return False
        for attachment in iter(mails):  # make sure mails are generator to correctly count total_count
            attachment: Attachment
            e: Envelope = attachment.get_envelope()

            if e.message().strip() == "" or e.subject().strip() == "":
                # program flow should never allow lead us here
                print("Missing subject or mail body text.")
                return False

            if attachment.sent:
                # program flow should never allow lead us here
                print(f"Message for {attachment.mail} already sent, skipping!")
                continue

            for address in e.to():
                if not validate_email(address, check_dns=False, check_smtp=False):
                    logger.error("Erroneous e-mail: {}".format(address))
                    continue

            status = False
            # noinspection PyBroadException
            try:
                status = self.process(e)
            except KeyboardInterrupt:
                status = "interrupted"
                total_count += len(list(mails))
                break
            except Exception as e:
                logger.error(e)
                # if something fails (attachment FileNotFoundError, any other error),
                # we want tag the previously sent e-mails so that they will not be resend next time
                pass
            finally:
                if status:
                    t = "Marking as sent" if status == "interrupted" else "Sent"
                    s = ", ".join(e.recipients())
                    if Config.is_testing():
                        s += f" (intended for {attachment.mail})"
                    logger.warning(f"{t}: {s}")
                    sent_mails += 1
                    attachment.sent = True
                else:
                    logger.error(f"Error sending: {attachment.mail}")
                    attachment.sent = False
                total_count += 1
        self.stop()

        if status == "interrupted":
            print(f"Interrupted! We cannot be sure if the e-mail {attachment.mail} was sent but it is probable.")

        print("\nSent: {}/{} mails.".format(sent_mails, total_count))
        if sent_mails != total_count:
            print("Could not send all abroad mails. (Details in convey.log.)")


class MailSenderOtrs(MailSender):

    def _post_multipart(self, host, selector, fields, files, cookies):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return an appropriate http.client.HTTPResponse object.
        """

        # if not Config.get("otrs_check_ssl", "OTRS", get=bool):
        # import ssl
        # ssl._create_default_https_context = ssl._create_unverified_context  # XX once upon a day (10.2.2017), the certificate stopped working or whatever. This is an ugly solution - i think we may delete this line in few weeks
        # context = ssl._create_unverified_context()
        # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # context.options &= ~ssl.OP_NO_TLSv1

        content_type, body = self._encode_multipart_formdata(fields, files)
        body = bytes(body, "UTF-8")
        if "://" not in host:
            protocol = "https"
        else:
            protocol, host = host.split("://", 1)
        if protocol == "http":
            h = http.client.HTTPConnection(host)
        elif protocol == "https":
            h = http.client.HTTPSConnection(host)
        else:
            raise ValueError(f"Unknown protocol in the host {host}")
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
            print(" Line {}: Record missing CONTACTS field ".format(lineno))
        return valid

    @staticmethod
    def _check_response(response):
        response = response.decode("UTF-8")
        if Config.is_testing():
            logger.info(" Response length:\n " + str(len(response)))

        mo = re_title.search(response)
        if not mo:
            logger.warning(" Unrecognized response")
            logger.error(response)
            return False

        if Config.is_debug():
            logger.info("Got response\n" + response)

        title = mo.group(1)
        if 'Předat - Tiket - ' in title or 'Forward - Ticket - ' in title:
            # XX we are not sure sending succeeded. Ex: if we do not include "To" recipient, we land on the same page
            #   but no message will be send because the page will just state recipient is missing.
            #   However, this is not a priority, this mostly works. You can always use SMTP via --references flag.
            return True

        elif title == 'Login - OTRS':
            logger.warning("\n\n *** Not logged in or wrong session cookie ***")
        elif title in ('Fatal Error - Frontend -  OTRS', 'Fatal Error - Rozhraní -  OTRS'):
            logger.warning("\n\n *** Bad CSRF token ***")
        else:
            logger.warning(" Unrecognized response: " + title)
            logger.error(response)
        return False

    @staticmethod
    def ask_value(value, description=""):
        sys.stdout.write(f'Change {description} ({value})? [s]kip or paste it: ')
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
            if (force
                    or not self.parser.otrs_id or not self.parser.otrs_num
                    or not self.parser.otrs_cookie or not self.parser.otrs_token or not self.parser.attachment_name):
                self.parser.otrs_id = self.ask_value(self.parser.otrs_id, "ticket url-id")
                self.parser.otrs_num = self.ask_value(self.parser.otrs_num, "ticket long-num")
                self.parser.otrs_cookie = self.ask_value(self.parser.otrs_cookie, "cookie")
                self.parser.otrs_token = self.ask_value(self.parser.otrs_token, "token")
                self.parser.attachment_name = self.ask_value(self.parser.attachment_name, "attachment name")

            sys.stdout.write(f"Ticket id = {self.parser.otrs_id}, ticket num = {self.parser.otrs_num},"
                             f" cookie = {self.parser.otrs_cookie}, token = {self.parser.otrs_token},"
                             f" attachment_name = {self.parser.attachment_name}"
                             f"\nWas that correct? [y]/n ")
            if input().lower() in ("y", ""):
                return True
            else:
                force = True
                continue

    def process(self, e: Envelope):
        def assure_str(c):
            return c if isinstance(c, str) else ";".join(c)

        # body must be HTML because OTRS treats it as such
        # (we might do a convey option to determine whether OTRS treats a text as plain or html)
        message = e.message()
        if not any(x for x in ("<br", "<b>", "<i>", "<p", "<img") if x in message):
            message = e.message().replace("\n", "<br>\n")

        fields = (
            ("Action", "AgentTicketForward"),
            ("Subaction", "SendEmail"),
            ("TicketID", str(self.parser.otrs_id)),
            ("Email", e.from_().address),
            ("From", assure_str(e.from_())),
            ("To", assure_str(e.to())),  # mails can be delimited by comma or semicolon
            ("Subject", e.subject()),
            ("Body", message),
            ("ArticleTypeID", "1"),  # mail-external
            ("ComposeStateID", "4"),  # open
            ("ChallengeToken", self.parser.otrs_token),
        )

        try:  # XX convert "try" to if m := Config.get("signkeyid", "OTRS"):
            if OTRS_VERSION == 6:
                fields += ("EmailSecurityOptions", Config.get("signkeyid", "OTRS")),
            else:
                fields += ("SignKeyID", Config.get("signkeyid", "OTRS")),
        except KeyError:
            pass

        if e.cc():
            fields += ("Cc", assure_str(e.cc())),

        if e.bcc():
            fields += ("Bcc", assure_str(e.bcc())),

        attachment_contents = ""
        if self.parser.attachment_name and len(e.attachments()):
            attachment_contents = str(e.attachments()[0])
        if attachment_contents:
            files = (("FileUpload", self.parser.attachment_name, attachment_contents),)
        else:
            files = ()

        # OTRS3 Session
        # OTRS6 OTRSAgentInterface
        if OTRS_VERSION == 6:
            cookies = (('Cookie', f'OTRSAgentInterface={self.parser.otrs_cookie}'),)
        else:
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
        except Exception:
            import traceback
            logger.error(traceback.format_exc())
            logger.error(f"\nE-mail could not be send to the host {host}{selector} with the fields {fields}."
                  f" Are you allowed to send from this e-mail etc?")
            # input("Program now ends.")
            # quit()
            raise
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

    def process(self, e: Envelope):
        e.smtp(self.smtp)
        return bool(e.send(True))
