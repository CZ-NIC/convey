import logging
import re
import smtplib
import sys
from abc import abstractmethod, ABC
from socket import gaierror
from bs4 import BeautifulSoup
from requests import get, post

from validate_email import validate_email

from envelope import Envelope


from .dialogue import is_yes
from .parser import Parser
from .attachment import Attachment
from .config import Config

re_title = re.compile('<title>([^<]*)</title>')
logger = logging.getLogger(__name__)

OTRS_VERSION = 6


class MailSender(ABC):
    def __init__(self, parser):
        self.parser: Parser = parser

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

            try:
                e: Envelope = attachment.get_envelope()
            except RuntimeError as e:
                # troubles with an attachment
                total_count += 1
                logging.error('Troubles sending the mail for %s. %s', attachment.mail, e)
                continue

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
                Config.error_caught()
                # if something fails (attachment FileNotFoundError, any other error),
                # we want to tag the previously sent e-mails so that they will not be resend next time
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

    def _post_multipart(self, url, fields, cookies, attachments):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return an appropriate http.client.HTTPResponse object.
        """

        # import ssl
        # # XX once upon a day (10.2.2017), the certificate stopped working or whatever. This is an ugly solution - i think we may delete this line in few weeks
        # If this happens again, we may add a check that we are able to connect to OTRS before sending starts.
        # ssl._create_default_https_context = ssl._create_unverified_context
        # context = ssl._create_unverified_context()
        # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # context.options &= ~ssl.OP_NO_TLSv1

        # if Config.is_debug():
        # http.client.HTTPConnection.debuglevel = 1
        # requests_log = logging.getLogger("requests.packages.urllib3")
        # requests_log.setLevel(logging.INFO)
        # requests_log.propagate = True

        # upload attachments before the main request
        if attachments:
            # get FormID to pair attachments
            logger.debug("Receiving FormID")
            upload_form = get(url,
                              params={"ChallengeToken": self.parser.otrs_token,
                                      "Action": "AgentTicketForward",
                                      "TicketID": str(self.parser.otrs_id)},
                              cookies=cookies
                              )
            m = re.search(r'FormID" value="((\d|\.)*)"', upload_form.text)
            if m:
                form_id = m[1]
                self._clean_attachments(upload_form, url, form_id, cookies)
                for a in attachments:
                    logger.debug("Uploading %s", a.name)
                    post(url,
                         params={"Action": "AjaxAttachment",
                                 "Subaction": "Upload",
                                 "FormID": form_id,
                                 "ChallengeToken": self.parser.otrs_token
                                 },
                         cookies=cookies,
                         files={"Files": (a.name, a.data)}
                         )

                fields["FormID"] = form_id
            else:
                raise RuntimeError("Cannot get the FormID, unable to upload the attachments.")

        # If we had a single file, we could upload it with a single request that way:
        # `files={"FileUpload": (a.name, a.data)}`
        logger.debug("Submitting mail")
        r = post(url, data=fields, cookies=cookies)

        return r.text

    def _clean_attachments(self, upload_form, url, form_id, cookies):
        """ Remove all the attachments, received in the first ticket article so that they are not forwareded. """
        REMOVE_ALL_ATTACHMENTS = True
        def bs(): return BeautifulSoup(upload_form.text, features="html.parser")

        if REMOVE_ALL_ATTACHMENTS:
            for td in reversed(bs().find_all('a', {'class': 'AttachmentDelete'})): # why reversed? When deleted, others data-file-id shift down.
                self._remove_attachment(td['data-file-id'], form_id, url, cookies)
        elif self.parser.source_file:  # remove at least the attachment we have been split from (avoid duplicity)
            td = bs().find('td', {'class': 'Filename'}, lambda tag: tag.string == self.parser.source_file.name)
            if td:  # such attachment exists
                tr = td.parent
                data_file_id = tr.find('a', {'class': 'AttachmentDelete'})['data-file-id']
                self._remove_attachment(data_file_id, form_id, url, cookies)

    def _remove_attachment(self, data_file_id, form_id, url, cookies):
        logger.debug(f"Removing FileID={data_file_id} from the ticket article attachments") # XXX
        vv = post(url,
             params={"Action": "AjaxAttachment",
                     "Subaction": "Delete",
                     "FormID": form_id,
                     "ChallengeToken": self.parser.otrs_token,
                     "FileID": data_file_id
                     },
             cookies=cookies)

    @staticmethod
    def _check_record(record, lineno):
        valid = ('CONTACTS' in record)
        if not valid:
            print(" Line {}: Record missing CONTACTS field ".format(lineno))
        return valid

    @staticmethod
    def _check_response(response):
        if Config.is_testing():
            logger.info(" Response length:\n " + str(len(response)))

        mo = re_title.search(response)
        if not mo:
            logger.warning(" Unrecognized response")
            logger.error(response)
            return False

        # if Config.is_debug():
        #     logger.info("Got response\n" + response)

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

            if is_yes(f"Ticket id = {self.parser.otrs_id}, ticket num = {self.parser.otrs_num},"
                      f" cookie = {self.parser.otrs_cookie}, token = {self.parser.otrs_token},"
                      f" attachment_name = {self.parser.attachment_name}"
                      f"\nWas that correct?"):
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

        fields = {
            "Action": "AgentTicketForward",
            "Subaction": "SendEmail",
            "TicketID": str(self.parser.otrs_id),
            "Email": e.from_().address,
            "From": assure_str(e.from_()),
            "To": assure_str(e.to()),  # mails can be delimited by comma or semicolon
            "Subject": e.subject(),
            "Body": message,
            "ArticleTypeID": "1",  # mail-external
            "ComposeStateID": "4",  # open
            "ChallengeToken": self.parser.otrs_token,
        }

        try:  # XX as of Python3.8, convert "try" to if m := Config.get("signkeyid", "OTRS"):
            if OTRS_VERSION == 6:
                fields["EmailSecurityOptions"] = Config.get("signkeyid", "OTRS")
            else:
                fields["SignKeyID"] = Config.get("signkeyid", "OTRS")
        except KeyError:
            pass

        if e.cc():
            fields["Cc"] = assure_str(e.cc())
        if e.bcc():
            fields["Bcc"] = assure_str(e.bcc())

        attachments = e.attachments()
        cookies = {('OTRSAgentInterface' if OTRS_VERSION == 6 else 'Session'): self.parser.otrs_cookie}

        if Config.is_testing():
            print(" **** Testing info:")
            print(' ** Fields: ' + str(fields))
            print(' ** Files: ', [(a.name, len(a.data)) for a in attachments])
            print(' ** Cookies: ' + str(cookies))

        host = Config.get("otrs_host", "OTRS")
        url = (host if "://" in host else f"https://{host}") + Config.get("baseuri", "OTRS")
        try:
            res = self._post_multipart(url,
                                       fields=fields,
                                       cookies=cookies,
                                       attachments=e.attachments())
        except Exception:
            import traceback
            logger.error(traceback.format_exc())
            logger.error(f"\nE-mail could not be send to the host {url} with the fields {fields}."
                         f" Are you allowed to send from this e-mail etc?")
            raise
        if not res or not self._check_response(res):
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
