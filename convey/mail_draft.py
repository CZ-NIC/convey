from __future__ import annotations
import binascii
import logging
from base64 import b64decode
from pathlib import Path

from colorama import Fore
from envelope import Envelope
from jinja2 import Template, exceptions
from typing import TYPE_CHECKING

from .config import Config, get_path, edit

if TYPE_CHECKING:
    from .attachment import Attachment

PLAIN_DELIMITER = "\n"

HTML_DELIMITER = "<br>\n"

logger = logging.getLogger(__name__)


def is_html(s):
    return any(x in s for x in ("<br", "<p"))


class MailDraft:
    """ Mail management data structure """
    def __init__(self, filename):
        self.text = False
        self.template_file = get_path(filename)
        self.mail_file = Path(Config.get_cache_dir(), filename)
        self.file_assured = False  # we tried to load the e-mail text from the template and with the use of CLI flags

    @classmethod
    def init(cls, parser):
        cls.parser = parser

    def get_mail_preview(self) -> str:
        l = self.get_envelope().preview().splitlines()
        s = "\n".join(l[:40])
        if len(l) > 40:
            s += "\n..."
        return Fore.CYAN + s + Fore.RESET

    @staticmethod
    def _decode_text(t):
        base64_text = "data:text/plain;base64,"
        if t.startswith(base64_text):
            try:
                return b64decode(t[len(base64_text):]).decode("utf-8", "ignore")
            except binascii.Error:
                raise RuntimeError(f"Cannot decode text and create e-mail template: {t}")
        return t

    def edit_text(self, blocking=True):
        """ Opens file for mail text to GUI editing.
            Create the e-mail file from the template if had not existed before.
            If --subject, --body and --reference flags are used, they get re-merged into the template.
        """
        self._assure_file()
        edit(self.mail_file, mode=2, blocking=blocking)

    def _assure_file(self):
        """ Create the e-mail file from the template if had not existed before.
            If --subject, --body and --reference flags are used, they get re-merged into the template.
            :rtype: bool True if the e-mail file was newly created.
            """
        if self.file_assured:
            return False

        just_created = False

        # enrich e-mail text using the template
        if not self.mail_file.is_file():
            # t = Path(self.template_file).read_text()
            try:
                self.mail_file.write_text(self.template_file.read_text())
                logger.info(f"Writing from template {self.template_file}")
                just_created = True
            except FileNotFoundError:
                logger.warning(f"Template file {self.template_file} not found")

        # enrich e-mail text using the CLI variables `body`, `subject`, `references`
        subject = Config.get("subject")
        body = Config.get("body")
        references = Config.get("references")
        if subject or body or references:
            e = Envelope.load(self.mail_file).date(False)
            if subject:
                e.subject(self._decode_text(subject))
            if body:
                # reset loaded message from the template
                # to prevent the situation when template message is considered a text/plain alternative
                # and `--body` message is considered as a text/html alternative.
                # XX envelope might have method to delete message, like
                #  .message(False), .message(""), .message(text, alternative="replace")
                # We rather join template with the current message.
                template_message = e.message()
                message = self._decode_text(body).replace(r"\n", PLAIN_DELIMITER)
                if template_message:
                    # add / remove HTML from the template message
                    if is_html(template_message) and not is_html(message):
                        template_message = template_message.replace("<br>", PLAIN_DELIMITER)
                    elif not is_html(template_message) and is_html(message):
                        template_message = template_message.replace(PLAIN_DELIMITER, HTML_DELIMITER)
                    delimiter = HTML_DELIMITER if is_html(message) else PLAIN_DELIMITER
                    message = template_message + delimiter * 2 + message

                e.message("", alternative="auto") \
                    .message("", alternative="plain") \
                    .message("", alternative="html") \
                    .message(message)
            if references:
                if not (references.startswith("<") and references.endswith(">")):
                    references = f"<{references}>"
                e.header("Reference", references)
                e.bcc(Config.get("email_from_name", "SMTP"))

            # When a HTML is piped through --body flag, Content-Transfer-Encoding might change to ex: quoted-printable.
            # However when editing, we do not want to see quoted-printable garbage but plain text.
            # XX test should be added
            headers = [f"{k}: {v}" for k, v in e.as_message().items() if k.lower() != "content-transfer-encoding"]
            self.mail_file.write_text(PLAIN_DELIMITER.join((*headers, "", e.message())))

            # XDEPRECATED
            # So, we
            # 1) fetch the headers (except Content-Transfer-Encoding)
            # 2) insert blank line (between headers and the body)
            # 3) fetch the body while stripping out all <br> tags at the line ends
            #       (they should be re-inserted by envelope automatically and the readability increases)
            # XX test should be added
            # no_br_end = re.compile("<br\s?/?>$")
            # eml_text = [line for line in str(e)[:str(e).index("\n\n")].splitlines()
            #             if not line.startswith("Content-Transfer-Encoding")] +\
            #            [""] +\
            #            [no_br_end.sub("", line) for line in e.message().splitlines()]
            #
            # self.mail_file.write_text(PLAIN_DELIMITER.join(eml_text))

        self.file_assured = True
        return just_created

    def _make_envelope(self, attachment: Attachment):
        """ The format of the mail template is:
                Header: value
                Another-header: value
                Subject: value

                Body text begins after space.

            :raises RuntimeError if there is security concern about an attachment
        """
        try:
            self.text = self.mail_file.read_text()
        except FileNotFoundError:
            self.text = None

        if not self.text:  # user did not fill files in GUI
            return "Empty body text."

        if attachment and Config.get("jinja", "SMTP", get=bool):
            if self.apply_jinja(attachment) is False:
                return "Wrong jinja2 template."

        e = (Envelope
             .load(self.text)
             .signature("auto"))

        if not e.from_():
            e.from_(Config.get("email_from_name", "SMTP"))
        if not e.message() or not e.message().strip():
            return "Missing body text. Try writing 'Subject: text', followed by a newline and a text."
        if not e.subject():
            return "Missing subject. Try writing 'Subject: text', followed by a newline."
        if attachment:
            # set recipients
            e.to(attachment.mail)
            if attachment.cc:
                e.cc(attachment.cc)

            # attach the split CSV file
            if attachment.path and not attachment.used_in_body and Config.get('attach_files', 'SMTP', get=bool):
                e.attach(attachment.path, "text/csv", attachment.parser.attachment_name)

            # attach the paths from the path column (images, ...) in the split CSV file
            # If there is a trouble with an attachment,
            if Config.get('attach_paths_from_path_column', 'SMTP', get=bool):
                for path in attachment.get_paths_from_path_column():
                    try:
                        e.attach(path)
                    except FileNotFoundError as e:
                        return f"Cannot find the attachment: {e}"


        if Config.is_testing():
            e.recipients(clear=True)
            intended_to = attachment.mail if attachment else None
            e.to(Config.get('testing_mail'))
            # XX envelope might have method to delete message, like
            #  .message(False), .message(""), .message(text, alternative="replace")
            m = e.message()
            e.message("", alternative="auto") \
                .message("", alternative="plain") \
                .message("", alternative="html") \
                .message(f"This is testing mail only from Convey."
                         f" Don't be afraid, it was not delivered to: {intended_to}\r\n{m}")

        return e

    def get_envelope(self, attachment: Attachment = None) -> Envelope:
        """ :raises RuntimeError if there is security concern about an attachment """
        while True:
            just_created = self._assure_file()
            e = self._make_envelope(attachment)
            if isinstance(e, Envelope):
                if not just_created:  # even if Envelope is well generated, we invoke editing
                    return e
                e = "Editing just created file"
            # user fills GUI file, saves it and we get back to the method
            print(e)
            self.edit_text()

    def apply_jinja(self, attachment: Attachment):

        def print_attachment():
            """ Prints the attachment contents and prevent it to be attached.
                # XX may have header=False parameter to skip header.
            """
            attachment.used_in_body = True
            return attachment.path.read_text()

        def amount(count=2):
            """ Check if the attachment has at least count number of lines.
                Header is not counted.
            """
            if self.parser.settings["header"]:
                count += 1  # we skip header, so we must increment the count
            with attachment.path.open() as f:
                for i, _ in enumerate(f):
                    if i + 1 == count:
                        return True
            return False

        def row():
            """ Generate attachment row by row. Header is skipped. """
            with attachment.path.open() as f:
                if self.parser.settings["header"]:
                    next(f)
                for line in f:
                    yield line.strip().split(self.parser.settings["dialect"].delimiter)

        def joined(column: int, delimiter=", "):
            """ Return a column joined by delimiter  """
            return delimiter.join(r[column] for r in row())

        # Access first line fields
        first_row = next(row())
        try:
            self.text = Template(self.text).render(first_row=first_row,
                                                   row=row,
                                                   joined=joined,
                                                   amount=amount,
                                                   attachment=print_attachment)
        except exceptions.TemplateError as e:
            print(f"Template error: {e}")
            return False
