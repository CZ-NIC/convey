""" Mail management data structure """
import binascii
from base64 import b64decode
from pathlib import Path

from colorama import Fore
from jinja2 import Template, exceptions

from envelope import Envelope
from .config import Config, get_path, edit


class MailDraft:
    def __init__(self, filename):
        self.text = False
        self.template_file = get_path(filename)
        self.mail_file = Path(Config.get_cache_dir(), filename)

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
                return b64decode(t[len(base64_text):]).decode("utf-8")
            except binascii.Error:
                raise RuntimeError("Cannot decode text and create e-mail template: {t}")
        return t

    def edit_text(self, blocking=True):
        """ Opens file for mail text to GUI editing. Created from the template if had not existed before.
            If --subject or --body flags are merged into the template if used.
        """
        if not Path(self.mail_file).is_file():
            t = Path(self.template_file).read_text()
            subject = Config.get("subject")
            body = Config.get("body")
            if subject or body:
                e = Envelope.load(t).date(False)
                if subject:
                    e.subject(self._decode_text(subject))
                if body:
                    e.message(self._decode_text(body).replace(r"\n", "\n"))
                t = str(e)
            Path(self.mail_file).write_text(t)

        edit(self.mail_file, mode=2, blocking=blocking)

    def get_envelope(self, attachment: "Attachment" = None) -> Envelope:
        def _get_envelope():
            """ The format of the mail template is:
                    Header: value
                    Another-header: value
                    Subject: value

                    Body text begins after space.
            """
            try:
                self.text = Path(self.mail_file).read_text()
            except FileNotFoundError:
                self.text = None

            if not self.text:  # user didn't fill files in GUI
                return "Empty body text."

            if attachment and Config.get("jinja", "SMTP", get=bool):
                if self.jinja(attachment) is False:
                    return "Wrong jinja2 template."

            e = (Envelope
                 .load(self.text)
                 .signature("auto"))

            if not e._sender:  # XX this should be a publicly exposed method (and internal ._sender may change to ._from in the future)
                e.from_(Config.get("email_from_name", "SMTP"))
            if not e.message() or not e.message().strip():
                return "Missing body text. Try writing 'Subject: text', followed by a newline a text."
            if not e.subject():
                return "Missing subject. Try writing 'Subject: text', followed by a newline."
            if attachment:
                if attachment.path and attachment.attach and Config.get('attach_files', 'SMTP', get=bool):
                    e.attach(attachment.path, "text/csv", attachment.parser.attachment_name)

                if Config.is_testing():
                    e.recipients(clear=True)
                    intended_to = attachment.mail
                    e.to(Config.get('testing_mail'))
                    e.message(f"This is testing mail only from Convey."
                              f" Don't be afraid, it was not delivered to: {intended_to}\r\n{e._message}")
                else:
                    e.to(attachment.mail)
                    if attachment.cc:
                        e.cc(attachment.cc)

            return e

        while True:
            e = _get_envelope()
            if isinstance(e, Envelope):
                return e
            else:  # user fill GUI file, saves it and we get back to the method
                print(e)
                self.edit_text()

    def jinja(self, attachment: "Attachment"):

        def print_attachment():
            """ Prints the attachment contents and prevent it to be attached.
                # XX may have header=False parameter to skip header.
            """
            attachment.attach = False
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
