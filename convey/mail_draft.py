""" Mail management data structure """
from pathlib import Path
from subprocess import call, Popen, PIPE, run

from envelope import envelope
from .config import Config, get_path


class MailDraft:
    def __init__(self, filename):
        self.text = False
        self.template_file = get_path(filename)
        self.mail_file = Path(Config.get_cache_dir(), filename)

    def get_mail_preview(self) -> str:
        return "\n".join(str(self.get_envelope()).splitlines()[:20])
        # return (self.get_subject() + ": " + self.get_body()[0:50] + "... ").replace("\n", " ").replace("\r", " ")

    def edit_text(self):
        if input("Do you wish to open GUI for editing? [y]/n ").lower() in ("y", ""):
            self.edit()
            input("Hit Enter after filling in the e-mail...")
        else:
            self.edit(False)
        return self.get_envelope()  # user fill GUI file, saves it and we get back to the method

    def get_envelope(self) -> envelope:
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
            print("Empty body text.")
            return self.edit_text()
        e = (envelope
             .load(self.text)
             .from_(Config.get("email_from_name", "SMTP")))
        if not e._message or not e._message.strip():
            print("Missing body text. Try writing 'Subject: text', followed by a newline a text.")
            self.text = False
            return self.edit_text()
        if not e._subject:
            print("Missing subject. Try writing 'Subject: text', followed by a newline.")
            self.text = False
            return self.edit_text()
        return e

    def edit(self, gui=True):
        """ Opens file for mail text to GUI editing. Created from the template if had not existed before. """
        if not Path(self.mail_file).is_file():
            Path(self.mail_file).write_text(Path(self.template_file).read_text())

        if gui:
            editor = run(["xdg-mime", "query", "default", "text/plain"], stdout=PIPE).stdout.split()[0]  # run: blocking, output
            Popen(["gtk-launch", editor, self.mail_file], stdout=PIPE, stderr=PIPE)  # Popen: non blocking
        else:
            call(["editor", self.mail_file]) # call: blocking, no output
