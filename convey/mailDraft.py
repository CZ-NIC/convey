""" Mail management data structure """
import subprocess
from pathlib import Path

from .config import Config, get_path


class MailDraft:
    def __init__(self, filename):
        self.text = False
        self.template_file = get_path(filename)
        self.mail_file = Path(Config.get_cache_dir(), filename)  # ex: csirt/2015/mail_cz5615616.txt XMailDraft.dir +  + MailDraft.hash

    def get_body(self):
        """ get body text """
        if self._assure_mail_contents():
            CRLF = '\r\n'
            return CRLF.join(self.text.splitlines()[1:])
        else:
            return ""

    def get_subject(self):
        if self._assure_mail_contents():
            return self.text.splitlines()[0]
        else:
            return ""

    def get_mail_preview(self) -> str:
        return (self.get_subject() + ": " + self.get_body()[0:50] + "... ").replace("\n", " ").replace("\r", " ")

    def _assure_mail_contents(self):
        self.text = self._load_text()
        if not self.text:  # user didn't fill files in GUI
            print("Empty body text. Do you wish to open GUI for editing? [y]/n")
            if input().lower() in ("y", ""):
                self.gui_edit()
                input("Hit Enter after filling in the e-mail...")
                return False  # user fill GUI file, saves it and manually comes here to the method
            else:
                print("Do you wish to edit the text manually[y]/n")
                if input().lower() in ("y", ""):
                    print(
                        "Write mail text. First line is subject. (Copy in to the terminal likely by Ctrl+Shift+V.)")  # XX really is first line subject? It may not be implemented. We've always used gui.
                    self.text = input()
                else:
                    return False  # bodytext not received
        return True

    def _load_text(self):
        """Loads body text and subject from the file."""
        try:
            with open(self.mail_file, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def gui_edit(self):
        """ Opens file for mail text to GUI editing. Created from the template if had not existed before. """
        if not Path(self.mail_file).is_file():
            with open(self.template_file, 'r') as template, open(self.mail_file, 'w+') as file:
                file.write(template.read())

        subprocess.Popen(['xdg-open', self.mail_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
