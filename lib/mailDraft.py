""" Mail management data structure """
import os
import subprocess

from lib.config import Config


class MailDraft:
    def __init__(self, filename):
        self.text = False
        self.templateFile = Config.get(filename)
        self.mailFile = Config.getCacheDir() + filename + ".txt"  # ex: csirt/2015/mail_cz5615616.txt XMailDraft.dir +  + MailDraft.hash
        # self.guiEdit()

    def getBody(self):
        """ get body text """
        if self._assureMailContents() == True:
            CRLF = '\r\n'
            return CRLF.join(self.text.splitlines()[1:])
        else:
            return ""

    def getSubject(self):
        if self._assureMailContents() == True:
            return self.text.splitlines()[0]
        else:
            return ""

    def getMailPreview(self):
        return (self.getSubject() + ": " + self.getBody()[0:50] + "... ").replace("\n", " ").replace("\r", " ")

    def _assureMailContents(self):
        self.text = self._loadText()
        if not self.text:  # user didn't fill files in GUI
            print("Empty body text. Do you wish to open GUI for editation? [y]/n")
            if input().lower() in ("y", ""):
                self.guiEdit()
                print("Come back after filling in the mail.")
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

    def _loadText(self):
        """Loads body text and subject from the file."""
        try:
            with open(self.mailFile, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def guiEdit(self):
        """ Opens file for mail text to GUI editation. Created from the template if not exist. """
        if os.path.isfile(self.mailFile) == False:
            with open(self.templateFile, 'r') as template, open(self.mailFile, 'w+') as file:
                file.write(template.read())

        subprocess.Popen(['xdg-open', self.mailFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
