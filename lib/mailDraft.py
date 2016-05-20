# Mail management data structure
from collections import defaultdict
import os
import webbrowser
import subprocess
import re
from lib.config import Config


class MailDraft:

    """ Mail management data structure """
    def __init__(self, filename):
        self.text = False                
        self.templateFile = Config.get("mail_template_local")
        self.mailFile = Config.getCacheDir() + filename + ".txt" # ex: csirt/2015/mail_cz5615616.txt XMailDraft.dir +  + MailDraft.hash
        #self.guiEdit()

    # get body text
    def getBody(self):
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
        return (self.getSubject() + ": " + self.getBody()[0:50] + "... ").replace("\n"," ").replace("\r"," ")

    def _assureMailContents(self):
        self.text = self._loadText() # XX some text is always returned, following lines that manually edits text, will likely never be executed
        if self.text == False: # user didn't fill files in GUI
            print("Empty body text. Do you wish to open GUI for editation? [y]/n")
            if input().lower() in ("y",""):                
                self.guiEdit()
                print("Come back after filling in the mail.")
                return False # user fill GUI file, saves it and manually comes here to the method
            else:
                print("Do you wish to edit the text manually[y]/n")
                if input().lower() in ("y",""):
                    print("Write mail text. First line is subject. (Copy in to the terminal likely by Ctrl+Shift+V.)") # XX really is first line subject? It may not be implemented. We've always used gui.
                    self.text = input()
                else:
                    return False # bodytext not received
        return True

    def _loadText(self):
        """Loads body text and subject from the file."""
        with open(self.mailFile, 'r') as f:
            return f.read()

    # Opens file for mail text to GUI editation.
    # If file doesnt exists, it creates it from the template.
    def guiEdit(self):        
        if os.path.isfile(self.mailFile) == False:
            with open(self.templateFile, 'r') as template, open(self.mailFile , 'w+') as file:
                file.write(template.read())

        #webbrowser.open(mailFile) X this preferred method didnt work, console was fullfilled by errors
        subprocess.Popen(['gedit',self.mailFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


