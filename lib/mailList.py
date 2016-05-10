# Mail management data structure
from collections import defaultdict
import os
import webbrowser
import subprocess
import re
from lib.config import Config

class MailList:

    """ Mail management data structure """
    def __init__(self, listName, templateFile):        
        self.text = False
        self.mails = defaultdict(_Mail) #defaultdict(set)
        self.listName = listName
        self.templateFile = templateFile
        self.mailFile = Config.getCacheDir() + self.listName + ".txt" # ex: csirt/2015/mail_cz5615616.txt XMailList.dir +  + MailList.hash
        self.guiEdit()

    # Clears mail structure.
    def resetMails(self):
        self.mails = defaultdict(_Mail)

    # Returns set of IPs without e-mail.
    # It has sense only in the local address list mailCz. To the orphan-IP can't be found e-mail (and they will be likely ignored or send to ASN e-mail).
    # In the case of foreign address mailWorld list, orphans are whole countries. CSIRT conctact has to be found.
    #
    def getOrphans(self):
        if "unknown" in self.mails:
            return self.mails["unknown"]
        else:
            return set()
        

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

    def __str__(self):
        result = ("Abusemails count: {0}\n".format(len(self.mails)))
        for mail in self.mails:            
            result += "'{}' ({})".format(mail, len(self.mails[mail]))            
            if self.mails[mail].cc:
                result += " cc: {} ".format(self.mails[mail].cc)            
            result += "\n"
            
        #print(result);import pdb; pdb.set_trace()
        return result

    ##
    # mail = mail@example.com;mail2@example2.com -> [example.com, example2.com]
    def getDomains(mail):
        try:
            #return set(re.findall("@([\w.]+)", mail))
            return set([x[0] for x in re.findall("@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mail)])
        except AttributeError:
            return []


    # Opens file for mail text to GUI editation.
    # If file doesnt exists, it creates it from the template.
    def guiEdit(self):        
        if os.path.isfile(self.mailFile) == False:
            with open(self.templateFile, 'r') as template, open(self.mailFile , 'w+') as file:
                file.write(template.read())

        #webbrowser.open(mailFile) X this preferred method didnt work, console was fullfilled by errors
        subprocess.Popen(['gedit',self.mailFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class _Mail(set):
    def __init__(self, state= None): # state=None because of unpickling. State gets values of set.
        self.cc = ""
        if state:
            self.update(state)

    def __setstate__(self,state): # this is called by pickle.load. State receives attributes (cc)
        self.__dict__ = state