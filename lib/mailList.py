# datova struktura na spravu mailu
from collections import defaultdict
import os
import webbrowser
import subprocess

class MailList:
    """ Datova struktura na spravu mailu"""
    def __init__(self, listName, templateFile):
        self.text = False
        self.mails = defaultdict(set)
        self.listName = listName
        self.templateFile = templateFile
        self.mailFile = MailList.dir +  self.listName + MailList.hash + ".txt" # ex: csirt/2015/mail_cz5615616.txt        

        self.guiEdit()

    # Vraci set IP, ktera nemaji zadny e-mail.
    # Ma smysl jenom u listu ceskych adres mailCz. K orphan-IP nelze dohledat mail (a zrejme se vyhodi nebo poslou na ASN adresu).
    # U list svetovych adres mailWorld jsou orphany cele zeme, ke kterym musi dohledat kontakt operator.
    #
    def getOrphans(self):
        if "unknown" in self.mails:
            return self.mails["unknown"]
        else:
            return set()


    hash = "" # hash se pripoji k temp-souboru, ktery obsahuje bodytext
    def setHash(hash):
        MailList.hash = hash
    
    dir = "cache/" # vcetne lomitka
    def setDir(dir):
        MailList.dir = dir
        

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

        #print("Vypisuji text mailu:")
        #print(self.text)
        #print("\nVypsal jsem text mailu. J")

    def _assureMailContents(self):
        self.text = self._loadText() # XX nejaky text se vrati vzdy, nasledujici radky, kdy je mozno vlozit text rucne, se tedy zrejme neprovedou
        if self.text == False: # uzivatel jeste v GUI nevyplnil soubory
            print("Prázdný body text. Přejete si v GUI otevřít soubor k editaci? [y]/n")
            if input() in ("y","Y",""):
                # otevrit template mailu v GUI
                self.guiEdit()
                print("Po vyplnění textu mailu se vraťte.")
                return False # uživatel vyplnít GUI soubor, uloží jej a pak se ručně vrátí sem do metody
            else:
                print("Přejete si napsat text ručně? [y]/n")
                if input() in ("y","Y",""):
                    print("Vepište ručně text mailu. První řádek je subject. (Vkopírujte Ctrl+Shift+V.)") # XX vazne je prvni radek subject? Jeste jsem to neimplementoval
                    self.text = input()
                else:
                    return False # bodytext jsme neziskali
        return True

    def _loadText(self):
        """Nacte ze souboru text body a subject."""        
        with open(self.mailFile, 'r') as f:
            return f.read()

    def __str__(self):        
        result = ("Počet abusemailů: {0}\n".format(len(self.mails)))
        for mail in self.mails:
            result += "'{}' ({})\n".format(mail, len(self.mails[mail]))
        return result



    # Otevre soubor pro text z mailu ke GUI editaci.
    # Pokud soubor neexistuje, vytvori ho a vlozi do nej text ze souboru sablony.    
    def guiEdit(self):        
        if os.path.isfile(self.mailFile) == False: # soubor pro bodytext sablonu jeste neexistuje
            with open(self.templateFile, 'r') as template, open(self.mailFile , 'w+') as file: # nacte sablonu
                file.write(template.read()) # zapsat do textu mailu defaultni template

        #webbrowser.open(mailFile) X furt do konzole vypisuje error hlasky, nic nepomohlo
        subprocess.Popen(['gedit',self.mailFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

 


        