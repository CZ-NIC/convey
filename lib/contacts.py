import csv, os, re
from lib.config import Config
from lib.mailDraft import MailDraft

class Contacts:
    @classmethod
    def refresh(cls):
        cls.mailDraft = {"local": MailDraft("mail_template_local"), "foreign": MailDraft("mail_template_foreign")}
        cls.abusemails = cls._update("contacts_local")
        cls.countrymails = cls._update("contacts_foreign")

    @classmethod
    def getContacts(cls, keys, checkCountries=False):
        """ key = created filename, outputs mail and cc """
        for key in keys:
            if key == Config.UNKNOWN_NAME or key == Config.INVALID_NAME:
                continue

            mail = key
            cc = ""

            if checkCountries:
                if key in cls.countrymails:
                    mail = cls.countrymails[key]
                else:
                    continue

            for domain in cls.getDomains(mail):
                if domain in cls.abusemails:
                    record.cc += cls.abusemails[domain] + ";"

            with open(Config.getCacheDir() + key,"r") as f:
                yield mail, cc, f.read()

    @staticmethod
    def getDomains(mailStr):
        """ mail = mail@example.com;mail2@example2.com -> [example.com, example2.com] """
        try:
            #return set(re.findall("@([\w.]+)", mail))
            return set([x[0] for x in re.findall("@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mailStr)])
        except AttributeError:
            return []

    @staticmethod
    def _update(key):
        """ Update info from external CSV file. """
        file = Config.get(key)
        if os.path.isfile(file) == False: # file with contacts
            print("(Contacts file {} not found on path {}.) ".format(key, file))
            return False
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                rows = {rows[0]:rows[1] for rows in reader}
                return rows

