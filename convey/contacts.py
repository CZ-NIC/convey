import csv
import re
from pathlib import Path
from typing import Dict

from .config import Config, get_path
from .mail_draft import MailDraft


class Contacts:
    mail2cc: Dict[str, str]
    country2mail: Dict[str, str]
    mail_draft: Dict[str, MailDraft]

    @classmethod
    def init(cls):
        """
        Refreshes list of abusemails (for Cc of the mails in the results) (config key contacts_cc)
        and csirtmails (country contact) (config key contacts_abroad)
        """
        cls.mail_draft = {"local": MailDraft(Config.get("mail_template")),
                          "abroad": MailDraft(Config.get("mail_template_abroad"))}
        cls.mail2cc = cls._update("contacts_cc")
        cls.country2mail = cls._update("contacts_abroad")

    @staticmethod
    def get_domains(mail: str):
        """ mail = mail@example.com;mail2@example2.com -> [example.com, example2.com] """
        try:
            # return set(re.findall("@([\w.]+)", mail))
            return set([x[0] for x in re.findall(r"@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mail)])
        except AttributeError:
            return []

    @staticmethod
    def _update(key: Dict[str, str]) -> object:
        """ Update info from an external CSV file. """
        file = get_path(Config.get(key))
        if not Path(file).is_file():  # file with contacts
            print("(Contacts file {} not found on path {}.) ".format(key, file))
            input()
            return {}
        else:
            with open(file, 'r') as f:
                reader = csv.reader(f)
                next(reader)  # skip header row
                try:
                    rows = {rows[0]: rows[1] for rows in reader}
                except IndexError:
                    raise IndexError(f"Error while loading file {file}")
                return rows