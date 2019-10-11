import csv
import re
from pathlib import Path
from typing import Dict

from validate_email import validate_email

from .config import Config, get_path
from .mailDraft import MailDraft


class Attachment:
    sent: bool  # True => sent, False => error while sending, None => not yet sent
    partner: bool  # True => partner e-mail is in Contacts dict, False => e-mail is file name, None => undeliverable (no e-mail)

    def __init__(self, partner, sent, path):
        self.partner = partner
        self.sent = sent
        self.path = path

    def get_abs_path(self):
        return Path(Config.get_cache_dir(), self.path)

    @classmethod
    def get_basic(cls, attachments):
        return cls._get(attachments, False)

    @classmethod
    def get_partner(cls, attachments):
        return cls._get(attachments, True)

    @classmethod
    def _get(cls, attachments, listed_only=False):
        for o in attachments:
            if o.path in [Config.UNKNOWN_NAME, Config.INVALID_NAME]:
                continue

            cc = ""

            if listed_only:
                if o.path in Contacts.csirtmails:
                    mail = Contacts.csirtmails[o.path]
                else:  # we don't want send to standard abuse mail, just to a partner
                    continue
            else:
                mail = o.path

            for domain in Contacts.get_domains(mail):
                if domain in Contacts.abusemails:
                    cc += Contacts.abusemails[domain] + ";"

            try:
                with open(o.get_abs_path(), "r") as f:
                    yield o, mail, cc, f.read()
            except FileNotFoundError:
                continue

    @classmethod
    def refresh_attachment_stats(cls, csv):
        attachments = csv.attachments
        st = csv.stats
        st["partner_count"] = [0, 0]
        st["abuse_count"] = [0, 0]
        st["non_deliverable"] = 0
        st["totals"] = 0

        for o in attachments:
            if o.path in Contacts.csirtmails:
                st["partner_count"][int(bool(o.sent))] += 1
                o.partner = True
            elif validate_email(o.path):
                st["abuse_count"][int(bool(o.sent))] += 1
                o.partner = False
            else:
                st["non_deliverable"] += 1
                o.partner = None
            st["totals"] += 1


class Contacts:
    abusemails: Dict[str, str]
    csirtmails: Dict[str, str]
    mailDraft: Dict[str, MailDraft]

    @classmethod
    def init(cls):
        """
        Refreshes list of abusemails (for Cc of the mails in the results) (config key contacts_local)
        and csirtmails (country contact) (config key contacts_foreign)
        """
        cls.mailDraft = {"local": MailDraft(Config.get("mail_template_basic")),
                         "foreign": MailDraft(Config.get("mail_template_partner"))}
        cls.abusemails = cls._update("contacts_local")
        cls.csirtmails = cls._update("contacts_foreign")

    @staticmethod
    def get_domains(mailStr):
        """ mail = mail@example.com;mail2@example2.com -> [example.com, example2.com] """
        try:
            # return set(re.findall("@([\w.]+)", mail))
            return set([x[0] for x in re.findall("@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mailStr)])
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
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                next(reader)  # skip header row
                rows = {rows[0]: rows[1] for rows in reader}
                return rows
