import csv
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Dict

from validate_email import validate_email

from .config import Config, get_path
from .mail_draft import MailDraft


class Attachment:
    sent: bool  # True => sent, False => error while sending, None => not yet sent
    abroad: bool  # True => abroad e-mail is in Contacts dict, False => e-mail is file name, None => undeliverable (no e-mail)

    def __init__(self, filename):
        self.abroad = Config.ABROAD_MARK in filename
        self._sent = None
        self.filename = filename
        self.attach = True  # whether the file contents should be added as an e-mail attachment

        st = self.parser.stats

        if validate_email(self.mail):
            st[self.get_draft_name()][int(bool(self.sent))] += 1
        else:
            st["non_deliverable"] += 1
        # self.abroad = None
        st["totals"] += 1

    @property
    def path(self):
        return Path(Config.get_cache_dir(), self.filename)

    @property
    def sent(self):
        return self._sent

    @sent.setter
    def sent(self, value):
        if self._sent != value:
            if bool(self._sent) != bool(value):  # no effect if sent status chagnes from None (not tried) to False (not succeeded)
                r = self.parser.stats[self.get_draft_name()]
                # exchange the count from the not-sent to sent or vice verse
                r[int(value is not True)] -= 1
                r[int(value is True)] += 1
            self._sent = value

    @classmethod
    def init(cls, parser):
        cls.parser = parser

    @classmethod
    def reset(cls, stats):
        stats["abroad"] = [0, 0]  # abroad [not-sent, sent]
        stats["local"] = [0, 0]  # local [not-sent, sent]
        stats["non_deliverable"] = 0
        stats["totals"] = 0

    @classmethod
    def get_all(cls, abroad=None, sent=None, limit=float("inf"), threedots=False):
        o: Attachment
        for i, o in enumerate(cls.parser.attachments):
            if sent is not None and sent is not bool(o.sent):  # we want to filter either sent or not-sent attachments only
                continue
            if abroad is not None and any((abroad and not o.abroad, not abroad and o.abroad)):
                # filtering abroad/local attachments only
                continue
            if limit == 0:
                if threedots:
                    yield SimpleNamespace(mail="...")
                return
            else:
                limit -= 1
            yield o

    @property
    def mail(self):
        if self.abroad:
            return self.filename[self.filename.index(Config.ABROAD_MARK) + 2:]
        return self.filename

    @property
    def cc(self):
        """ Return cc header from Contacts. This has nothing in common with possible Cc header in the mail_draft! """
        cc = ""
        for domain in Contacts.get_domains(self.mail):
            if domain in Contacts.mail2cc:
                cc += Contacts.mail2cc[domain] + ";"
        return cc

    def get_draft_name(self):
        return "abroad" if self.abroad else "local"

    def get_draft(self):
        return Contacts.mail_draft[self.get_draft_name()]

    def get_envelope(self):
        return self.get_draft().get_envelope(self)


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
            return set([x[0] for x in re.findall("@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mail)])
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
