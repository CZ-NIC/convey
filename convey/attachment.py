from __future__ import annotations
from csv import reader as csvreader
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import TYPE_CHECKING

from validate_email import validate_email

from .config import Config
from .contacts import Contacts
from .types import Types

if TYPE_CHECKING:
    from .parser import Parser

class Attachment:
    sent: bool
    "True => sent, False => error while sending, None => not yet sent"

    abroad: bool
    "True => abroad e-mail is in Contacts dict, False => e-mail is file name, None => undeliverable (no e-mail)"

    def __init__(self, filename):
        self.abroad = Config.ABROAD_MARK in filename
        self._sent = None
        self.filename = filename
        self.used_in_body : bool = False
        "Whether the file contents should be added as an e-mail attachment. If set, we suppose, the attachment has been pasted to the body text via jinja template."

        st = self.parser.stats

        if validate_email(self.mail, check_dns=False, check_smtp=False):
            st[self.get_draft_name()][int(bool(self.sent))] += 1
        else:
            st["non_deliverable"] += 1
        st["totals"] += 1

    def get_paths_from_path_column(self):
        """ Load a column that was marked being of the path Type. Checks the file meet some security standards
            that are quite limiting (and possibly be reduced in the future)
            so that a crafted CSV would not pull up ~/.ssh or /etc/ files.

            :raises RuntimeError if there is security concern about an attachment
        """
        path = next((f for f in self.parser.fields if f.type == Types.path), None)

        with self.path.open() as f:
            reader = csvreader(f, dialect=self.parser.settings["dialect"])
            paths = [Path(row[path.col_i]) for row in reader]
            for path in paths:
                if str(path) != path.name:
                    raise RuntimeError(f"For security reasons, path must be just a file name: {path}")
                if not path.stat().st_mode & stat.S_IROTH:
                    raise RuntimeError(f"For security reasons, path must be readable to others: {path}")
                if path.is_symlink():
                    raise RuntimeError(f"For security reasons, path must not be a symlink: {path}")
            return paths

    @property
    def path(self):
        """ Path of the split CSV file (that contain rows having the same value in the split column). """
        return Path(Config.get_cache_dir(), self.filename)

    @property
    def sent(self):
        return self._sent

    @sent.setter
    def sent(self, value):
        if self._sent != value:
            # no effect if sent status changes from None (not tried) to False (not succeeded)
            if bool(self._sent) != bool(value):
                r = self.parser.stats[self.get_draft_name()]
                # exchange the count from the not-sent to sent or vice verse
                r[int(value is not True)] -= 1
                r[int(value is True)] += 1
            self._sent = value

    @classmethod
    def init(cls, parser):
        cls.parser : Parser = parser

    @classmethod
    def reset(cls, stats):
        stats["abroad"] = [0, 0]  # abroad [not-sent, sent]
        stats["local"] = [0, 0]  # local [not-sent, sent]
        stats["non_deliverable"] = 0
        stats["totals"] = 0

    @classmethod
    def get_all(cls, abroad=None, sent=None, limit=float("inf"), threedots=False):
        for i, o in enumerate(cls.parser.attachments):
            # we want to filter either sent or not-sent attachments only
            if sent is not None and sent is not bool(o.sent):
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
        """ Return cc header from Contacts.
            This has nothing in common with possible Cc header in the mail_draft template!
        """
        return Types.get_method(Types.abusemail, Types.cc_contact)(self.mail)

    def get_draft_name(self):
        return "abroad" if self.abroad else "local"

    def get_draft(self):
        return Contacts.mail_draft[self.get_draft_name()]

    def get_envelope(self):
        return self.get_draft().get_envelope(self)
