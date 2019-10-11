# Source file parsing
import csv
import datetime
import logging
import os
import re
import subprocess
import time
from collections import defaultdict
from json import dumps
from math import ceil
from pathlib import Path
from shutil import move
from typing import List

from tabulate import tabulate

from .config import Config
from .contacts import Contacts, Attachment
from .dialogue import Cancelled, is_yes, ask
from .identifier import Identifier, b64decode, Fields, get_computable_fields
from .informer import Informer
from .processor import Processor
from .whois import Whois

logger = logging.getLogger(__name__)


class SourceParser:
    is_split: bool
    is_analyzed: bool
    attachments: List[Attachment]

    def __init__(self, source_file=False, stdin=None, prepare=True):
        self.is_formatted = False
        self.is_repeating = False
        self.dialect = None  # CSV dialect
        self.has_header = None  # CSV has header
        self.header = ""  # if CSV has header, it's here so that Processor can take it
        self.sample = []  # lines from the first to up to eighth
        self.fields: List[str | "Field"] = []  # CSV columns that will be generated to an output
        self.first_line_fields: List[str] = []  # initial CSV columns (equal to header if header is used)
        self.second_line_fields: List[str] = []  # list of values on the 2nd line if available
        # settings:
        #    "add": new_field:Field,
        #           source_col_i:int - number of field to compute from,
        #           fitting_type:Field - possible type of source ,
        #           custom:tuple - If target is a 'custom' field, we'll receive a tuple (module path, method name).
        self.settings = defaultdict(list)
        self.redo_invalids = Config.get("redo_invalids")
        self.otrs_cookie = False  # OTRS attributes to be linked to CSV
        self.otrs_id = Config.get("ticketid", "OTRS")
        self.otrs_token = False
        self.otrs_num = Config.get("ticketnum", "OTRS")
        self.attachment_name = "part-" + (Path(source_file).name if source_file else "attachment")
        self.ip_count_guess = None
        self.ip_count = None
        self.attachments = []  # files created if splitting
        self.invalid_lines_count = 0
        self.line_count = 0
        self.time_last = self.time_start = self.time_end = None
        self.stdout = None  # when called from another program we communicate through this stream rather then through a file
        self.is_single_value = False  # CSV processing vs single_value check usage
        self._reset()

        # load CSV
        self.source_file = source_file
        self.stdin = []
        self.target_file = None
        self.processor = Processor(self)
        self.informer = Informer(self)
        self.identifier = Identifier(self)

        if self.source_file:  # we're analysing a file on disk
            self.size = Path(self.source_file).stat().st_size
            self.first_line, self.sample = self.identifier.get_sample(self.source_file)
            self.lines_total = self.informer.source_file_len()
        elif stdin:  # we're analysing an input text
            self.set_stdin(stdin)

        self.refresh()
        if prepare:
            self.prepare()

    def refresh(self):
        """
        Refresh dependency files – contact list, we need to tell the attachments if they are deliverable.
        """
        Contacts.init()
        Attachment.refresh_attachment_stats(self)

    def prepare(self):
        if self.size == 0:
            print("Empty contents.")
            quit()
        self.prepare_target_file()

        # check if we are parsing a single cell
        if self.stdin:
            seems = True

            def join_base(s):
                return "".join(s).replace("\n", "").replace("\r", "")

            len_ = len(self.sample)
            if len_ > 1 and re.search("[^A-Za-z0-9+/=]", join_base(self.sample)) is None:
                # in the sample, there is just base64-chars
                s = join_base(self.stdin)
                if not b64decode(s):  # all the input is base64 decodable
                    seems = False
                self.set_stdin([s])
            elif not len_ or len_ > 1:
                seems = False

            if seems:
                # init some basic parameters
                self.fields = self.stdin
                self.dialect = csv.unix_dialect
                self.has_header = False
                self.identifier.init()

                # tell the user what type we think their input is
                # access the detection message for the first (and supposedly only) field
                detection = self.get_fields_autodetection()[0][1]
                if not detection:
                    # this is not a single cell despite it was probable, let's continue input parsing
                    logger.info("We couldn't parse the input text easily.")
                else:
                    logger.info(f"Input value {detection}\n")
                    self.is_single_value = True
                    return self

        # we are parsing a CSV file
        self.informer.sout_info()
        try:
            # Dialog to obtain basic information about CSV - delimiter, header
            self.dialect, self.has_header = self.identifier.guess_dialect(self.sample)
            uncertain = False

            if Config.get("delimiter"):
                self.dialect.delimiter = Config.get("delimiter")
                print(f"Delimiter character set: '{self.dialect.delimiter}'\n", end="")
            else:
                uncertain = True
                print(f"Delimiter character found: '{self.dialect.delimiter}'\n", end="")

            if Config.get("quote_char"):
                self.dialect.quotechar = Config.get("quote_char")
                print(f"Quoting character set: '{self.dialect.quotechar}'\n", end="")
            else:
                uncertain = True
                print(f"Quoting character: '{self.dialect.quotechar}'\n", end="")

            if Config.get("header") is not None:
                self.has_header = Config.get("header")
            else:
                uncertain = True
                print(f"Header is present: " + ("yes" if self.has_header else "not used"))

            if uncertain and not is_yes("\nCould you confirm this?"):
                while True:
                    s = "What is delimiter " + (f"(default '{self.dialect.delimiter}')" if self.dialect.delimiter else "") + ": "
                    self.dialect.delimiter = input(s) or self.dialect.delimiter
                    if len(self.dialect.delimiter) != 1:
                        print("Delimiter must be a 1-character string. Invent one (like ',').")
                        continue
                    s = "What is quoting char " + (f"(default '{self.dialect.quotechar}')" if self.dialect.quotechar else "") + ": "
                    self.dialect.quotechar = input(s) or self.dialect.quotechar
                    break
                self.dialect.quoting = csv.QUOTE_NONE if not self.dialect.quotechar else csv.QUOTE_MINIMAL
                if not is_yes("Header " + ("" if self.has_header else "not found; ok?")):
                    self.has_header = not self.has_header
            self.first_line_fields = csv.reader([self.first_line], dialect=self.dialect).__next__()
            if len(self.sample) >= 2:
                self.second_line_fields = csv.reader([self.sample[1]], dialect=self.dialect).__next__()
            if self.has_header:
                self.header = self.first_line_fields
            self.reset_settings()
            self.identifier.init()
        except Cancelled:
            print("Cancelled.")
            return self
        self.informer.sout_info()

        # X self._guess_ip_count()
        # if not Dialogue.is_yes("Everything set alright?"):
        #    self.is_repeating = True
        #    continue
        # else:
        self.is_formatted = True  # delimiter and header has been detected etc.
        return self

    def get_fields_autodetection(self):  # Xreturn_first_types=False
        """ returns list of tuples [ (field, detection), ("UrL", "url, hostname") ] 
        :type return_first_types: If True, we return possible types of the first field in []
        """
        fields = []
        for i, field in enumerate(self.fields):
            s = ""
            if i in self.identifier.field_type and len(self.identifier.field_type[i]):
                possible_types = self.identifier.field_type[i]
                if Fields.any_ip in possible_types and (Fields.ip in possible_types or Fields.port_ip in possible_types):
                    del possible_types[Fields.any_ip]
                if Fields.url in possible_types and Fields.wrong_url in possible_types:
                    del possible_types[Fields.url]
                # XX tohle asi pryč, l=possible_types l = sorted(possible_types, key=possible_types.get), checkni, jestli to funguje bez toho
                # XXXXX ale když jsem to dal pryč, píše to Input value [('example.com', 'detected: hostname')])
                # if return_first_types:
                #     return l
                s = f"detected: {', '.join((str(e) for e in possible_types))}"
            else:
                for f, _, _type, custom_method in self.settings["add"]:
                    if field == f:
                        s = f"computed from: {_type}"
            fields.append((field, s))
        # if return_first_types:  # we did find nothing
        #     return []
        return fields

    def set_stdin(self, stdin):
        self.stdin = stdin
        self.lines_total = self.size = len(self.stdin)
        if self.size:
            self.first_line, self.sample = self.stdin[0], self.stdin[:7]
        return self

    def run_single_value(self, json=False, new_fields=[]):
        """ Print out meaningful details about the single-value contents.
        :type new_fields: List[Field] to compute
        """
        # prepare the result variables
        rows = []
        data = {}

        def append(target_type, val):
            rows.append([str(target_type), "×" if val is None else val])
            data[str(target_type)] = val

        # transform the field by all known means
        for target_type in new_fields or get_computable_fields():  # loop all existing methods
            if target_type.is_private:
                continue
            if not new_fields and target_type in Config.get("single_value_ignored_fields", get=list):
                # do not automatically compute ignored fields
                continue
            fitting_type = self.identifier.get_fitting_type(0, target_type, try_plaintext=bool(new_fields))

            # print(f"Target type:{target_type} Treat value as type: {fitting_type}")
            if fitting_type:
                val = self.first_line
                for l in self.identifier.get_methods_from(target_type, fitting_type, None):
                    val = l(val)
                if type(val) is tuple:  # XX and type(val[0]) is Whois:  # XX or SCRAPE WEB
                    val = val[1]
                # elif type(val) is Whois:  # we ignore this whois temp value
                #     continue
                append(target_type, val)

        # prepare json to return (useful in a web service)
        if "csirt-contact" in data and data["csirt-contact"] == "-":
            data["csirt-contact"] = ""  # empty value instead of a dash, stored in CsvGuesses-method-("whois", "csirt-contact")

        # output in text, json or file
        if Config.get("output"):
            logger.info(f"Writing to {self.target_file}...")
            self.target_file.write_text(dumps(data))
        if json:
            return dumps(data)
        else:
            # pad to the screen width
            try:
                _, width = (int(s) for s in os.popen('stty size', 'r').read().split())
            except (OSError, ValueError):
                pass
            else:
                if rows:
                    # size of terminal - size of the longest field name + 2 column space
                    width -= max(len(row[0]) for row in rows) + 2
                    for i, row in enumerate(rows):
                        val = row[1]
                        if width and len(str(val)) > width:  # split the long text by new lines
                            row[1] = "\n".join([val[i:i + width] for i in range(0, len(val), width)])

            print(tabulate(rows, headers=("field", "value")))

    def reset_whois(self, hard=True, assure_init=False):
        """

        :type assure_init: Just assure the connection between picklable SourceParser and current Whois class.
        """
        if not assure_init:
            self.whois_stats = defaultdict(int)
            if hard:
                self.ranges = {}
                self.whoisip_seen = {}
        Whois.init(self.whois_stats, self.ranges, self.whoisip_seen)

    def reset_settings(self):
        self.settings = defaultdict(list)
        self.fields = list(self.first_line_fields)
        self.settings["chosen_cols"] = list(range(len(self.fields)))

    def _reset_output(self):
        self.line_count = 0
        self.line_sout = 1
        self.velocity = 0

    def _reset(self, hard=True):
        """ Reset variables before new analysis. """
        self.stats = defaultdict(set)
        self.invalid_lines_count = 0

        if self.dialect:
            class Wr:  # very ugly way to correctly get the output from csv.writer
                def write(self, row):
                    self.written = row

            wr = Wr()
            cw = csv.writer(wr, dialect=self.dialect)
            cw.writerow([self.fields[i] for i in self.settings["chosen_cols"]])
            self.header = wr.written
        self._reset_output()

        self.time_start = None
        self.time_end = None
        self.time_last = None
        self.is_analyzed = False
        self.is_split = False
        self.is_processable = False
        self.attachments.clear()
        # self.is_formatted = False
        self.reset_whois(hard=hard)

    def prepare_target_file(self):
        target_file = None
        if not self.settings["split"] and self.settings["split"] is not 0:  # 0 is a valid column
            l = []
            if self.settings["filter"]:
                l.append("filter")
            if self.settings["unique"]:
                l.append("uniqued")
            if self.settings["dialect"]:
                l.append("dialect")
            if not len(self.settings["chosen_cols"]) == len(self.fields):
                l.append("shuffled")
            for name, _, _, _ in self.settings["add"]:
                l.append(str(name))
            if self.source_file:
                l.insert(0, Path(self.source_file).name)
                target_file = f"{'_'.join(l)}.csv"
            else:
                target_file = f"output_{time.strftime('%Y-%m-%d %H:%M:%S')}.csv"
            output = Config.get("output")
            self.target_file = Path(str(output)) if output else Path(Config.get_cache_dir(), target_file)
            self.is_split = False
        else:
            self.target_file = None
            self.is_split = True

    def run_analysis(self, autoopen_editor=None):
        """ Run main analysis of the file.
        :type autoopen_editor: bool May shadow config file value "autoopen_editor"
        """
        self._reset(hard=False)

        if (autoopen_editor or autoopen_editor is None) and Config.get("autoopen_editor"):
            Contacts.mailDraft["local"].gui_edit()
            Contacts.mailDraft["foreign"].gui_edit()

        self.time_start = self.time_last = datetime.datetime.now().replace(microsecond=0)
        self.refresh()
        # Config.update()
        self.prepare_target_file()
        self.processor.process_file(self.source_file, rewrite=True, stdin=self.stdin)
        self.time_end = datetime.datetime.now().replace(microsecond=0)
        self.lines_total = self.line_count  # if we guessed the total of lines, fix the guess now
        self.is_analyzed = True

        self.informer.sout_info()
        # print("Whois analysis COMPLETED.\n")
        if self.invalid_lines_count:
            self.resolve_invalid()

        if self.stats["czUnknownPrefixes"]:
            self.resolve_unknown()

        self.line_count = 0

    def _guess_ip_count(self):
        """ Determine how many IPs there are in the file.
        XX not used and not right (doesnt implement dialect but only delimiter) (doesnt implement stdin instead of source_file)
        """
        if self.urlColumn is None:
            try:
                max = 100000
                i = 0
                ipSet = set()
                fraction = None
                with open(self.source_file, 'r') as csvfile:
                    for line in csvfile:
                        i += 1
                        if self.has_header and i == 1:
                            continue
                        ip = line.split(self.dialect.delimiter)[self.ipColumn].strip()
                        ipSet.add(ip)
                        if i == (max - 1000):
                            fraction = len(ipSet)
                        if i == max:
                            break
                if i != max:
                    self.ip_count = len(ipSet)
                    print("There are {} IPs.".format(self.ip_count))
                else:
                    delta = len(ipSet) - fraction  # determine new IPs in the last portion of the sample
                    self.ip_count_guess = len(ipSet) + ceil((self.lines_total - i) * delta / i)
                    print(
                        "In the first {} lines, there are {} unique IPs. There might be around {} IPs in the file.".format(
                            i, len(ipSet), self.ip_count_guess))
            except Exception:
                print("Can't guess IP count.")

    def _resolve_again(self, path, basename):
        self.reset_whois(assure_init=True)
        temp = str(path) + ".running.tmp"
        try:
            move(path, temp)
        except FileNotFoundError:
            input("File {} not found, maybe resolving was run in the past and failed. Please rerun again.".format(path))
            return False

        self._reset_output()
        if basename in self.processor.files_created:
            self.processor.files_created.remove(basename)  # this file exists no more, if recreated, include header
        self.processor.process_file(temp)
        Path(temp).unlink()
        self._reset_output()
        self.informer.sout_info()
        return True

    def resolve_unknown(self):
        """ Process all prefixes with unknown abusemails. """

        if len(self.stats["ipsCzMissing"]) < 1:
            print("No unknown abusemails.")
            return

        s = "There are {0} IPs in {1} unknown prefixes. Should I proceed additional search for these {1} items?".format(
            len(self.stats["ipsCzMissing"]), len(self.stats["czUnknownPrefixes"]))
        if not is_yes(s):
            return

        path = Path(Config.get_cache_dir(), Config.UNKNOWN_NAME)
        self.stats["ipsCzMissing"] = set()
        self.stats["czUnknownPrefixes"] = set()
        Whois.unknown_mode = True
        if self._resolve_again(path, Config.UNKNOWN_NAME) is False:
            return False
        Whois.unknown_mode = False

    def resolve_invalid(self):
        """ Process all invalid rows. """
        invalids = self.invalid_lines_count
        if not self.invalid_lines_count:
            print("No invalid rows.")
            return

        path = Path(Config.get_cache_dir(), Config.INVALID_NAME)
        while True:
            print("There are {0} invalid rows".format(self.invalid_lines_count))
            try:
                with open(path, 'r') as f:
                    for i, row in enumerate(f):
                        print(row.strip())
                        if i > 5:
                            break
            except FileNotFoundError:
                input("File {} not found, maybe resolving was run in the past and failed. Please rerun again.".format(path))
                return False
            s = "Open the file in text editor (o) and make the rows valid, when done, hit y for reanalysing them, or hit n for ignoring them. [o]/y/n "
            res = ask(s)
            if res == "n":
                return False
            elif res == "y":
                break
            else:
                print("Opening the editor...")
                subprocess.Popen(['xdg-open', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.invalid_lines_count = 0
        if self._resolve_again(path, Config.INVALID_NAME) is False:
            return False
        if self.invalid_lines_count:
            solved = invalids - self.invalid_lines_count
            if solved == 0:
                s = "No invalid row resolved."
            else:
                s = ("Only {}/{} invalid rows were resolved.".format(solved, invalids))
            print("\n" + s)
            self.resolve_invalid()

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['informer']
        del state['processor']
        del state['identifier']
        state['dialect'] = self.dialect.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.informer = Informer(self)
        self.processor = Processor(self)
        self.dialect = csv.unix_dialect
        for k, v in state["dialect"].items():
            setattr(self.dialect, k, v)
        self.identifier = Identifier(self)
        self.identifier.init()
