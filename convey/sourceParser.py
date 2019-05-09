# Source file parsing
import csv
import datetime
import logging
import ntpath
import os
import subprocess
import time
from collections import defaultdict
from os.path import join
from shutil import move
from typing import List

from math import ceil
from tabulate import tabulate

from .config import Config
from .contacts import Contacts, Attachment
from .csvGuesses import CsvGuesses
from .dialogue import Cancelled, is_yes, ask
from .informer import Informer
from .processor import Processor
from .whois import Whois

try:
    logging.FileHandler('whois.log', 'a')
except PermissionError:
    input("Launching convey from a dir you don't have write permissions for. Exiting.")
    quit()


class SourceParser:
    is_split: bool
    is_analyzed: bool
    attachments: List[Attachment]

    def __init__(self, source_file=False, stdin=None):
        print("Config file loaded from: {}".format(Config.path))
        self.is_formatted = False
        self.is_repeating = False
        self.dialect = None  # CSV dialect
        self.has_header = None  # CSV has hedialect.0ader
        self.header = None  # if CSV has header, it's here
        self.sample = ""
        self.fields = []  # CSV columns
        self.first_line_fields = []
        self.settings = defaultdict(list)
        self.redo_invalids = Config.getboolean("redo_invalids")
        self.otrs_cookie = False  # OTRS attributes to be linked to CSV
        self.otrs_id = Config.get("ticketid", "OTRS")
        self.otrs_token = False
        self.otrs_num = Config.get("ticketnum", "OTRS")
        self.attachment_name = "part-" + (ntpath.basename(source_file) if source_file else "attachment")
        self.ip_count_guess = None
        self.ip_count = None
        self.attachments = []  # files created if splitting
        self.invalid_lines_count = 0
        self._reset()

        # load CSV
        self.source_file = source_file
        self.target_file = None
        self.processor = Processor(self)
        self.informer = Informer(self)
        self.guesses = CsvGuesses(self)
        if source_file:  # we're analysing a file on disk
            self.size = os.path.getsize(source_file)
            self.stdin = None
            first_line, self.sample = self.guesses.get_sample(source_file)
        else:  # we're analysing an input text
            self.stdin = stdin
            self.size = len(self.stdin)
            if self.size == 0:
                print("Empty contents.")
                quit()
            first_line, self.sample = self.stdin[0], self.stdin[:7]

            # if that's a single cell, just print out some useful information and exit
            if len(stdin) == 1 and "," not in stdin[0]:
                if self.check_single_cell(stdin):
                    quit()

        self.lines_total = self.informer.file_len(source_file)  # sum(1 for line in open(source_file))
        self.informer.sout_info()
        try:
            # Dialog to obtain basic information about CSV - delimiter, header
            self.dialect, self.has_header = self.guesses.guess_dialect(self.sample)
            if not is_yes(f"Delimiter character found: '{self.dialect.delimiter}'\nQuoting character: '{self.dialect.quotechar}'\nHeader is present: "+("yes" if self.has_header else "not used")+"\nCould you confirm this?"):
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
            self.first_line_fields = csv.reader([first_line], dialect=self.dialect).__next__()
            if self.has_header:
                self.header = self.first_line_fields
            self.reset_settings()
            self.guesses.identify_cols()
        except Cancelled:
            print("Cancelled.")
            return
        self.informer.sout_info()

        # X self._guess_ip_count()
        # if not Dialogue.is_yes("Everything set alright?"):
        #    self.is_repeating = True
        #    continue
        # else:
        self.is_formatted = True  # delimiter and header has been detected etc.
        # break

    def get_fields_autodetection(self):
        """ returns list of tuples [ (field, detection), ("UrL", "url, hostname") ] """
        fields = []
        for i, field in enumerate(self.fields):
            s = ""
            if (i, field) in self.guesses.field_type and len(self.guesses.field_type[i, field]):
                possible_types = self.guesses.field_type[i, field]
                if "anyIP" in possible_types and ("ip" in possible_types or "portIP" in possible_types):
                    del possible_types["anyIP"]
                s = "detected: {}".format(", ".join(sorted(possible_types, key=possible_types.get)))
            else:
                for f, _, _type, custom_method in self.settings["add"]:
                    if field == f:
                        s = "computed from: {}".format(_type)
            fields.append((field, s))
        return fields

    def check_single_cell(self, stdin):
        """ Check if we are parsing a single cell and print out some meaningful details."""

        # init some basic parameters
        self.fields = self.first_line_fields = stdin
        self.dialect = csv.unix_dialect
        self.has_header = False
        self.guesses.identify_cols()
        Contacts.init()

        # tell the user what type we think their input is
        detection = self.get_fields_autodetection()[0][1]  # access the detection message for the first (and supposedly only) field
        if not detection:
            print("We couldn't parse the input text easily.")
            return False  # this is not a single cell, let's continue input parsing
        else:
            print("The inputted value " + detection)

        # transform the field by all known means
        seen = set()
        rows = []
        for _, target_type in self.guesses.methods.keys():  # loop all existing methods
            if target_type in seen:
                continue
            else:
                seen.add(target_type)
            fitting_type = self.guesses.get_fitting_type(0, target_type)
            #print(f"Target type:{target_type} Treat value as type: {fitting_type}")
            if fitting_type:
                val = stdin[0]
                for l in self.guesses.get_methods_from(target_type, fitting_type, None):
                    val = l(val)
                if type(val) is tuple and type(val[0]) is Whois:
                    val = val[1]
                elif type(val) is Whois:  # we ignore this whois temp value
                    continue
                rows.append((target_type, "×" if val is None else val))
        print("\n" + tabulate(rows, headers=("field", "value")))
        return True

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

        Config.has_header = self.has_header
        if self.dialect:
            class Wr:  # very ugly way to correctly get the output from csv.writer
                def write(self, row):
                    self.written = row

            wr = Wr()
            cw = csv.writer(wr, dialect=self.dialect)
            cw.writerow([self.fields[i] for i in self.settings["chosen_cols"]])
            Config.header = wr.written
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

    def _set_target_file(self):
        if not self.settings["split"] and self.settings["split"] is not 0:  # 0 is a valid column
            l = []
            if self.settings["filter"]:
                l.append("filter")
            if self.settings["uniqued"]:
                l.append("uniqued")
            if self.settings["redialected"]:
                l.append("redialected")
            if not len(self.settings["chosen_cols"]) == len(self.fields):
                l.append("shuffled")
            for name, _, _, _ in self.settings["add"]:
                l.append(name)
            if self.source_file:
                self.target_file = f"{ntpath.basename(self.source_file)}_{'_'.join(l)}.csv"
            else:
                self.target_file = f"output_{time.strftime('%Y-%m-%d %H:%M:%S')}.csv"
            self.is_split = False
        else:
            self.target_file = None
            self.is_split = True

    def run_analysis(self):
        """ Run main analysis of the file. """
        self._reset(hard=False)

        if Config.getboolean("autoopen_editor"):
            Contacts.mailDraft["local"].gui_edit()
            Contacts.mailDraft["foreign"].gui_edit()

        self.time_start = self.time_last = datetime.datetime.now().replace(microsecond=0)
        Contacts.init()
        #Config.update()
        self._set_target_file()
        self.processor.process_file(self.source_file, rewrite=True, stdin=self.stdin)
        self.time_end = datetime.datetime.now().replace(microsecond=0)
        self.lines_total = self.line_count  # if we guessed the total of lines, fix the guess now
        self.is_analyzed = True

        self.informer.sout_info()
        print("Whois analysis COMPLETED.\n")
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
        temp = path + ".running.tmp"
        try:
            move(path, temp)
        except FileNotFoundError:
            input("File {} not found, maybe resolving was run in the past and failed. Please rerun again.".format(path))
            return False

        self._reset_output()
        if basename in self.processor.files_created:
            self.processor.files_created.remove(basename)  # this file exists no more, if recreated, include header
        self.processor.process_file(temp)
        os.remove(temp)
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

        path = join(Config.get_cache_dir(), Config.UNKNOWN_NAME)
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

        path = join(Config.get_cache_dir(), Config.INVALID_NAME)
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
            print("\n"+s)
            self.resolve_invalid()

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['informer']
        del state['processor']
        state['dialect'] = self.dialect.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.informer = Informer(self)
        self.processor = Processor(self)
        self.dialect = csv.unix_dialect
        for k, v in state["dialect"].items():
            setattr(self.dialect, k, v)
