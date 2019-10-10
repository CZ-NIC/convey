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

import requests
from bs4 import BeautifulSoup
from tabulate import tabulate

from .config import Config
from .contacts import Contacts, Attachment
from .csvGuesses import CsvGuesses, b64decode
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

    def __init__(self, source_file=False, stdin=None, prepare=True):
        self.is_formatted = False
        self.is_repeating = False
        self.dialect = None  # CSV dialect
        self.has_header = None  # CSV has header
        self.header = None  # if CSV has header, it's here
        self.sample = []  # up to first eight lines
        self.fields = []  # CSV columns that will be generated to an output
        self.first_line_fields = []  # initial CSV columns (equal to header if header is used)
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
        self._reset()

        # load CSV
        self.source_file = source_file
        self.stdin = []
        self.target_file = None
        self.processor = Processor(self)
        self.informer = Informer(self)
        self.guesses = CsvGuesses(self)

        if self.source_file:  # we're analysing a file on disk
            self.size = Path(self.source_file).stat().st_size
            self.first_line, self.sample = self.guesses.get_sample(self.source_file)
            self.lines_total = self.informer.source_file_len()
        elif stdin:  # we're analysing an input text
            self.set_stdin(stdin)

        Contacts.init()
        if prepare:
            self.prepare()

    def prepare(self):
        if self.size == 0:
            print("Empty contents.")
            quit()
        self.prepare_target_file()

        # if that's a single cell, just print out some useful information and exit
        if self.stdin and self.check_single_cell():
            quit()

        self.informer.sout_info()
        try:
            # Dialog to obtain basic information about CSV - delimiter, header
            self.dialect, self.has_header = self.guesses.guess_dialect(self.sample)
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

    def get_fields_autodetection(self, return_first_types=False):
        """ returns list of tuples [ (field, detection), ("UrL", "url, hostname") ] 
        :type return_first_types: If True, we return possible types of the first field in []
        """
        fields = []
        for i, field in enumerate(self.fields):
            s = ""
            if (i, field) in self.guesses.field_type and len(self.guesses.field_type[i, field]):
                possible_types = self.guesses.field_type[i, field]
                if "anyIP" in possible_types and ("ip" in possible_types or "portIP" in possible_types):
                    del possible_types["anyIP"]
                if "url" in possible_types and "wrongURL" in possible_types:
                    del possible_types["wrongURL"]
                l = sorted(possible_types, key=possible_types.get)
                if return_first_types:
                    return l
                s = f"detected: {', '.join(l)}"
            else:
                for f, _, _type, custom_method in self.settings["add"]:
                    if field == f:
                        s = f"computed from: {_type}"
            fields.append((field, s))
        if return_first_types:  # we did find nothing
            return []
        return fields

    def set_stdin(self, stdin):
        self.stdin = stdin
        self.lines_total = self.size = len(self.stdin)
        if self.size:
            self.first_line, self.sample = self.stdin[0], self.stdin[:7]
        return self

    def check_single_cell(self):
        """ Check if we are parsing a single cell and print out some meaningful details."""

        def join_base(s):
            return "".join(s).replace("\n", "").replace("\r", "")

        len_ = len(self.sample)
        if len_ > 1 and re.search("[^A-Za-z0-9+/=]", join_base(self.sample)) is None:
            # in the sample, there is just base64-chars
            s = join_base(self.stdin)
            if not b64decode(s):  # all the input is base64 decodable
                return False
            self.set_stdin([s])
        elif not len_ or len_ > 1:
            return False

        # init some basic parameters
        self.fields = self.stdin
        self.dialect = csv.unix_dialect
        self.has_header = False
        self.guesses.identify_cols()

        # tell the user what type we think their input is
        detection = self.get_fields_autodetection(True)  # access the detection message for the first (and supposedly only) field
        if not detection:
            print("\nWe couldn't parse the input text easily.")
            return False  # this is not a single cell, let's continue input parsing
        else:
            print("\nInput value detected: " + " ,".join(detection))

        # prepare the result variables
        seen = set()
        rows = []
        json = {}

        def append(target_type, val):
            rows.append([target_type, "×" if val is None else val])
            json[target_type] = val

        # transform the field by all known means
        for _, target_type in self.guesses.methods.keys():  # loop all existing methods
            if target_type in seen:
                continue
            else:
                seen.add(target_type)
            fitting_type = self.guesses.get_fitting_type(0, target_type)
            # print(f"Target type:{target_type} Treat value as type: {fitting_type}")
            if fitting_type:
                val = self.first_line
                for l in self.guesses.get_methods_from(target_type, fitting_type, None):
                    val = l(val)
                if type(val) is tuple and type(val[0]) is Whois:
                    val = val[1]
                elif type(val) is Whois:  # we ignore this whois temp value
                    continue
                append(target_type, val)

        # scrape the website if needed
        if Config.get("scrape_url"):
            url = None
            for dict_ in [detection, json]:  # try to find and URL in input fields or worse in computed fields
                if url:
                    break
                for key in ["url", "hostname", "ip"]:  # prefer url over ip
                    if key in dict_:
                        url = self.first_line if dict_ is detection else dict_[key]
                        if key != "url":
                            url = "http://" + url
                        break
            if url:
                print(f"Scraping URL {url}...")
                append("scrape-url", url)
                try:
                    response = requests.get(url, timeout=3)
                except IOError as e:
                    append("status", 0)
                    append("scrape-error", str(e))
                else:
                    append("status", response.status_code)
                    response.encoding = response.apparent_encoding  # https://stackoverflow.com/a/52615216/2036148
                    soup = BeautifulSoup(response.text, features="html.parser")
                    [s.extract() for s in soup(["style", "script", "head"])]  # remove tags with low probability of content
                    text = re.sub(r'\n\s*\n', '\n', soup.text)  # reduce multiple new lines to singles
                    text = re.sub(r'[^\S\r\n][^\S\r\n]*[^\S\r\n]', ' ', text)  # reduce multiple spaces (not new lines) to singles
                    append("text", text)

        # prepare json to return (useful in a web service)
        if "csirt-contact" in json and json["csirt-contact"] == "-":
            json["csirt-contact"] = ""  # empty value instead of a dash, stored in CsvGuesses-method-("whois", "csirt-contact")

        # pad to the screen width
        try:
            _, width = (int(s) for s in os.popen('stty size', 'r').read().split())
        except (OSError, ValueError):
            pass
        else:
            width -= max(len(row[0]) for row in rows) + 2  # size of terminal - size of the longest field name + 2 column space
            for i, row in enumerate(rows):
                val = row[1]
                if width and len(str(val)) > width:  # split the long text by new lines
                    row[1] = "\n".join([val[i:i + width] for i in range(0, len(val), width)])

        # print out output
                # XX
                # if len(rows) == 1 and len(rows[0][1]) > 150:
                #     # we found a single possible output and that one is too long (ex: long base64 string), print it in lines, not in a table
                #     output = rows[0][1].replace("\\n", "\n")
                #     if Config.output:
                #         print(f"Writing to {self.target_file}...")
                #         self.target_file.write_text(output)
                #     print(f"\nField: {rows[0][0]}\n" + "*" * 50)
                #     print(output)
                # else:
        print("\n" + tabulate(rows, headers=("field", "value")))
        if Config.get("output"):
            print(f"Writing to {self.target_file}...")
            self.target_file.write_text(dumps(json))

        return dumps(json)

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
                l.append(name)
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
        Contacts.init()
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
        state['dialect'] = self.dialect.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.informer = Informer(self)
        self.processor = Processor(self)
        self.dialect = csv.unix_dialect
        for k, v in state["dialect"].items():
            setattr(self.dialect, k, v)
