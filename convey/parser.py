# Source file parsing
import csv
import datetime
import logging
import re
import subprocess
import time
from collections import defaultdict
from itertools import zip_longest
from json import dumps
from math import ceil, inf
from pathlib import Path
from shutil import move
from typing import List

from tabulate import tabulate

from .config import Config, get_terminal_size
from .contacts import Contacts, Attachment
from .dialogue import Cancelled, is_yes, ask
from .identifier import Identifier, Types, Type, Web, TypeGroup, Checker
from .informer import Informer
from .processor import Processor
from .whois import Whois

logger = logging.getLogger(__name__)


class Parser:
    is_split: bool
    is_analyzed: bool
    attachments: List[Attachment]

    def __init__(self, source_file=False, stdin=None, prepare=True):
        self.is_formatted = False
        self.is_processable = False
        self.is_repeating = False
        self.dialect = None  # CSV dialect
        self.has_header = None  # CSV has header
        self.header: str = ""  # if CSV has header, it's here so that Processor can take it
        self.sample: List[str] = []  # lines  of the original file, including first line - possible header
        self.sample_parsed: List[List[str]] = []  # values of the prepared output (ex re-sorted), always excluding header
        self.fields: List[Field] = []  # CSV columns that will be generated to an output
        self.first_line_fields: List[str] = []  # CSV columns (equal to header if used) in the original file
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
        self.queued_lines_count = self.invalid_lines_count = 0
        self.line_count = 0
        self.time_last = self.time_start = self.time_end = None
        self.stdout = None  # when called from another program we communicate through this stream rather then through a file
        self.is_single_query = False  # CSV processing vs single_query check usage
        self.ranges = {}  # XX should be refactored as part of Whois
        self.ip_seen = {}  # XX should be refactored as part of Whois
        self._reset()
        self.selected: List[int] = []  # list of selected fields col_i that may be in/excluded and moved in the menu

        # load CSV
        self.source_file = source_file or self.invent_file_str()
        self.stdin = []
        self.stdout = None  # when accepting input from stdin and not saving the output into a file, we will have it here
        self.target_file = None
        self.saved_to_disk = None  # has been saved to self.target_file
        self.processor = Processor(self)
        self.informer = Informer(self)
        self.identifier = Identifier(self)

        if stdin:  # we're analysing an input text
            self.set_stdin(stdin)
        else:  # we're analysing a file on disk
            self.lines_total, self.size = self.informer.source_file_len(self.source_file)
            self.first_line, self.sample = self.identifier.get_sample(self.source_file)


        self.refresh()
        if prepare:
            self.prepare

    def refresh(self):
        """
        Refresh dependency files – contact list, we need to tell the attachments if they are deliverable.
        """
        Contacts.init()
        Attachment.refresh_attachment_stats(self)

    @property
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

            def join_quo(s):
                return "".join(s).replace("=\n", "").replace("=\r", "").replace("\n", r"\n").replace("\r", r"\r")

            len_ = len(self.sample)
            if len_ > 1 and re.search("[^A-Za-z0-9+/=]", join_base(self.sample)) is None:
                # in the sample, there is just base64-chars
                s = join_base(self.stdin)
                seems = False
                try:
                    if Checker.is_base64(s):  # all the input is base64 decodable
                        seems = True
                        self.set_stdin([s])
                except ValueError:
                    pass
            elif len_ > 1 and re.search("=[A-Z0-9]{2}", join_quo(self.sample)):
                s = join_quo(self.stdin)

                seems = False
                if Checker.is_quopri(s):
                    seems = True
                    self.set_stdin([s])
            elif not len_ or len_ > 1:
                seems = False

            if seems and Config.get("single_query") is not False:
                # identify_fields some basic parameters
                self.add_field([Field(self.stdin[0])])  # stdin has single field
                self.dialect = False
                self.has_header = False
                self.sample_parsed = [x for x in csv.reader(self.sample)]
                if self.identifier.identify_fields(quiet=True):
                    # tell the user what type we think their input is
                    # access the detection message for the first (and supposedly only) field
                    detection = self.get_fields_autodetection(False)[0][1]
                    if not detection and not Config.get("adding-new-fields"):
                        # this is not a single cell despite it was probable, let's continue input parsing
                        logger.info("We couldn't parse the input text easily.")
                    else:
                        if not detection:
                            # we are adding new fields - there is a reason to continue single processing
                            logger.info("Input value seems to be plaintext.")
                        else:
                            logger.info(f"Input value {detection}\n")
                        self.is_single_query = True
                        return self
                if Config.get("single_query"):
                    logger.info("Forced single processing")
                    self.fields[0].possible_types = {Types.plaintext: 1}
                    self.is_single_query = True
                    return self

        # we are parsing a CSV file
        self.informer.sout_info()
        try:
            # Dialog to obtain basic information about CSV - delimiter, header
            self.dialect, self.has_header, seems_single = self.identifier.guess_dialect(self.sample)
            uncertain = False

            if not Config.get("yes"):
                if Config.get("delimiter", "CSV"):
                    self.dialect.delimiter = Config.get("delimiter", "CSV")
                    print(f"Delimiter character set: '{self.dialect.delimiter}'\n", end="")
                else:
                    uncertain = True
                    s = "proposed" if seems_single else "found"
                    print(f"Delimiter character {s}: '{self.dialect.delimiter}'\n", end="")

                if Config.get("quote_char", "CSV"):
                    self.dialect.quotechar = Config.get("quote_char", "CSV")
                    print(f"Quoting character set: '{self.dialect.quotechar}'\n", end="")
                else:
                    uncertain = True
                    print(f"Quoting character: '{self.dialect.quotechar}'\n", end="")

                if Config.get("header", "CSV") is not None:
                    self.has_header = Config.get("header", "CSV")
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
            self.reset_settings()
            self.identifier.identify_fields()
        except Cancelled:
            print("Cancelled.")
            quit()
        self.informer.sout_info()
        self.is_formatted = True  # delimiter and header has been detected etc.
        return self

    def get_fields_autodetection(self, append_values=True):
        """ returns list of tuples [ (field, detection str), ("Url", "url, hostname") ]
        :type append_values: bool Append sample values to the informative result string.
        """
        fields = []
        for col, field in enumerate(self.fields):
            s = ""
            if field.is_new:
                s = f"computed from: {field.source_type}"
            elif field.possible_types:
                types = field.possible_types
                if Types.any_ip in types and (Types.ip in types or Types.port_ip in types):
                    del types[Types.any_ip]
                if Types.url in types and Types.wrong_url in types:
                    del types[Types.url]
                s = f"detected: {', '.join((str(e) for e in types))}"
                if append_values:
                    s += " – values: " + ", ".join(field.get_samples(3))
            fields.append((field, s))
        return fields

    def add_field(self, replace: List["Field"] = None, append: "Field" = None):
        fields = []
        if replace:
            self.fields = []
            fields = replace
        if append:
            fields += [append]

        for f in fields:
            f.col_i_original = f.col_i = len(self.fields)
            f.parser = self
            self.fields.append(f)

    def get_computed_fields(self):
        for f in self.fields:
            if f.is_new:
                yield f

    def set_stdin(self, stdin):
        self.stdin = stdin
        self.lines_total = self.size = len(self.stdin)
        if self.size:
            self.first_line, self.sample = self.stdin[0], self.stdin[:7]
        return self

    def run_single_query(self, json=False):
        """ Print out meaningful details about the single-value contents.
        :param json: If true, returns json.
        """
        # prepare the result variables
        rows = []
        data = {}
        Web.init()

        def append(target_type, val):
            """
            :type target_type: Field|Type If if is Field, it is added on purpose. If Type, convey just tries to add all.
            """
            data[str(target_type.name)] = val
            if type(val) is list and len(val) == 1:
                val = val[0]
            elif val is None or val == [] or (type(val) is str and val.strip() == ""):
                if Config.is_verbose() or not hasattr(target_type, "group" or target_type.group == TypeGroup.general):
                    # if not verbose and target_type is Type and no result, show just TypeGroup.general basic types
                    val = "×"
                else:
                    return
            else:
                val = str(val)
            rows.append([str(target_type.name), val])

        # get fields and their methods to be computed
        fields = [(f, f.get_methods()) for f in self.fields if f.is_new]  # get new fields only
        custom_fields = True
        if not fields:  # transform the field by all known means
            custom_fields = False
            if self.fields[0].type.is_plaintext_derivable:
                # Ex: when input is quoted_printable, we want plaintext only,
                # not plaintext re-encoded in base64 by default. (It's easy to specify that we want base64 by `--field base64`)
                types = [Types.plaintext]
            else:  # loop all existing methods
                types = Types.get_computable_types(ignore_custom=True)
            for target_type in types:
                if target_type in Config.get("single_query_ignored_fields", "FIELDS", get=list):
                    # do not automatically compute ignored fields
                    continue
                elif target_type.group == TypeGroup.custom:
                    continue
                fitting_type = self.identifier.get_fitting_type(0, target_type)
                if fitting_type:
                    methods = self.identifier.get_methods_from(target_type, fitting_type, None)
                    if methods:
                        fields.append((target_type, methods))

        method_cache = {}
        for field, methods in fields:
            if type(field) is Type:
                val = self.first_line
            else:
                val = self.sample_parsed[0][field.source_field.col_i]
            try:
                for i, l in enumerate(methods):
                    val_old = val
                    if (repr((val, methods[:i+1]))) in method_cache:
                        val = method_cache[(repr((val, methods[:i+1])))]
                        continue
                    if isinstance(val, list):
                        # resolve all items, while flattening any list encountered
                        val = [y for x in (l(v) for v in val) for y in (x if type(x) is list else [x])]
                    else:
                        val = l(val)
                    # We cache this value so that it will not be recomputed when crawling the same path on the graph again.
                    # Ex: `hostame → ip → country` and `hostname → ip → asn` will not call method `hostname → ip` twice (for each).
                    method_cache[(repr((val, methods[:i+1])))] = val
            except Exception as e:
                val = str(e)
            self.sample_parsed[0].append(val)
            append(field, val)

        # prepare json to return (useful in a web service)
        if "csirt-contact" in data and data["csirt-contact"] == "-":
            data["csirt-contact"] = ""  # empty value instead of a dash, stored in CsvGuesses-method-("whois", "csirt-contact")

        # output in text, json or file
        if Config.get("output"):
            logger.info(f"Writing to {self.target_file}...")
            self.target_file.write_text(dumps(data))
        if json:
            return dumps(data)
        elif Config.is_quiet() and len(rows) == 1:
            print(rows[0][1])
        else:
            # pad to the screen width
            width = get_terminal_size()[1]
            if rows and width:
                # size of terminal - size of the longest field name + 10 column space
                width -= max(len(row[0]) for row in rows) + 10
                for i, row in enumerate(rows):
                    val = row[1]
                    if width and len(str(val)) > width:  # split the long text by new lines
                        row[1] = "\n".join([val[i:i + width] for i in range(0, len(val), width)])
            if not rows and custom_fields:
                s = ", ".join([str(f) for f in fields])
                print(f"Cannot compute {s}")
            else:
                print(tabulate(rows, headers=("field", "value")))

    def reset_whois(self, hard=True, assure_init=False, slow_mode=False, unknown_mode=False):
        """

        :type assure_init: Just assure the connection between picklable Parser and current Whois class.
        """
        if not assure_init:
            if hard:
                self.whois_stats = defaultdict(int)
                self.ranges = {}
                self.ip_seen = {}
        Whois.init(self.whois_stats, self.ranges, self.ip_seen, self.stats, slow_mode=slow_mode, unknown_mode=unknown_mode)

    def reset_settings(self):
        self.settings = defaultdict(list)
        self.sample_parsed = [x for x in
                              csv.reader(self.sample[slice(1 if self.has_header else 0, None)], dialect=self.dialect)]
        self.add_field([Field(f) for f in self.first_line_fields])

    def _reset_output(self):
        self.line_count = 0
        self.line_sout = 1
        self.velocity = 0

    def _reset(self, hard=True):
        """ Reset variables before new analysis. """
        self.stats = defaultdict(set)
        self.queued_lines_count = self.invalid_lines_count = 0

        if self.dialect:
            class Wr:  # very ugly way to correctly get the output from csv.writer
                def write(self, row):
                    self.written = row

            wr = Wr()
            cw = csv.writer(wr, dialect=self.dialect)
            cw.writerow([f for f in self.fields if f.is_chosen])
            self.header = wr.written
        self._reset_output()
        # self.get_sample_values()  # assure sout_info would consume a result from duplicate_row

        self.time_start = None
        self.time_end = None
        self.time_last = None
        self.is_analyzed = False
        self.is_split = False
        self.is_processable = False
        self.attachments.clear()
        self.reset_whois(hard=hard)

    def prepare_target_file(self):
        if not self.settings["split"] and self.settings["split"] is not 0:  # 0 is a valid column
            self.target_file = self.invent_file_str()
            self.is_split = False
        else:
            self.target_file = None
            self.is_split = True

    def invent_file_str(self):
        l = []
        if self.settings["filter"]:
            l.append("filter")
        if self.settings["unique"]:
            l.append("uniqued")
        if self.settings["dialect"]:
            l.append("dialect")
        if [f for f in self.fields if not f.is_chosen]:
            l.append("shuffled")
        for f in self.settings["add"]:
            l.append(str(f))
        if hasattr(self, "source_file"):
            l.insert(0, Path(self.source_file).name)
            target_file = f"{'_'.join(l)}.csv"
        else:
            target_file = f"output_{time.strftime('%Y-%m-%d %H:%M:%S')}.csv"
        output = Config.get("output")
        return Path(str(output)) if output else Path(Config.get_cache_dir(), target_file)

    def run_analysis(self, autoopen_editor=None):
        """ Run main analysis of the file.
        :type autoopen_editor: bool May shadow config file value "autoopen_editor"
        """
        self._reset(hard=False)

        if (autoopen_editor or autoopen_editor is None) and Config.get("autoopen_editor") and self.csv.is_split:
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

        if self.queued_lines_count and Config.get("lacnic_quota_resolve_immediately", "FIELDS") is not False:
            self.resolve_queued(Config.get("lacnic_quota_resolve_immediately", "FIELDS"))

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

    def _resolve_again(self, path, basename, slow_mode=False, unknown_mode=False):
        self.reset_whois(assure_init=True, slow_mode=slow_mode, unknown_mode=unknown_mode)
        temp = str(path) + ".running.tmp"
        try:
            move(path, temp)
        except FileNotFoundError:
            input("File {} not found, maybe resolving was run in the past and failed. Please rerun again.".format(path))
            return False

        self._reset_output()
        lines_total, size = self.lines_total, self.size
        self.lines_total, self.size = self.informer.source_file_len(temp)
        if basename in self.processor.files_created:
            self.processor.files_created.remove(basename)  # this file exists no more, if recreated, include header
        self.processor.process_file(temp)
        Path(temp).unlink()
        self.lines_total, self.size = lines_total, size
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
        res = self._resolve_again(path, Config.UNKNOWN_NAME, unknown_mode=True)
        Whois.unknown_mode = False
        if res is False:
            return False

    def resolve_queued(self, force=False):
        count = self.queued_lines_count
        if not count:
            return True
        print(f"There are {self.queued_lines_count} queued rows")
        if Whois.quota.remains():
            print(f"We will have to wait {Whois.quota.remains()} s before LACNIC quota is over.")
        if not (force or is_yes(f"Reanalyse them?")):
            return False
        if Whois.quota.remains():
            print(f"Waiting till {Whois.quota.time()} or Ctrl-C to return", end="")
            try:
                while True:
                    time.sleep(1)
                    print(".", end="", flush=True)
                    if not Whois.quota.remains():
                        break
            except KeyboardInterrupt:
                return
            print(" over!")

        self.queued_lines_count = 0
        Whois.queued_ips = set()
        path = Path(Config.get_cache_dir(), Config.QUEUED_NAME)
        res = self._resolve_again(path, Config.QUEUED_NAME, slow_mode=True)
        if res is False:
            return False
        if self.queued_lines_count:
            solved = count - self.queued_lines_count
            if solved == 0:
                s = "No queued row resolved."
            else:
                s = f"Only {solved}/{count} queued rows were resolved."
            print("\n" + s)
            self.resolve_queued()

    def resolve_invalid(self):
        """ Process all invalid rows. """
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
            s = "Open the file in text editor (o) and make the rows valid, when done, hit y for reanalysing them," \
                " or hit n for ignoring them. [o]/y/n "
            res = ask(s)
            if res == "n":
                return False
            elif res == "y":
                break
            else:
                print("Opening the editor...")
                subprocess.Popen(['xdg-open', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        invalids = self.invalid_lines_count
        self.invalid_lines_count = 0
        if self._resolve_again(path, Config.INVALID_NAME) is False:
            return False
        if self.invalid_lines_count:
            solved = invalids - self.invalid_lines_count
            if solved == 0:
                s = "No invalid row resolved."
            else:
                s = f"Only {solved}/{invalids} invalid rows were resolved."
            print("\n" + s)
            self.resolve_invalid()

    def resort(self, chosens=[]):
        """
        :type chosens: List[str] Column IDs in str, ex: "1" points to column index 0
        """
        for f in self.fields:
            f.is_chosen = False
        l = [str(c + 1) for c in range(len(self.fields))]
        excluded = [f for f in l if f in set(l) - set(chosens)]
        transposed = list(zip(*self.sample_parsed))
        sp = []
        for i, (col, is_chosen) in enumerate([(col, True) for col in chosens] + [(col, False) for col in excluded]):
            col_i = self.identifier.get_column_i(col)
            self.fields[col_i].col_i = i
            if self.fields[col_i].is_new:
                sp.append([None] * len(self.sample_parsed))
            else:
                sp.append(transposed[col_i])
            self.fields[col_i].is_chosen = is_chosen
        self.fields = sorted(self.fields, key=lambda f: f.col_i)
        self.sample_parsed = list(map(list, zip(*sp)))  # force list preventing tuples

    def move_selection(self, direction=0, move_contents=False):
        """ Move cursor or whole columns
            :type move_contents: bool Move whole columns, not only cursor.
            :type direction: int +1 right, -1 left
        """
        selected = [f for f in self.fields if f.is_selected]
        if not selected:  # initial value is on an either border
            i = direction - 1 if direction > 0 else direction
            self.fields[i % len(self.fields)].is_selected = True
            if not move_contents:
                return
        if move_contents:
            for f in [f for f in self.fields if f.is_selected]:
                f.move(direction)
            self.is_processable = True
        else:
            for f in selected:  # deselect previous ones
                f.is_selected = False
            for f in selected:  # select new ones
                self.fields[(f.col_i + direction) % len(self.fields)].is_selected = True

    def get_sample_values(self):
        rows = []  # nice table formatting
        full_rows = []  # formatting that optically matches the Sample above
        for l in self.sample_parsed:
            row = []
            full_row = []
            for f, c in zip_longest(self.fields, l):
                if c is None:
                    c = f.compute_preview(l)
                row.append(f.color(c, True))
                full_row.append(f.color(c))
            rows.append(row)
            full_rows.append(full_row)
        return full_rows, rows

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['informer']
        del state['processor']
        del state['identifier']
        del state['ip_seen']  # delete whois dicts
        del state['ranges']
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


class Field:
    def __init__(self, name, is_chosen=True, source_field: "Field" = None, source_type=None, new_custom=None,
                 parser: Parser = None):
        self.col_i = None  # index of the field in parser.fields
        self.col_i_original = None  # original index before any sorting
        self.parser = None  # ref to parser
        self.name = str(name)
        self.is_chosen = is_chosen
        self.is_selected = False
        self.possible_types = {}
        if isinstance(name, Type):
            self.type = name
        else:
            self.type = None
        self.is_new = False
        if source_field:
            self.is_new = True
            self.source_field = source_field
            self.source_type = source_type if type(source_type) is Type else getattr(Types, source_type)
            self.new_custom = new_custom
        else:
            self.source_field = self.source_type = self.new_custom = None

    def __repr__(self):
        return f"<Field {self.name}({self.type})>"

    def move(self, direction=0):
        """ direction = +1 right, -1 left """
        p = self.parser
        i, i2 = self.col_i, (self.col_i + direction) % len(p.fields)
        p.fields[i2].col_i, self.col_i = i, i2

        def swap(i, i2):
            """ Swap given iterable elements on the positions i and i2 """

            def _(it):
                it[i], it[i2] = it[i2], it[i]

            return _

        transposed = list(zip(*p.sample_parsed))
        list(map(swap(i, i2), [p.fields, transposed]))
        p.sample_parsed = list(map(list, zip(*transposed)))

    def toggle_chosen(self):
        self.is_chosen = not self.is_chosen

    @property
    def type(self):
        if self._type:
            return self._type
        if self.possible_types:
            return next(iter(self.possible_types))

    @type.setter
    def type(self, val):
        self._type = val
        if val:
            self.possible_types[val] = 100

    def color(self, v, shorten=False):
        """ Colorize single line of a value. Strikes it if field is not chosen. """
        v = str(v)  # ex: Types.http_status returns int
        if shorten:
            v = v[:17] + "..." if len(v) > 20 else v
        l = []
        if not self.is_chosen:
            l.append("9")  # strike
        if self.is_selected:
            l.append("7")  # bold
        if self.is_new:
            l.append("33")  # yellow
        elif self.type is None or self.type == Types.plaintext:
            l.append("36")  # blue
        else:
            l.append("32")  # green
        s = "\033[" + ";".join(l) + f"m{v}\033[0m"
        return s

    def get(self, long=False, color=True):
        s = ""
        if long:
            if self.is_new:
                s = f"{self.name} from:\n{self.source_field}"
            elif self.has_clear_type():
                s = f"{self.name}\n   ({self.type})"
        if not s:
            s = self.name
        if color:
            s = "\n".join((self.color(c) for c in s.split("\n")))
        return s

    def has_clear_type(self):
        return self.type is not None and self.type != Types.plaintext

    def get_methods(self, target=None, start=None):
        if start is None:
            start = self.source_type
        if target is None:
            target = self.type
        return self.parser.identifier.get_methods_from(target, start, self.new_custom)

    def __str__(self):
        return self.name

    def get_samples(self, max_samples=inf, supposed_type=None, target_type=None):
        """ get few sample values of a field """
        c = min(len(self.parser.sample_parsed), max_samples)
        try:
            res = [self.parser.sample_parsed[line][self.col_i] for line in
                   range(0, c)]
        except IndexError:
            rows = []
            for l in self.parser.sample_parsed[slice(None, c)]:
                rows.append(self.compute_preview(l))
            res = rows
        if supposed_type and supposed_type.is_plaintext_derivable:
            rows, res = res.copy(), []
            for c in rows:
                for m in self.get_methods(Types.bytes if target_type == Types.charset else Types.plaintext, self.type):
                    c = m(c)
                res.append(c)
        return res

    def compute_preview(self, source_line):
        if Config.get("compute_preview"):
            c = source_line[self.source_field.col_i]
            if c is None:
                # source column has not yet been resolved because of column resorting
                # (note this will not a problem when processing)
                return "..."
            for l in self.get_methods():
                if isinstance(c, list):
                    # resolve all items, while flattening any list encountered
                    c = [y for x in (l(v) for v in c) for y in (x if type(x) is list else [x])]
                else:
                    c = l(c)
        else:
            c = "..."
        # add a newly computed value to source_parsed
        for _ in range(self.col_i - len(source_line) + 1):  # source_line is shorter than we need - fill the missing cols with Nones
            source_line.append(None)
        if type(c) is list and len(c) == 1:
            c = c[0]
        source_line[self.col_i] = c
        return c
