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
from math import ceil
from operator import eq, ne
from pathlib import Path
from shutil import move
from typing import List

from tabulate import tabulate

from .attachment import Contacts, Attachment
from .config import Config, get_terminal_size
from .dialogue import Cancelled, is_yes, ask
from .field import Field
from .identifier import Identifier
from .informer import Informer
from .mail_draft import MailDraft
from .processor import Processor
from .types import Types, Type, Web, TypeGroup, Checker
from .whois import Whois

logger = logging.getLogger(__name__)


class Parser:
    is_split: bool
    is_analyzed: bool
    attachments: List[Attachment]

    def __init__(self, source_file: Path = False, stdin=None, types=None, prepare=True):
        self.is_formatted = False
        self.is_processable = False
        self.is_repeating = False
        self.dialect = None  # CSV dialect
        self.has_header = None  # CSV has header
        self.is_pandoc = False  # pandoc table format (second line to be skipped, a lot of spaces)
        self.header: str = ""  # if CSV has header, it's here so that Processor can take it
        self.sample: List[str] = []  # lines  of the original file, including first line - possible header
        self.sample_parsed: List[List[str]] = []  # values of the prepared output (ex re-sorted), always excluding header
        self.fields: List[Field] = []  # CSV columns that will be generated to an output
        self.first_line_fields: List[str] = []  # CSV columns (equal to header if used) in the original file
        self.types = []  # field types of the columns as given by the user
        # settings:
        #    * "add": new_field:Field,
        #             source_col_i:int - number of field to compute from,
        #             fitting_type:Field - possible type of source ,
        #             custom:tuple - If target is a 'custom' field, we'll receive a tuple (module path, method name).
        #    * "dialect": always present (set in controller just after parser.prepare()), output CSV dialect
        #    * "header": True if input CSV has header and output CSV should have it too.
        #                False if either input CSV has not header or the output CSV should omit it.
        #
        self.settings = defaultdict(list)
        self.redo_invalids = Config.get("redo_invalids")
        self.otrs_cookie = False  # OTRS attributes to be linked to CSV
        self.otrs_id = Config.get("ticketid", "OTRS")
        self.otrs_token = False
        self.otrs_num = Config.get("ticketnum", "OTRS")
        self.attachment_name = (source_file.name if source_file else "attachment")
        self.ip_count_guess = None
        self.ip_count = None
        self.attachments = []  # files created if splitting
        self.queued_lines_count: int
        self.invalid_lines_count: int
        self.unknown_lines_count: int
        self.line_count = 0
        self.time_start = self.time_end = None
        # when called from another program we communicate through this stream rather than through a file
        # XX this is not used right now, convey is not at the moment connectable to other programs
        # see __init__.py at revision d2cf88f48409ca8cc5e229954df34836de884445
        self.external_stdout = None
        self.is_single_query = False  # CSV processing vs single_query check usage
        self.ranges = {}  # XX should be refactored as part of Whois
        self.ip_seen = {}  # XX should be refactored as part of Whois
        # set by processor [location file][grouped row][order in aggregation settings] = [sum generator, count]
        self.aggregation = defaultdict(dict)
        self.refresh()
        self._reset(reset_header=False)
        self.selected: List[int] = []  # list of selected fields col_i that may be in/excluded and moved in the menu
        self.files_created = set()  # files created with this parser, will not be rewritten but appended to if reprocessing lines

        # load CSV
        self.source_file: Path = source_file or self.invent_file_str()
        self.stdin = []
        # When accepting input from stdin and not saving the output into a file
        #   or when setting this to True,
        #   the output will be here.
        self.stdout = Config.get("stdout")
        self.stdout_sample = None
        self.target_file = None
        self.saved_to_disk = None  # has been saved to self.target_file
        self.processor = Processor(self)
        self.informer = Informer(self)
        self.identifier = Identifier(self)

        if stdin:  # we're analysing an input text
            self.set_stdin(stdin)
        elif source_file:  # we're analysing a file on disk
            self.first_line, self.sample, self.is_pandoc = self.identifier.get_sample(self.source_file)
            self.lines_total, self.size = self.informer.source_file_len(self.source_file)
        self.set_types(types)
        # otherwise we are running a webservice which has no stdin nor source_file

        if prepare:
            self.prepare()

    def refresh(self):
        """
        Refresh dependency files – contact list Xwe need to tell the attachments if they are deliverable.
        """
        Contacts.init()
        Attachment.init(self)
        MailDraft.init(self)

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
                return "\n".join(s).replace("=\n", "").replace("=\r", "").replace("\n", r"\n").replace("\r", r"\r")

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
                        logger.info("We could not parse the input text easily.")
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

            l = []
            if self.is_pandoc:
                l.append("Pandoc table format detected (header were underlined by -------)")
            if Config.get("delimiter", "CSV"):
                self.dialect.delimiter = Config.get("delimiter", "CSV")
                l.append(f"Delimiter character set: '{self.dialect.delimiter}'")
                self.dialect.delimiter = self.dialect.delimiter.replace(r"\t", "\t").replace("TAB", "\t").replace("tab", "\t")
            else:
                uncertain = True
                s = "proposed" if seems_single else "found"
                l.append(f"Delimiter character {s}: '{self.dialect.delimiter}'")

            if Config.get("quote_char", "CSV"):
                self.dialect.quotechar = Config.get("quote_char", "CSV")
                l.append(f"Quoting character set: '{self.dialect.quotechar}'")
            else:
                uncertain = True
                l.append(f"Quoting character: '{self.dialect.quotechar}'")

            if Config.get("header", "CSV") is not None:
                self.has_header = Config.get("header", "CSV")
            else:
                uncertain = True
                l.append(f"Header is present: " + ("yes" if self.has_header else "not used"))

            if Config.get("yes"):
                uncertain = False
            else:
                print("\n".join(l))

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
            self.first_line_fields = csv.reader([self.first_line], skipinitialspace=self.is_pandoc, dialect=self.dialect).__next__()
            self.reset_settings()
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
            elif field.type:
                s = field.type
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
        """
        :param replace: Replace fields by the new field list.
        :param append: Append new field to the current list.
        """
        fields = []
        if replace:
            self.fields = []
            fields = replace
        if append:
            fields += [append]

        for f in fields:
            f.col_i_original = f.col_i = len(self.fields)
            if self.types and len(self.types) > f.col_i:
                f.type = self.types[f.col_i]
            f.parser = self
            self.fields.append(f)
        return self

    def set_types(self, types):
        if types:
            try:
                self.types = [getattr(Types, t) for t in types.split(",")]
            except AttributeError:
                print(f"Unknown type amongst: {types}")
                quit()
        else:
            self.types = []
        return self

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
            :type target_type: Field|Type If Field, it is added on purpose. If Type, convey just tries to add all.
            """
            data[str(target_type.name)] = [str(v) for v in val] if type(val) is list else (str(val) if val else "")
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
            elif not self.sample_parsed[0]:
                print(f"No field to compute {field} from.")
                return
            else:
                val = self.sample_parsed[0][field.source_field.col_i]
            try:
                for i, l in enumerate(methods):
                    val_old = val
                    if (repr((val, methods[:i + 1]))) in method_cache:
                        val = method_cache[(repr((val, methods[:i + 1])))]
                        continue
                    if isinstance(val, list):
                        # resolve all items, while flattening any list encountered
                        val = [y for x in (l(v) for v in val) for y in (x if type(x) is list else [x])]
                    else:
                        val = l(val)
                    # We cache this value so that it will not be recomputed when crawling the same path on the graph again.
                    # Ex: `hostame → ip → country` and `hostname → ip → asn` will not call method `hostname → ip` twice (for each).
                    method_cache[(repr((val, methods[:i + 1])))] = val
            except Exception as e:
                val = str(e)
            self.sample_parsed[0].append(val)
            if type(field) is Type or field.is_chosen:
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
        # when resetting settings, we free up any finished aggregation
        # (because informer wants to display it but the self.parser.settings["aggregate"] is gone
        self.aggregation = defaultdict(
            dict)  # self.aggregation[location file][grouped row][order in aggregation settings] = [sum generator, count]
        self.sample_parsed = [x for x in
                              csv.reader(self.sample[slice(1 if self.has_header else 0, None)], skipinitialspace=self.is_pandoc,
                                         dialect=self.dialect)]
        self.add_field([Field(f) for f in self.first_line_fields])
        self.identifier.identify_fields()

    def _reset_output(self):
        self.line_count = 0
        self.velocity = 0

    def _reset(self, hard=True, reset_header=True):
        """ Reset variables before new analysis.
        @type reset_header: False if we are in the constructor and added fields is not ready yet.
        """
        self.stats = defaultdict(set)
        Attachment.reset(self.stats)
        self.queued_lines_count = self.invalid_lines_count = self.unknown_lines_count = 0
        # self.aggregation[location file][grouped row][order in aggregation settings] = [sum generator, count]
        self.aggregation = defaultdict(dict)

        if reset_header:
            class Wr:  # very ugly way to correctly get the output from csv.writer
                def write(self, row):
                    self.written = row

            wr = Wr()
            cw = csv.writer(wr, dialect=self.settings["dialect"])
            cw.writerow([f for f in self.fields if f.is_chosen])
            self.header = wr.written
        self._reset_output()
        # self.get_sample_values()  # assure sout_info would consume a result from duplicate_row

        self.time_start = None
        self.time_end = None
        self.is_analyzed = False
        self.is_split = False
        self.is_processable = False
        self.attachments.clear()
        self.reset_whois(hard=hard)

    def prepare_target_file(self):
        if not self.settings["split"] and self.settings["split"] is not 0:  # 0 is a valid column
            self.is_split = False
            self.target_file = self.invent_file_str()
        else:
            self.is_split = True
            self.target_file = None
        return self.target_file

    def invent_file_str(self):
        l = []
        se = self.settings
        if se["filter"]:
            l.append("filter")
        if se["unique"]:
            l.append("uniqued")
        if se["dialect"] and (se["dialect"].delimiter != self.dialect.delimiter
                              or se["dialect"].quotechar != self.dialect.quotechar):
            l.append("dialect")
        if se["header"] is False:
            l.append("noheader")
        if [f for f in self.fields if not f.is_chosen]:
            l.append("shuffled")
        for f in se["add"]:
            # XX get external function name
            # if f.type == Types.external:
            #     l.append(str(f))
            # else:
            l.append(str(f))
        agg = se["aggregate"]
        if agg:
            if agg[0] is not None:
                l.append(f"{self.fields[agg[0]]}-grouped")
            for fn, col in agg[1]:
                l.append(f"{fn.__name__}-{self.fields[col]}")
        if hasattr(self, "source_file"):
            l.insert(0, self.source_file.stem)
            target_file = f"{'_'.join(l)}{self.source_file.suffix}"
        else:
            target_file = f"output_{time.strftime('%Y-%m-%d %H:%M:%S')}.csv"
        output = Config.get("output")
        return Path(str(output)) if output else Path(Config.get_cache_dir(), target_file)

    def run_analysis(self, autoopen_editor=None):
        """ Run main analysis of the file.
        :type autoopen_editor: bool May shadow config file value "autoopen_editor"
        """
        self.refresh()
        self._reset(hard=False)

        if (autoopen_editor or autoopen_editor is None) and Config.get("autoopen_editor") and self.is_split:
            Contacts.mail_draft["local"].edit_text(blocking=False)
            Contacts.mail_draft["abroad"].edit_text(blocking=False)

        self.time_start = datetime.datetime.now().replace(microsecond=0)
        self.prepare_target_file()
        self.processor.process_file(self.source_file, rewrite=True, stdin=self.stdin)
        self.time_end = datetime.datetime.now().replace(microsecond=0)
        self.lines_total = self.line_count  # if we guessed the total of lines, fix the guess now
        self.is_analyzed = True
        self.informer.sout_info()
        if self.invalid_lines_count:
            self.resolve_invalid()

        if self.unknown_lines_count:
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

    def _resolve_again(self, path, basename, var, key, reprocess_method, slow_mode=False, unknown_mode=False):
        count = getattr(self, var)  # ex: `count = self.invalid_lines_count`
        setattr(self, var, 0)
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
        if basename in self.files_created:
            self.files_created.remove(basename)  # this file exists no more, if recreated, include header
        dialect_tmp = self.dialect
        self.dialect = self.settings["dialect"]
        # XX missing start time reset here
        self.processor.process_file(temp)
        self.dialect = dialect_tmp
        Path(temp).unlink()
        self.lines_total, self.size = lines_total, size
        self._reset_output()
        self.informer.sout_info()

        if getattr(self, var):
            solved = count - getattr(self, var)
            print(f"\nNo {key} row resolved." if solved == 0 else f"\nOnly {solved}/{count} {key} rows were resolved.")
            reprocess_method()

    def stat(self, key):
        """ self.stats reader shorthand (no need to call len(...))"""
        return len(self.stats[key])

    def resolve_unknown(self):
        """ Process all prefixes with unknown abusemails.

        When split processing, unknown file is always generated; when single file processing,
        it is generated only if whois_reprocessable_unknown is True, otherwise cells remain empty

        It is not trivial to determine which IPs are really marked as unknowns.
        If we are splitting by abusemail, this may do. But if we are splitting by incident-contact,
        some of the IP with unknown abusemails are deliverable through csirtmail.
        Whois module does statistics but is not able to determine whether we use abusemail or incident-contact.

        That is the reason we are saying 'up to': "There are ... lines with up to ... IPs".
        """

        # (self.is_split or Config.get("whois_reprocessable_unknown", "FIELDS", get=bool)) \
        #    and (self.stats["prefix_local_unknown"] or self.stats["prefix_abroad_unknown"]):

        if not self.unknown_lines_count:
            # self.stats["ip_local_unknown"] and not self.stats["ip_abroad_unknown"]:
            input("No unknown abusemails. Press Enter to continue...")
            return

        l = []
        if self.stats["ip_local_unknown"]:
            l.append(f"{self.stat('ip_local_unknown')} IPs in {self.stat('prefix_local_unknown')} unknown prefixes")
        if self.stats["ip_abroad_unknown"]:
            l.append(f"{self.stat('ip_abroad_unknown')} IPs in {self.stat('prefix_abroad_unknown')} unknown abroad prefixes")
        s = f"There are {self.unknown_lines_count} lines with up to {' and '.join(l)}. Should I proceed additional search" \
            f" for these {self.stat('ip_local_unknown') + self.stat('ip_abroad_unknown')} IPs?"
        if not is_yes(s):
            return

        path = Path(Config.get_cache_dir(), Config.UNKNOWN_NAME)
        [self.stats[f"{a}_{b}_unknown"].clear() for a in ("ip", "prefix") for b in ("local", "abroad")]  # reset the stats matrix
        # res = self._resolve_again(path, Config.UNKNOWN_NAME, unknown_mode=True)
        self._resolve_again(path, Config.UNKNOWN_NAME, "unknown_lines_count", "unknown", self.resolve_unknown, unknown_mode=True)
        Whois.unknown_mode = False
        # if res is False:
        #     return False

    def resolve_queued(self, force=False):
        count = self.queued_lines_count
        if not count:
            return True
        print(f"There are {count} queued rows")
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

        path = Path(Config.get_cache_dir(), Config.QUEUED_NAME)
        Whois.queued_ips.clear()

        self._resolve_again(path, Config.QUEUED_NAME, "queued_lines_count", "queued", self.resolve_queued, slow_mode=True)
        # self.queued_lines_count = 0
        # res = self._resolve_again(path, Config.QUEUED_NAME, slow_mode=True)
        # if res is False:
        #     return False
        # if self.queued_lines_count:
        #     solved = count - self.queued_lines_count
        #     if solved == 0:
        #         s = "No queued row resolved."
        #     else:
        #         s = f"Only {solved}/{count} queued rows were resolved."
        #     print("\n" + s)
        #     self.resolve_queued()

    def resolve_invalid(self):
        """ Process all invalid rows. """
        if Config.get("yes", get=bool) and Config.is_quiet():
            return False
        if not self.invalid_lines_count:
            input("No invalid rows. Press Enter to continue...")
            return

        path = Path(Config.get_cache_dir(), Config.INVALID_NAME)
        print("There are {0} invalid rows".format(self.invalid_lines_count))
        while True:
            try:
                with open(path, 'r') as f:
                    for i, row in enumerate(f):
                        print(row.strip())
                        if i > 5:
                            break
            except FileNotFoundError:
                input("File {} not found, maybe resolving was run in the past and failed. Please rerun again.".format(path))
                return False
            if Config.get("yes", get=bool):
                res = "n"
            else:
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

        self._resolve_again(path, Config.INVALID_NAME, "invalid_lines_count", "invalid", self.resolve_invalid)
        # invalids = self.invalid_lines_count
        # self.invalid_lines_count = 0
        # if self._resolve_again(path, Config.INVALID_NAME) is False:
        #     return False
        # if self.invalid_lines_count:
        #     solved = invalids - self.invalid_lines_count
        #     if solved == 0:
        #         s = "No invalid row resolved."
        #     else:
        #         s = f"Only {solved}/{invalids} invalid rows were resolved."
        #     print("\n" + s)
        #     self.resolve_invalid()

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
            col_i = self.identifier.get_column_i(col, check="to be re-sorted")
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
        settings = self.settings
        unique_sets = defaultdict(set)

        rows = []  # nice table formatting
        full_rows = []  # formatting that optically matches the Sample above
        for line in self.sample_parsed:
            row = []
            for field, cell in zip_longest(self.fields, line):
                if cell is None:
                    cell = field.compute_preview(line)
                # suppress new lines in preview; however while processing, new lines are printed and this may render the CSV unloadable
                row.append((cell.replace("\n", r"\n"), field))

            # check if current line is filtered out
            line_chosen = True
            for include, col_i, val in settings["filter"]:  # (include, col, value), ex: [(True, 23, "passed-value"), ...]
                if (ne if include else eq)(val, row[col_i][0]):
                    line_chosen = False

            if settings["unique"]:  # unique columns
                for col_i in settings["unique"]:  # list of uniqued columns [2, 3, 5, ...]
                    if row[col_i][0] in unique_sets[col_i]:  # skip line
                        line_chosen = False
                        break
                else:  # do not skip line
                    for col_i in settings["unique"]:
                        unique_sets[col_i].add(row[col_i][0])

            # colorize the line
            g = lambda short: (field.color(cell, short, line_chosen) for cell, field in row)
            rows.append([*g(True)])
            full_rows.append([*g(False)])
        return full_rows, rows

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['informer']
        del state['processor']
        del state['identifier']
        del state['ip_seen']  # delete whois dicts
        del state['ranges']
        # counters generators may be removed (their state is not jsonpicklable)
        # however that means that when re-resolving after main processing, generators counts will reset
        # See comment in the Aggregation class, concerning generator serialization.
        # counters[location file][grouped row][order in aggregation settings] = [sum generator, count]
        for l in state['aggregation'].values():
            for g in l.values():
                for o in g:
                    o[0] = None
        state['dialect'] = self.dialect.__dict__.copy()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.informer = Informer(self)
        self.processor = Processor(self, rewrite=False)

        # input CSV dialect
        self.dialect = csv.unix_dialect()
        for k, v in state["dialect"].items():
            setattr(self.dialect, k, v)

        # output CSV dialect
        d = self.settings["dialect"]
        if d:
            self.settings["dialect"] = csv.unix_dialect()
            for k, v in d.items():
                setattr(self.settings["dialect"], k, v)

        self.identifier = Identifier(self)
        self.ranges = {}
        self.ip_seen = {}
