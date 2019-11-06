import io
import logging
import operator
import traceback
from bdb import BdbQuit
from collections import defaultdict
from csv import reader as csvreader, writer as csvwriter
from datetime import datetime
from functools import reduce
from math import ceil
from pathlib import Path
from typing import Dict

from convey.identifier import Web
from .config import Config
from .contacts import Attachment
from .dialogue import ask
from .whois import Quota, Whois

logger = logging.getLogger(__name__)


def prod(iterable):  # XX as of Python3.8, replace with math.prod
    return reduce(operator.mul, iterable, 1)


class Processor:
    """ Opens the CSV file and processes the lines. """

    descriptors: Dict[str, object]  # location => file_descriptor, his csv-writer
    descriptorsStatsOpen: Dict[str, int]  # {location: count} XX(performance) we may use a SortedDict object

    def __init__(self, csv, rewrite=True):
        """

        :type rewrite: bool Previously created files will get rewritten by default. Not wanted when we're resolving invalid lines or so.
        """
        self.csv = csv
        if rewrite:
            self.files_created = set()

        self.unique_sets = defaultdict(set)
        self.descriptors_max = 1000  # XX should be given by the system, ex 1024
        self.descriptors_count = 0
        self.descriptorsStatsOpen = {}
        self.descriptorsStatsAll = defaultdict(int)
        self.descriptors = {}

    def process_file(self, file, rewrite=False, stdin=None):
        csv = self.csv
        self.__init__(csv, rewrite=rewrite)
        settings = csv.settings.copy()

        # apply setup
        adds = []  # convert settings["add"] to lambdas
        for f in settings["add"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
            adds.append((f.name, f.source_field.col_i_original, f.get_methods()))
        del settings["add"]
        settings["addByMethod"] = adds

        if [f for f in self.csv.fields if (not f.is_chosen or f.col_i_original != f.col_i)]:
            settings["chosen_cols"] = [f.col_i_original for f in self.csv.fields if f.is_chosen]

        if not settings["dialect"]:
            settings["dialect"] = csv.dialect

        Web.init(self.csv.get_computed_fields())

        # start file processing
        try:
            if stdin:
                source_stream = stdin
                settings["target_file"] = 1
            else:
                source_stream = open(file, "r")
                settings["target_file"] = str(csv.target_file)
            if csv.stdout:
                settings["target_file"] = 2
            # with open(file, "r") as sourceF:
            reader = csvreader(source_stream, dialect=csv.dialect)
            if csv.has_header:  # skip header
                reader.__next__()
            for row in reader:
                if not row:  # skip blank
                    continue
                csv.line_count += 1
                if csv.line_count == csv.line_sout:
                    now = datetime.now()
                    delta = (now - csv.time_last).total_seconds()
                    csv.time_last = now
                    if delta < 1 or delta > 2:
                        new_vel = ceil(csv.velocity / delta) + 1
                        if abs(new_vel - csv.velocity) > 100 and csv.velocity < new_vel:
                            # smaller accelerating of velocity (decelerating is alright)
                            csv.velocity += 100
                        else:
                            csv.velocity = new_vel
                    csv.line_sout = csv.line_count + 1 + csv.velocity
                    csv.informer.sout_info()
                    Whois.quota.check_over()
                try:
                    self.process_line(csv, row, settings)
                except BdbQuit:  # not sure if working, may be deleted
                    print("BdbQuit called")
                    raise
                except KeyboardInterrupt:
                    print(f"Keyboard interrupting on line number: {csv.line_count}")
                    s = "[a]utoskip LACNIC encounters" \
                        if self.csv.queued_lines_count and not Config.get("lacnic_quota_skip_lines", "FIELDS") else ""
                    o = ask("Keyboard interrupt caught. Options: continue (default, do the line again), "
                            "[s]kip the line, [d]ebug, [e]nd processing earlier, [q]uit: ")
                    if o == "a":
                        Config.set("lacnic_quota_skip_lines", True, "FIELDS")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.")  # I dont know why.
                        Config.get_debugger().set_trace()
                    elif o == "s":
                        continue  # skip to the next line
                    elif o == "e":
                        return
                    elif o == "q":
                        self._close_descriptors()
                        quit()
                    else:  # continue from last row
                        csv.line_count -= 1  # let's pretend we didn't just do this row before and give it a second chance
                        self.process_line(csv, row, settings)
        finally:
            if not stdin:
                source_stream.close()
                if not self.csv.is_split:
                    self.csv.saved_to_disk = True
            elif not self.csv.is_split and 1 in self.descriptors:  # we have all data in a io.TextBuffer, not in a regular file
                if Config.verbosity <= logging.INFO:
                    print("\n\n** Completed! **\n")
                result = self.descriptors[1][0].getvalue()
                print(result.strip())
                csv.stdout = result
                self.csv.saved_to_disk = False
            if 2 in self.descriptors:
                del self.descriptors[2]

            self._close_descriptors()

        if self.csv.is_split:
            attch = set()
            for at in self.csv.attachments:
                attch.add(at.path)
            for f in self.files_created:
                if f not in attch and f != Config.INVALID_NAME:
                    # set that a mail with this attachment have not yet been sent
                    self.csv.attachments.append(Attachment(None, None, f))
            Attachment.refresh_attachment_stats(self.csv)

    def _close_descriptors(self):
        """ Descriptors have to be closed (flushed) """
        for f in self.descriptors.values():
            f[0].close()

    def process_line(self, csv, line, settings, fields=None):
        """
        Parses line – compute fields while adding, perform filters, pick or delete cols, split and write to a file.
        """
        try:
            if not fields:
                fields = line.copy()

                if len(fields) is not len(csv.first_line_fields):
                    raise ValueError("Invalid number of line fields: {}".format(len(fields)))

                # add fields
                list_lengths = []
                for col in settings["addByMethod"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
                    val = fields[col[1]]
                    for l in col[2]:
                        if isinstance(val, list):
                            # resolve all items, while flattening any list encountered
                            val = [y for x in (l(v) for v in val) for y in (x if type(x) is list else [x])]
                        else:
                            val = l(val)
                    fields.append(val)
                    if isinstance(val, list):
                        list_lengths.append(len(val))
                if list_lengths:  # duplicate rows because we received lists amongst scalars
                    row_count = prod(list_lengths)
                    for i, f in enumerate(fields):  # 1st col returns 3 values, 2nd 2 values → both should have 3*2 = 6 values
                        if type(f) is not list:
                            fields[i] = [f]
                        fields[i] *= row_count // len(fields[i])
                    it = zip(*fields)
                    fields = it.__next__()
                    for v in it:
                        self.process_line(csv, line, settings, v)  # duplicate row because single lambda produced a list

            # inclusive filter
            for f in settings["filter"]:  # list of tuples (col, value): [(23, "passed-value"), (13, "another-value")]
                if f[1] != fields[f[0]]:
                    return False

            # unique columns
            if settings["unique"]:
                for u in settings["unique"]:  # list of uniqued columns [2, 3, 5, ...]
                    if fields[u] in self.unique_sets[u]:  # skip line
                        return False
                else:  # do not skip line
                    for u in settings["unique"]:
                        self.unique_sets[u].add(fields[u])

            # pick or delete columns
            if settings["chosen_cols"]:
                chosen_fields = [fields[i] for i in settings["chosen_cols"]]  # chosen_cols = [3, 9, 12]
            else:
                chosen_fields = fields

            # determine location
            if type(settings["split"]) == int:
                location = fields[settings["split"]].replace("/", "-")  # split ('/' is a forbidden char in linux file names)
                if not location:
                    location = Config.UNKNOWN_NAME
                    chosen_fields = line  # reset to the original line (location will be reprocessed)
            else:
                location = settings["target_file"]
        except BdbQuit:  # BdbQuit and KeyboardInterrupt caught higher
            raise
        except Quota.QuotaExceeded:
            csv.queued_lines_count += 1
            location = Config.QUEUED_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)
        except Exception as e:
            if Config.is_debug():
                traceback.print_exc()
                Config.get_debugger().set_trace()
            else:
                logger.warning(e, exc_info=True)
            csv.invalid_lines_count += 1
            location = Config.INVALID_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)

        if not location:
            return
        elif location in self.files_created:
            method = "a"
        else:
            method = "w"
            # print("File created", location, csv.delimiter.join(chosen_fields))
            self.files_created.add(location)

        # choose the right file descriptor for saving
        # (we do not close descriptors immediately, if needed we close the one the least used)
        if location not in self.descriptorsStatsOpen:
            if self.descriptors_count >= self.descriptors_max:  # too many descriptors open, we have to close the least used
                key = min(self.descriptorsStatsOpen, key=self.descriptorsStatsOpen.get)
                self.descriptors[key][0].close()
                # print("Closing", key, self.descriptorsStatsOpen[key])
                del self.descriptorsStatsOpen[key]
                self.descriptors_count -= 1
            # print("Opening", location)

            if location is 2:  # this is a sign that we store raw data to stdout (not through a CSVWriter)
                t = w = csv.stdout  # custom object simulate CSVWriter - it adopts .writerow and .close methods
            else:
                if location is 1:  # this is a sign we output csv data to stdout
                    t = io.StringIO()
                else:
                    t = open(Path(Config.get_cache_dir(), location), method)
                w = csvwriter(t, dialect=settings["dialect"])
            self.descriptors[location] = t, w
            self.descriptors_count += 1
        # print("Printing", location)
        self.descriptorsStatsAll[location] += 1
        self.descriptorsStatsOpen[location] = self.descriptorsStatsAll[location]
        f = self.descriptors[location]
        if method == "w" and csv.has_header:
            f[0].write(csv.header)
        f[1].writerow(chosen_fields)
