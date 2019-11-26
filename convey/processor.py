import io
import logging
import operator
import traceback
from bdb import BdbQuit
from builtins import RuntimeWarning
from collections import defaultdict
from csv import reader as csvreader, writer as csvwriter
from datetime import datetime
from functools import reduce
from math import ceil
from pathlib import Path
from typing import Dict

from .config import Config
from .contacts import Attachment
from .dialogue import ask
from .types import Web
from .whois import Quota, Whois

logger = logging.getLogger(__name__)


def prod(iterable):  # XX as of Python3.8, replace with math.prod
    return reduce(operator.mul, iterable, 1)


class Processor:
    """ Opens the CSV file and processes the lines. """

    descriptors: Dict[str, object]  # location => file_descriptor, his csv-writer
    descriptorsStatsOpen: Dict[str, int]  # {location: count} XX(performance) we may use a SortedDict object

    def __init__(self, parser, rewrite=True):
        """

        :type rewrite: bool Previously created files will get rewritten by default. Not wanted when we're resolving invalid lines or so.
        """
        self.parser = parser
        if rewrite:
            self.files_created = set()

        self.unique_sets = defaultdict(set)
        self.descriptors_max = 1000  # XX should be given by the system, ex 1024
        self.descriptors_count = 0
        self.descriptorsStatsOpen = {}
        self.descriptorsStatsAll = defaultdict(int)
        self.descriptors = {}

    def process_file(self, file, rewrite=False, stdin=None):
        parser = self.parser
        self.__init__(parser, rewrite=rewrite)
        settings = parser.settings.copy()

        # apply setup
        adds = []  # convert settings["add"] to lambdas
        for f in settings["add"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
            adds.append((f.name, f.source_field.col_i_original, f.get_methods()))
        del settings["add"]
        settings["addByMethod"] = adds

        if [f for f in self.parser.fields if (not f.is_chosen or f.col_i_original != f.col_i)]:
            settings["chosen_cols"] = [f.col_i_original for f in self.parser.fields if f.is_chosen]

        if not settings["dialect"]:
            settings["dialect"] = parser.dialect

        Web.init(self.parser.get_computed_fields())

        # start file processing
        try:
            if stdin:
                source_stream = stdin
                settings["target_file"] = 1
            else:
                source_stream = open(file, "r")
                settings["target_file"] = str(parser.target_file)
            if parser.external_stdout:
                settings["target_file"] = 2
            # with open(file, "r") as sourceF:
            reader = csvreader(source_stream, dialect=parser.dialect)
            if parser.has_header:  # skip header
                reader.__next__()
            for row in reader:
                if not row:  # skip blank
                    continue
                parser.line_count += 1
                if parser.line_count == parser.line_sout:
                    now = datetime.now()
                    delta = (now - parser.time_last).total_seconds()
                    parser.time_last = now
                    if delta < 1 or delta > 2:
                        new_vel = ceil(parser.velocity / delta) + 1
                        if abs(new_vel - parser.velocity) > 100 and parser.velocity < new_vel:
                            # smaller accelerating of velocity (decelerating is alright)
                            parser.velocity += 100
                        else:
                            parser.velocity = new_vel
                    parser.line_sout = parser.line_count + 1 + parser.velocity
                    parser.informer.sout_info()
                    Whois.quota.check_over()
                try:
                    self.process_line(parser, row, settings)
                except BdbQuit:  # not sure if working, may be deleted
                    print("BdbQuit called")
                    raise
                except KeyboardInterrupt:
                    print(f"Keyboard interrupting on line number: {parser.line_count}")
                    s = "[a]utoskip LACNIC encounters" \
                        if self.parser.queued_lines_count and not Config.get("lacnic_quota_skip_lines", "FIELDS") else ""
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
                        parser.line_count -= 1  # let's pretend we didn't just do this row before and give it a second chance
                        self.process_line(parser, row, settings)

            if settings["aggregate"]:  # write aggregation results now because we skipped it in process_line when aggregating
                for location, data in self.parser.aggregation.items():
                    if location is 2:  # this is a sign that we store raw data to stdout (not through a CSVWriter)
                        t = parser.external_stdout  # custom object simulate CSVWriter - it adopts .writerow and .close methods
                    elif location is 1:  # this is a sign we output csv data to stdout
                        t = io.StringIO()
                        self.descriptors[1] = t, None  # put the aggregated data to the place we would attend them
                    else:
                        t = open(Path(Config.get_cache_dir(), location), "w")
                        if len(self.parser.aggregation) > 1:
                            print("\nSplit location: " + location)
                    v = self.parser.informer.get_aggregation(data)
                    #print(v)
                    t.write(v)
        finally:
            if not stdin:
                source_stream.close()
                if not self.parser.is_split:
                    self.parser.saved_to_disk = True
            elif not self.parser.is_split and 1 in self.descriptors:  # we have all data in a io.TextBuffer, not in a regular file
                # the data are in the self.descriptors[1]
                if Config.verbosity <= logging.INFO:
                    print("\n\n** Completed! **\n")
                result = self.descriptors[1][0].getvalue()
                print(result.strip())
                parser.stdout = result
                parser.stdout_sample = [row.split(parser.dialect.delimiter) for row in result.split("\n", 10)[:10]]
                self.parser.saved_to_disk = False
            if 2 in self.descriptors:
                # the data were in parser.stdout and were taken by the remote application
                del self.descriptors[2]

            self._close_descriptors()

        if self.parser.is_split:
            attch = set()
            for at in self.parser.attachments:
                attch.add(at.path)
            for f in self.files_created:
                if f not in attch and f != Config.INVALID_NAME:
                    # set that a mail with this attachment have not yet been sent
                    self.parser.attachments.append(Attachment(None, None, f))
            Attachment.refresh_attachment_stats(self.parser)

    def _close_descriptors(self):
        """ Descriptors have to be closed (flushed) """
        for f in self.descriptors.values():
            f[0].close()

    def process_line(self, parser, line, settings, fields=None):
        """
        Parses line – compute fields while adding, perform filters, pick or delete cols, split and write to a file.
        """
        try:
            if not fields:
                fields = line.copy()

                if len(fields) is not len(parser.first_line_fields):
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
                        list_lengths.append(len(val) or 1)
                if list_lengths:  # duplicate rows because we received lists amongst scalars
                    row_count = prod(list_lengths)
                    for i, f in enumerate(fields):  # 1st col returns 3 values, 2nd 2 values → both should have 3*2 = 6 values
                        if type(f) is not list:
                            fields[i] = [f]
                        # if we received empty list, row is invalid
                        # ex: missing IP of a hostname
                        if not fields[i]:
                            raise RuntimeWarning(i+1)
                        fields[i] *= row_count // len(fields[i])
                    it = zip(*fields)
                    fields = it.__next__()  # now we are sure fields has only scalar values
                    for v in it:  # duplicate row because one of lambdas produced a multiple value list
                        self.process_line(parser, line, settings, v)  # new row with scalar values only

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

            # aggregation: count column
            if settings["aggregate"]:
                # settings["aggregate"] = column to be grouped, [(sum, column to be summed)]
                # Ex: settings["aggregate"] = 1, [(Aggregate.sum, 2), (Aggregate.avg, 3)]
                # Ex: settings["aggregate"] = 0, [(Aggregate.count, 0)]
                # Ex: settings["aggregate"] = None, [(Aggregate.sum, 1)]
                # Ex: settings["aggregate"] = None, [(Aggregate.sum, 1), (Aggregate.avg, 1)]

                col_group_i = settings["aggregate"][0]
                grp = fields[col_group_i] if col_group_i is not None else None
                for i, (fn, col_data_i) in enumerate(settings["aggregate"][1]):
                    # counters[location file][grouped row][order in aggregation settings] = [sum generator, count]
                    loc = self.parser.aggregation[location]

                    if grp:  # it makes sense to compute total row because we are grouping
                        if None not in loc:
                            loc[None] = []
                        if len(loc[None]) <= i:
                            loc[None].append([fn(), 0])
                            next(loc[None][i][0])
                        if fn.__name__ == "list":
                            loc[None][i][1] = "(all)"  # we do not want to enlist whole table
                        else:
                            loc[None][i][1] = loc[None][i][0].send(fields[col_data_i])

                    if grp not in loc:
                        loc[grp] = []
                    if len(loc[grp]) <= i:
                        loc[grp].append([fn(), 0])
                        next(loc[grp][i][0])
                    loc[grp][i][1] = loc[grp][i][0].send(fields[col_data_i])
                return  # we will not write anything right know, aggregation results are not ready yet
        except BdbQuit:  # BdbQuit and KeyboardInterrupt caught higher
            raise
        except Quota.QuotaExceeded:
            parser.queued_lines_count += 1
            location = Config.QUEUED_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)
        except Exception as e:
            if Config.is_debug():
                traceback.print_exc()
                Config.get_debugger().set_trace()
            elif isinstance(e, RuntimeWarning):
                logger.warning(f"Cannot compute {e}. column at line: {line}")
            else:
                logger.warning(e, exc_info=True)
            parser.invalid_lines_count += 1
            location = Config.INVALID_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)

        if not location:
            return
        elif location in self.files_created:
            method = "a"
        else:
            method = "w"
            # print("File created", location, parser.delimiter.join(chosen_fields))
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
                t = w = parser.external_stdout  # custom object simulate CSVWriter - it adopts .writerow and .close methods
            else:
                if location is 1:  # this is a sign we output csv data to stdout
                    t = io.StringIO()
                else:
                    t = open(Path(Config.get_cache_dir(), location), method)
                w = csvwriter(t, dialect=settings["dialect"])
            self.descriptors[location] = t, w
            self.descriptors_count += 1
        self.descriptorsStatsAll[location] += 1
        self.descriptorsStatsOpen[location] = self.descriptorsStatsAll[location]
        f = self.descriptors[location]
        if method == "w" and parser.has_header:
            f[0].write(parser.header)
        f[1].writerow(chosen_fields)
