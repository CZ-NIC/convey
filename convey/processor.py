import io
import logging
import traceback
from bdb import BdbQuit
from collections import defaultdict
from csv import reader as csvreader, writer as csvwriter
from functools import reduce
from operator import eq, ne, mul
from pathlib import Path
from queue import Queue, Empty
from threading import Thread, Lock
from typing import Dict

from .attachment import Attachment
from .config import Config
from .dialogue import ask
from .types import Web
from .whois import Quota, UnknownValue

logger = logging.getLogger(__name__)


def prod(iterable):  # XX as of Python3.8, replace with math.prod
    return reduce(mul, iterable, 1)


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
            parser.files_created.clear()

        self.unique_sets = defaultdict(set)
        self.descriptors_max = 1000  # XX should be given by the system, ex 1024
        self.descriptors_count = 0
        self.descriptorsStatsOpen = {}
        self.descriptorsStatsAll = defaultdict(int)
        self.descriptors = {}
        self._lock = Lock()

    def process_file(self, file, rewrite=False, stdin=None):
        parser = self.parser
        inf = self.parser.informer
        self.__init__(parser, rewrite=rewrite)
        settings = parser.settings.copy()

        # apply setup
        # convert settings["add"] to lambdas
        adds = []
        for f in settings["add"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
            adds.append((f.name, f.source_field.col_i_original, f.get_methods()))
        del settings["add"]
        settings["addByMethod"] = adds

        # convert filter settings to pre (before line processing) and post that spare a lot of time
        #   (ex: skip lines before WHOIS processing)
        settings["f_pre"] = []
        settings["f_post"] = []
        for it in settings["filter"]:
            col_i = it[1]
            settings["f_post" if parser.fields[col_i].is_new else "f_pre"].append(it)
        del settings["filter"]

        settings["u_pre"] = []
        settings["u_post"] = []
        for col_i in settings["unique"]:  # list of uniqued columns [2, 3, 5, ...]
            settings["u_post" if parser.fields[col_i].is_new else "u_pre"].append(col_i)
        del settings["unique"]

        if [f for f in self.parser.fields if (not f.is_chosen or f.col_i_original != f.col_i)]:
            settings["chosen_cols"] = [f.col_i_original for f in self.parser.fields if f.is_chosen]

        # X if not settings["dialect"]:
        #     settings["dialect"] = parser.dialect
        # if settings["header"] is not False:
        #     settings["header"] = parser.has_header

        Web.init([f.type for f in self.parser.get_computed_fields()])

        # start file processing
        try:
            if stdin:
                source_stream = stdin
                settings["target_file"] = 1
            else:
                source_stream = open(file, "r")
                settings["target_file"] = str(parser.target_file)
            if parser.stdout is not None:
                settings["target_file"] = 1
            if parser.external_stdout:
                settings["target_file"] = 2
            # with open(file, "r") as sourceF:
            reader = csvreader(source_stream, skipinitialspace=parser.is_pandoc, dialect=parser.dialect)
            if parser.has_header:  # skip header
                reader.__next__()
                if parser.is_pandoc:  # second line is just first line underlining
                    reader.__next__()

            # prepare thread processing
            threads = []
            t = Config.get("threads")
            if t == "auto":
                # XX since threads are experimental, make this disable threads
                # In the future, enable it when using DNS and disable when using WHOIS (that may lead to duplicite calls)
                thread_count = 0
            elif type(t) is bool:
                thread_count = 10 if t else 0
            else:
                thread_count = int(t)

            if thread_count:
                q = Queue(maxsize=thread_count + 2)

                def x():
                    while True:
                        m = q.get()
                        if m is False:  # kill signal received
                            q.task_done()
                            return
                        parser.line_count += 1
                        self.process_line(parser, m, settings)
                        q.task_done()

                for index in range(thread_count):
                    t = Thread(target=x, daemon=True)
                    # prepend zeroes; 10 threads ~ 01..10, 100 threads ~ 001..100
                    t.name = "0" * (len(str(thread_count)) - len(str(index + 1))) + str(index + 1)
                    t.start()
                    threads.append(t)

            inf.start()

            for row in reader:
                try:
                    if not row:  # skip blank
                        continue
                    if thread_count:
                        q.put(row)
                    else:
                        parser.line_count += 1
                        self.process_line(parser, row, settings)
                except BdbQuit:
                    print("Interrupted.")
                    raise
                except KeyboardInterrupt:
                    inf.pause()
                    print(f"Keyboard interrupting on line number: {parser.line_count}")
                    s = "[a]utoskip LACNIC encounters" \
                        if self.parser.queued_lines_count and not Config.get("lacnic_quota_skip_lines", "FIELDS") else ""
                    o = ask("Keyboard interrupt caught. Options: continue (default, do the line again), "
                            "[s]kip the line, [d]ebug, [e]nd processing earlier, [q]uit: ")
                    inf.release()
                    if o == "a":
                        Config.set("lacnic_quota_skip_lines", True, "FIELDS")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.")  # I dont know why.
                        Config.get_debugger().set_trace()
                    elif o == "s":
                        continue  # skip to the next line XXmaybe this is not true for threads
                    elif o == "e":  # end processing now
                        if thread_count:
                            try:
                                while q.get_nowait():  # empty remaining queue
                                    pass
                            except Empty:
                                pass
                            [q.put(False) for _ in threads]  # send kill signal
                            [t.join() for t in threads]  # wait the threads to write descriptors
                        return
                    elif o == "q":
                        self._close_descriptors()
                        quit()
                    else:  # continue from last row
                        parser.line_count -= 1  # let's pretend we didn't just do this row before and give it a second chance
                        if thread_count:
                            # XX when in threads, task_done was not called to queue so no need to requeuing,
                            #  Instead, the line is put to invalid rows. At least when I was digging a number of DNS queries
                            #  that received.
                            # subprocess.CalledProcessError: Command '['dig', '+short', '-t',
                            #           'A', '...', '+timeout=1']' died with <Signals.SIGINT: 2>.
                            # This behaviour was not observed without threads, instead, a KeyboardInterrupt was produced.
                            continue
                        self.process_line(parser, row, settings)

            # join threads
            while True:
                try:
                    [q.put(False) for _ in threads]  # send kill signal
                    [t.join() for t in threads]  # wait the threads to write descriptors
                    break
                except KeyboardInterrupt:
                    print("Cannot keyboard interrupt now, all events were sent to threads.")

            # after processing changes
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
                    header, rows = inf.get_aggregation(data, nice=False)
                    w = csvwriter(t, dialect=settings["dialect"])
                    w.writerow(header)
                    [w.writerow(r) for r in rows]
        finally:
            inf.stop()
            if not stdin:
                source_stream.close()
            if not self.parser.is_split:
                if 1 in self.descriptors:  # we have all data in a io.TextBuffer, not in a regular file
                    # the data are in the self.descriptors[1]
                    if Config.verbosity <= logging.INFO:
                        print("\n\n** Completed! **\n")
                    result = self.descriptors[1][0].getvalue()
                    print(result.strip())
                    parser.stdout = result
                    parser.stdout_sample = [row.split(parser.dialect.delimiter) for row in result.split("\n", 10)[:10]]
                    self.parser.saved_to_disk = False
                else:
                    self.parser.saved_to_disk = True
            if 2 in self.descriptors:
                # the data were in parser.stdout and were taken by the remote application
                del self.descriptors[2]

            self._close_descriptors()

        if self.parser.is_split:
            # set that a mail with this attachment have not yet been sent
            existing = {a.filename for a in self.parser.attachments}
            self.parser.attachments.extend(Attachment(f) for f in parser.files_created
                                           if f not in existing  # not existing yet
                                           and f not in (Config.INVALID_NAME, Config.UNKNOWN_NAME, Config.QUEUED_NAME))
        inf.write_statistics()

    def _close_descriptors(self):
        """ Descriptors have to be closed (flushed) """
        for f in self.descriptors.values():
            f[0].close()

    def process_line(self, parser, line, settings, fields=None):
        """
        Parses line – compute fields while adding, perform filters, pick or delete cols, split and write to a file.
        """
        try:
            add = False
            if not fields:
                fields = line.copy()
                if len(fields) is not len(parser.first_line_fields):
                    raise RuntimeWarning(f"Invalid number of line fields ({len(fields)})")
                add = True

            # pre filtering
            # filter (include, col, value), ex: [(True, 23, "passed-value"), (False, 13, "another-value")]
            for include, col_i, val in settings["f_pre"]:
                if (ne if include else eq)(val, fields[col_i]):
                    return False

            # unique columns
            if settings["u_pre"]:
                for u in settings["u_pre"]:  # list of uniqued columns [2, 3, 5, ...]
                    if fields[u] in self.unique_sets[u]:  # skip line
                        return False
                else:  # do not skip line
                    for u in settings["u_pre"]:
                        self.unique_sets[u].add(fields[u])

            # add fields
            if add:
                list_lengths = []
                for col_i in settings["addByMethod"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
                    val = fields[col_i[1]]
                    for l in col_i[2]:
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
                            raise RuntimeWarning(f"Column {i + 1} cannot be determined and the row was marked as invalid")
                        fields[i] *= row_count // len(fields[i])
                    it = zip(*fields)
                    fields = it.__next__()  # now we are sure fields has only scalar values
                    for v in it:  # duplicate row because one of lambdas produced a multiple value list
                        self.process_line(parser, line, settings, v)  # new row with scalar values only

            # post filtering
            # filter (include, col, value), ex: [(True, 23, "passed-value"), (False, 13, "another-value")]
            for include, col_i, val in settings["f_post"]:
                if (ne if include else eq)(val, fields[col_i]):
                    return False

            # unique columns
            if settings["u_post"]:
                for u in settings["u_post"]:  # list of uniqued columns [2, 3, 5, ...]
                    if fields[u] in self.unique_sets[u]:  # skip line
                        return False
                else:  # do not skip line
                    for u in settings["u_post"]:
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
                    parser.unknown_lines_count += 1
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
        except Quota.QuotaExceeded:
            parser.queued_lines_count += 1
            location = Config.QUEUED_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)
        except UnknownValue:  # `whois_reprocessable_unknown` is True
            # we do want to reprocess such lines at the end no matter single or split processing
            # (When split processing, this behaviour is obligatory,
            # such lines will be marked unknowns above when determining file location)
            parser.unknown_lines_count += 1
            location = Config.UNKNOWN_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)
        except BdbQuit:  # prevent BdbQuit to be caught by general Exception below
            raise
        except Exception as e:
            if Config.is_debug():
                traceback.print_exc()
                # cannot post_mortem from here, I could not quit; looped here again there, catching BdbQuit ignored
                Config.get_debugger().set_trace()
            elif isinstance(e, RuntimeWarning):
                logger.warning(f"Invalid line: {e} on line {line}")
            else:
                logger.warning(e, exc_info=True)
            parser.invalid_lines_count += 1
            location = Config.INVALID_NAME
            chosen_fields = line  # reset the original line (location will be reprocessed)

        if not location:
            return
        elif location in parser.files_created:
            method = "a"
        else:
            method = "w"
            # print("File created", location, parser.delimiter.join(chosen_fields))
            parser.files_created.add(location)

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
        with self._lock:
            if method == "w" and settings["header"]:
                # write original header (stored unchanged in parser.first_line_fields) if line to be reprocessed or modified header
                if location in (Config.INVALID_NAME, Config.UNKNOWN_NAME, Config.QUEUED_NAME):
                    f[1].writerow(parser.first_line_fields)
                else:
                    f[0].write(parser.header)
            f[1].writerow(chosen_fields)
