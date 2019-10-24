import datetime
import io
import logging
import traceback
from bdb import BdbQuit
from collections import defaultdict
from csv import reader as csvreader, writer as csvwriter
from math import ceil
from pathlib import Path
from typing import Dict

import ipdb

from convey.identifier import Web
from .config import Config
from .contacts import Attachment, Contacts
from .dialogue import ask, is_no

logger = logging.getLogger(__name__)


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
            adds.append((f.name, self.csv.fields.index(f.source_field), f.get_methods()))
        del settings["add"]
        settings["addByMethod"] = adds

        if [f for f in self.csv.fields if (not f.is_chosen or f.col_i_original != f.col_i)]:
            settings["chosen_cols"] = [f.col_i_original for f in self.csv.fields if f.is_chosen]

        if not settings["dialect"]:
            settings["dialect"] = csv.dialect

        Web.init(self.csv.get_computed_fields())

        # start file processing
        try:
            if file:
                source_stream = open(file, "r")
                settings["target_file"] = str(csv.target_file)
            else:
                source_stream = stdin
                settings["target_file"] = 1
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
                    now = datetime.datetime.now()
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
                try:
                    self.process_line(csv, row, settings)
                except BdbQuit:  # not sure if working, may be deleted
                    print("BdbQuit called")
                    raise
                except KeyboardInterrupt:
                    print(f"Keyboard interrupting on line number: {csv.line_count}")
                    o = ask("Keyboard interrupt caught. Options: continue (default, do the line again), "
                            "[s]kip the line, [d]ebug, [q]uit: ")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.")  # I dont know why.
                        import ipdb
                        ipdb.set_trace()
                    elif o == "s":
                        continue  # skip to the next line
                    elif o == "q":
                        quit()
                        self._close_descriptors()
                    else:  # continue from last row
                        csv.line_count -= 1  # let's pretend we didn't just do this row before and give it a second chance
                        self.process_line(csv, row, settings)
        finally:
            if file:
                source_stream.close()
            elif not self.csv.is_split and 1 in self.descriptors:  # we have all data in a io.TextBuffer, not in a regular file
                if Config.verbosity <= logging.INFO:
                    print("\n\n** Completed! **\n")
                result = self.descriptors[1][0].getvalue()
                print(result.strip())


                if Config.get("output") is None:
                    ignore = is_no("Save to an output file?") if Config.get("save_stdin_output") is None\
                        else Config.get("save_stdin_output") is False
                else:
                    ignore = not Config.get("output")
                if ignore:
                    # we didn't have a preference and replied "no" or we had a preference to not save the output
                    csv.target_file = False
                    csv.stdout = result
                else:
                    csv.target_file.write_text(result)

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

    def process_line(self, csv, line, settings):
        """
        Parses line – compute fields while adding, perform filters, pick or delete cols, split and write to a file.
        """
        try:
            fields = line.copy()

            if len(fields) is not len(csv.first_line_fields):
                raise ValueError("Invalid number of line fields: {}".format(len(fields)))

            # add fields
            whois = None
            for col in settings["addByMethod"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
                val = fields[col[1]]
                for l in col[2]:
                    val = l(val)
                if isinstance(val, tuple):  # we get whois info-tuple
                    whois = val[0]
                    fields.append(val[1])
                else:
                    fields.append(val)

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

            if whois:
                csv.stats["ipsUnique"].add(whois.ip)
                mail = whois.get[2]
                if whois.get[1] == "local":
                    if not mail:
                        chosen_fields = line  # reset to the original line (will be reprocessed)
                        csv.stats["ipsCzMissing"].add(whois.ip)
                        csv.stats["czUnknownPrefixes"].add(whois.get[0])
                    else:
                        csv.stats["ipsCzFound"].add(whois.ip)
                        csv.stats["ispCzFound"].add(mail)
                else:
                    country = whois.get[5]
                    if country not in Contacts.csirtmails:
                        csv.stats["ipsWorldMissing"].add(whois.ip)
                        csv.stats["countriesMissing"].add(country)
                    else:
                        csv.stats["countriesFound"].add(country)
                        csv.stats["ipsWorldFound"].add(whois.ip)
                # XX invalidLines if raised an exception

            # split ('/' is a forbidden char in linux file names)
            location = (fields[settings["split"]].replace("/", "-") or Config.UNKNOWN_NAME if type(settings["split"]) == int
                        else settings["target_file"])
        except Exception as e:
            if isinstance(e, BdbQuit):
                raise  # BdbQuit and KeyboardInterrupt caught higher
            else:
                if Config.is_debug():
                    traceback.print_exc()
                    ipdb.set_trace()
                else:
                    logger.warning(e, exc_info=True)
                csv.invalid_lines_count += 1
                location = Config.INVALID_NAME
                chosen_fields = line  # reset the original line (will be reprocessed)

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
