import datetime
from bdb import BdbQuit
from collections import defaultdict
from csv import reader as csvreader, writer as csvwriter
from math import ceil

from .config import Config
from .contacts import Attachment, Contacts
from .dialogue import Dialogue


class Processer:
    """ Opens the CSV file and processes the lines. """

    # XXpython3.6 descriptors: Dict[str, object] # location => file_descriptor, his csv-writer
    # XXpython3.6 descriptorsStatsOpen: defaultdict[str, int] # {location: count} XX(performance) we may use a SortedDict object

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

    def process_file(self, file, rewrite=False):
        csv = self.csv
        self.__init__(csv, rewrite=rewrite)
        settings = csv.settings.copy()

        # convert settings["add"] to lambdas
        adds = []
        for it in settings["add"]:  # [("netname", 20, [lambda x, lambda x...]), ...]
            methods = self.csv.guesses.get_methods_from(it[0], it[2], it[3])
            adds.append((it[0], it[1], methods))
        del settings["add"]
        settings["addByMethod"] = adds

        if len(settings["chosen_cols"]) == len(csv.fields):
            del settings["chosen_cols"]

        if not settings["dialect"]:
            settings["dialect"] = csv.dialect

        settings["target_file"] = csv.target_file

        with open(file, "r") as sourceF:
            reader = csvreader(sourceF, dialect=csv.dialect)
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
                        newVel = ceil(csv.velocity / delta) + 1
                        if abs(
                                newVel - csv.velocity) > 100 and csv.velocity < newVel:  # smaller accelerating of velocity (decelerating is alright)
                            csv.velocity += 100
                        else:
                            csv.velocity = newVel
                    csv.line_sout = csv.line_count + 1 + csv.velocity
                    csv.informer.sout_info()
                try:
                    self.process_line(csv, row, settings)
                except BdbQuit:  # not sure if working, may be deleted
                    print("BdbQuit called")
                    raise
                except KeyboardInterrupt:
                    print("Keyboard interrupting")
                    try:
                        print("{} line number, {} ip".format(csv.line_count, ip))
                    except:
                        pass
                    o = Dialogue.ask(
                        "Catched keyboard interrupt. Options: continue (default, do the line again), [s]kip the line, [d]ebug, [q]uit: ")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.")  # I dont know why.
                        import ipdb;
                        ipdb.set_trace()
                    elif o == "s":
                        continue  # skip to the next line
                    elif o == "q":
                        quit()
                        self._close_descriptors()
                    else:  # continue from last row
                        csv.line_count -= 1  # let's pretend we didn't just do this row before and give it a second chance
                        self.process_line(csv, row, settings)
        self._close_descriptors()

        if self.csv.is_split:
            for f in self.files_created:
                # self.csv.attachments[f] = False  # set that a mail with this attachment have not yet been sent
                self.csv.attachments.append(
                    Attachment(None, None, f))  # set that a mail with this attachment have not yet been sent
            Attachment.refresh_attachment_stats(self.csv)

    def _close_descriptors(self):
        """ Descriptors have to be closed (flushed) """
        for f in self.descriptors.values():
            f[0].close()

    def process_line(self, csv, line, settings):
        """ XX
            self.ranges[prefix] = mail, location (foreign | local), asn, netname

            Arguments:
                line - current processed line
                settings - defaultdict(bool)
                    chosen_cols
                    unique_sets
                    files_created (set)
                    settings["filter"...]
                    split_by_col (int)

                XX
                1. compute["netname", 20, [lambda x, ...]]; filters.add([20, "value"])
                2. add netname ze sloupce 20 .. chosenColumns.add(20)
                3. processing: cols[20] = val = lambda x(compute[1])
                4. filters[ cols[20] ]

        """
        try:
            # fields = line.split(csv.delimiter) # Parse line
            fields = line.copy()

            # add fields
            whois = None
            # import ipdb; ipdb.set_trace()
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
                    if mail == "unknown":
                        chosen_fields = line  # reset to the original line (will be reprocessed)
                        csv.stats["ipsCzMissing"].add(whois.ip)
                        csv.stats["czUnknownPrefixes"].add(whois.get[0])
                    else:
                        csv.stats["ipsCzFound"].add(whois.ip)
                        csv.stats["ispCzFound"].add(mail)
                else:
                    country = whois.get[5]
                    if country not in Contacts.countrymails:
                        csv.stats["ipsWorldMissing"].add(whois.ip)
                        csv.stats["countriesMissing"].add(country)
                    else:
                        csv.stats["countriesFound"].add(country)
                        csv.stats["ipsWorldFound"].add(whois.ip)
                # XX invalidLines if raised an exception

            # split
            location = fields[settings["split"]] if type(settings["split"]) == int else settings["target_file"]
        except Exception as e:
            if isinstance(e, BdbQuit):
                raise  # BdbQuit and KeyboardInterrupt catched higher
            else:
                if Config.is_debug():
                    import traceback
                    traceback.print_exc()
                    import ipdb;
                    ipdb.set_trace()
                csv.invalid_lines_count += 1
                location = Config.INVALID_NAME
                chosen_fields = [line]  # reset the original line (will be reprocessed)

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
            t = open(Config.get_cache_dir() + location, method)
            self.descriptors[location] = t, csvwriter(t, dialect=settings["dialect"])
            self.descriptors_count += 1
        # print("Printing", location)
        self.descriptorsStatsAll[location] += 1
        self.descriptorsStatsOpen[location] = self.descriptorsStatsAll[location]
        f = self.descriptors[location]
        if method == "w" and Config.has_header:
            f[0].write(Config.header)
        f[1].writerow(chosen_fields)

    def __XXnotMigratedFunctionality(self):
        ## XX Check if this is already migrated
        if not reprocessing and csv.urlColumn is not None:  # if CSV has DOMAIN column that has to be translated to IP column
            ip = Whois.url2ip(records[csv.urlColumn])
            # if len(ips) > 1:
            #    self.extendCount += len(ips) -1 # count of new lines in logs
            #    print("Url {} has {} IP addresses: {}".format(records[self.urlColumn], len(ips), ips))
        else:  # only one record
            try:
                ip = records[csv.ipColumn].strip()  # key taken from IP column
            except IndexError:
                csv.invalidReg.count(row)
                return
            if not Whois.checkIp(ip):
                # format 1.2.3.4.port
                # XX maybe it would be a good idea to count it as invalidReg directly. In case of huge files. Would it be much quicker?
                # This is 2 times quicker than regulars (but regulars can be cached). if(ip.count(".") == 5): ip = ip[:ip.rfind(".")]
                #
                # print(ip)
                # import ipdb;ipdb.set_trace()
                print("ip:", ip)  # XX
                m = Processer.reIpWithPort.match(ip)
                if m:
                    # 91.222.204.175.23 -> 91.222.204.175
                    ip = m.group(1).rstrip(".")
                else:
                    m = Processer.reAnyIp.match(ip)
                    if m:
                        # "91.222.204.175 93.171.205.34" -> "91.222.204.175", '"1.2.3.4"' -> 1.2.3.4
                        ip = m.group(1)
                    else:
                        # except AttributeError:
                        csv.invalidReg.count(row)
                        return
