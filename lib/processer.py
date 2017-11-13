from lib.config import Config
from lib.informer import Informer
from lib.dialogue import Dialogue
import datetime
from math import log, sqrt, ceil
import re
from collections import defaultdict
from bdb import BdbQuit
import logging

class Processer:
    """ Processes the csv lines.
        For every line, it contants whois and sends it to registry.
    """

    def __init__(self, csv):
        self.csv = csv

    def processFile(self, file):
        csv = self.csv
        settings = csv.settings
        with open(file, "r") as sourceF:
            for row in sourceF:
                 # skip blanks and header
                row = row.strip()
                if(row == ""):
                    continue
                csv.lineCount += 1
                if csv.lineCount == 1 and csv.hasHeader:
                    continue
                # display infopanel
                if csv.lineCount == csv.lineSout:
                    now = datetime.datetime.now()
                    delta = (now - csv.timeLast).total_seconds()
                    csv.timeLast = now
                    if delta < 1 or delta > 2:
                        newVel = ceil(csv.velocity / delta) +1
                        if abs(newVel - csv.velocity) > 100 and csv.velocity < newVel: # smaller accelerating of velocity (decelerating is alright)
                            csv.velocity += 100
                        else:
                            csv.velocity = newVel
                    csv.lineSout = csv.lineCount + 1 +csv.velocity
                    csv.informer.soutInfo()
                # process the line (IP, ASN, ...)
                try:
                    self.processLine(csv, row, settings)
                    # X else: Varianta pro posilani CMS csv.reg["local"].count(row, row.split(csv.delimiter)[csv.urlColumn])r
                except BdbQuit as e: # not sure if working, may delete
                    print("BdbQuit called")
                    raise
                except Exception as e: # FileNotExist
                    print("ROW fault" + row)
                    print("This should not happen. CSV is wrong or tell programmer to repair this.")
                    print(e)
                    Config.errorCatched()
                except KeyboardInterrupt:
                    print("CATCHED")
                    try:
                        print("{} line number, {} ip".format(csv.lineCount, ip))
                    except:
                        pass
                    o = Dialogue.ask("Catched keyboard interrupt. Options: continue (default, do the line again), [s]kip the line, [d]ebug, [q]uit: ")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.") # I dont know why.
                        import ipdb;ipdb.set_trace()
                    elif o == "s":
                        continue # skip to the next line
                    elif o == "q":
                        quit()
                        self._closeDescriptors()
                    else:  # continue from last row
                        csv.lineCount -= 1 # let's pretend we didnt just do this row before
                        return self.processLine(csv, row, settings)
        self._closeDescriptors()

    def _closeDescriptors(self):
        """ Descriptors have to be closed (flushed) """
        for f in self.descriptors.values():
            f.close()
        #print("CHECK CLOSING DESCRITOP")
        #import ipdb; ipdb.set_trace()

    # XX predelat asi do csv.
    uniqueSets = defaultdict(set)
    filesCreated = set()

    descriptors_max = 1000 # XX should be given by the system, ex 1024
    descriptors_count = 0
    descriptorsStatsOpen =  {} # defaultdict(int) # location => count XX lets google for SortedDict
    descriptorsStatsAll = defaultdict(int)
    descriptors =  {} # location => file_descriptor

    def processLine(self, csv, line, settings):
        """ XX
            self.ranges[prefix] = mail, location (foreign | local), asn, netname

            Arguments:
                line - current processed line
                settings - defaultdict(bool)

                XX
                1. compute["netname", 20, [lambda x, ...]]; filters.add([20, "value"])
                2. add netname ze sloupce 20 .. chosenColumns.add(20)
                3. processing: cols[20] = val = lambda x(compute[1])
                4. filters[ cols[20] ]

                csv.chosen_cols
                uniqueSets
                filesCreated (set)
                settings["filter"...]
                split_by_col (int)
        """
        fields = line.split(csv.delimiter) # Parse line

        # add fields
        for col in settings["add"]: # [("netname", 20, [lambda x, lambda x...]), ...]
            val = fields[col[1]]
            for l in col[2]:
                val = l(val)
            fields.append(val)

        # inclusive filter
        for f in settings["filter"]: # list of tuples (col, value): [(23, "passed-value"), (13, "another-value")]
            if f[1] != fields[f[0]]:
                return False

        #import ipdb; ipdb.set_trace()
        # unique columns
        if settings["unique"]:
            #import ipdb; ipdb.set_trace()
            for u in settings["unique"]: # list of uniqued columns [2, 3, 5, ...]
                if fields[u] in self.uniqueSets[u]: # skip line
                    return False
            else: # do not skip line
                for u in settings["unique"]:
                    self.uniqueSets[u].add(fields[u])

        # pick or delete columns
        if settings["chosen_cols"]:
            chosen_fields = [fields[i] for i in settings["chosen_cols"]] # chosen_cols = [3, 9, 12]
        else:
            chosen_fields = fields

        if settings["do_statistics"]:
            ip_col = 4 # XX

            ip = fields[ip_col]
            csv.stats["ipsUnique"].add(ip)
            if fields[csirt-mail]:
                country_code, mail = fields[csirt-mail]
                if country_code == "local":
                    if mail == "unknown":
                        csv.stats["ipsCzMissing"].add(ip)
                    else:
                        csv.stats["ipsCzFound"].add(ip)
                        csv.stats["ispCzFound"].add(mail)
                else:
                    if mail == "unknown":
                        csv.stats["ipsWorldMissing"].add(ip)
                        csv.stats["countriesMissing"].add(country_code)
                    else:
                        csv.stats["countriesFound"].add(country_code)
                        csv.stats["ipsWorldFound"].add(ip)
                # XX invalidLines if raised an exception

        # split
        location = fields[settings["split"]] if type(settings["split"]) == int else "processed_file.csv"
        if not location:
            return
        elif location in self.filesCreated:
            method = "a"
        else:
            method = "w"
            #print("File created", location, csv.delimiter.join(chosen_fields))
            self.filesCreated.add(location)

        # choose the right file descriptor for saving
        # (we do not close descriptors immediately, if needed we close the one the least used)
        if location not in self.descriptorsStatsOpen:
            if self.descriptors_count >= self.descriptors_max: # too many descriptors open, we have to close the least used
                key = min(self.descriptorsStatsOpen, key=self.descriptorsStatsOpen.get)
                self.descriptors[key].close()
                #print("Closing", key, self.descriptorsStatsOpen[key])
                del self.descriptorsStatsOpen[key]
                self.descriptors_count -= 1
            #print("Opening", location)
            self.descriptors[location] = open(Config.getCacheDir() + location, method)
            self.descriptors_count += 1
        #print("Printing", location)
        self.descriptorsStatsAll[location] += 1
        self.descriptorsStatsOpen[location] = self.descriptorsStatsAll[location]
        f = self.descriptors[location]
        if method == "w" and Config.hasHeader:
            f.write(Config.header + "\n")
        #import ipdb; ipdb.set_trace()
        f.write(csv.delimiter.join(chosen_fields) + "\n")




    def XXnotMigratedFunctionality(self):
        ## XX OLD
        if not reprocessing and csv.urlColumn is not None: # if CSV has DOMAIN column that has to be translated to IP column
            ip = Whois.url2ip(records[csv.urlColumn])
            #if len(ips) > 1:
            #    self.extendCount += len(ips) -1 # count of new lines in logs
            #    print("Url {} has {} IP addresses: {}".format(records[self.urlColumn], len(ips), ips))
        else: # only one record
            try:
                ip = records[csv.ipColumn].strip() # key taken from IP column
            except IndexError:
                csv.invalidReg.count(row)
                return
            if not Whois.checkIp(ip):
                # format 1.2.3.4.port
                # XX maybe it would be a good idea to count it as invalidReg directly. In case of huge files. Would it be much quicker?
                # This is 2 times quicker than regulars (but regulars can be cached). if(ip.count(".") == 5): ip = ip[:ip.rfind(".")]
                #
                #print(ip)
                #import ipdb;ipdb.set_trace()
                print("ip:", ip) # XX
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
                        #except AttributeError:
                        csv.invalidReg.count(row)
                        return

        ######
        # ASSURING THE EXISTENCE OF PREFIX (abusemail)
        ######
        if not reprocessing: # (in 'reprocessing unknown' mode, this was already done)
            if csv.urlColumn is not None:
                row += csv.delimiter + ip # append determined IP to the last col


        else: # force to obtain abusemail
            if not found:
                raise AssertionError("The prefix for ip " + ip + " should be already present. Tell the programmer.")
            if mail == "unknown": # prefix is still unknown
                mail = Whois(ip).resolveUnknownMail()
                if mail != "unknown": # update prefix
                    csv.ranges[prefix] = mail, location, asn, netname
                else: # the row will be moved to unknown.local file again
                    print("No success for prefix {}.".format(prefix))

        ######
        # WRITE THE ROW TO THE APPROPRIATE FILE
        ######
        if csv.appendFields["asn"]:
            row += csv.delimiter + asn
        if csv.appendFields["netname"]:
            row += csv.delimiter + netname
        csv.reg[location].count(row, mail, ip, prefix)