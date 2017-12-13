import subprocess, sys
import os.path
import datetime
from math import log, sqrt, ceil
from lib.config import Config

class Informer:
    """ Prints analysis data in nice manner. """

    def __init__(self, csv):
        self.csv = csv

    def soutInfo(self, clear=True, full=False):
        """ Prints file information on the display. """
        if clear:
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            #os.system('cls' if os.name == 'nt' else 'clear')
        #sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        #print(chr(27) + "[2J")
        l = []
        l.append("Source file: " + self.csv.sourceFile)
        if self.csv.delimiter:
            l.append("delimiter: '" + self.csv.delimiter + "'")
        if self.csv.hasHeader is not None:
            l.append("header: " + ("used" if self.csv.hasHeader else "not used"))

        if self.csv.settings["add"]:
            l2 = []
            for col, i, b in self.csv.settings["add"] or []:
                l2.append("{} (from {})".format(col, self.csv.fields[i]))
            l.append("computed columns: " + ", ".join(l2))
        if self.csv.settings["filter"]:
            l2 = []
            [l2.append(f) for f in self.csv.settings["filter"]]
            l.append("Filter: " + ", ".join(l2))
        if self.csv.settings["unique"]:
            l2 = []
            [l2.append(self.csv.fields[f]) for f in self.csv.settings["unique"]]
            l.append("Unique col: " + ", ".join(l2))
        #if self.csv.settings["chosen_cols"]:
        #    l.append("only some cols chosen")
        if self.csv.settings["split"]:
            l.append("Split by: {}".format(self.csv.fields[self.csv.settings["split"]]))

        # XX
        #if self.csv.redo_invalids is not None:
        #    l.append("Redo invalids: " + str(self.csv.redo_invalids))
        sys.stdout.write(", ".join(l))
        l = []
        if self.csv.lineCount:
            if self.csv.ipCount:
                sys.stdout.write(", {} IPs".format(self.csv.ipCount))
            elif self.csv.ipCountGuess:
                sys.stdout.write(", around {} IPs".format(self.csv.ipCountGuess))
            l.append("\nLog lines processed: {}/{}, {} %".format(self.csv.lineCount, self.csv.linesTotal, ceil(100 * self.csv.lineCount / self.csv.linesTotal)))
        else:
            l.append("\nLog lines: {}".format(self.csv.linesTotal))
        if self.csv.timeEnd:
            l.append("{}".format(self.csv.timeEnd - self.csv.timeStart))
        elif self.csv.timeStart:
            l.append("{}".format(datetime.datetime.now().replace(microsecond=0) - self.csv.timeStart))
            l.append("{} lines / s".format(self.csv.velocity))
        sys.stdout.write(", ".join(l) + "\n")
        if self.csv.whoisStats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.csv.whoisStats.items()))

        print("\nSample:\n" + "\n".join(self.csv.sample.split("\n")[:4]) + "\n") # show first 3rd lines

        if not (len(self.csv.fields) == len(self.csv.settings["chosen_cols"])) == len(self.csv.firstLine.split(self.csv.delimiter)):
            ar = []
            for i,f in enumerate(self.csv.fields):
                if i not in self.csv.settings["chosen_cols"]:
                    ar.append("\x1b[9m" + f + "\x1b[0m")
                else:
                    ar.append(f)
            print("Fields after processing:", ", ".join(ar))
        #if Config.isDebug(): print("Debug – Settings", self.csv.settings)

        if self.csv.isAnalyzed:
            print("** Processing completed: Result file(s) in {}".format(Config.getCacheDir()))
            stat = self.getStatsPhrase()
            print("\n Statistics overview:\n" + stat)
            # XX will we write it again to a file? with open(os.path.dirname(file) + "/statistics.txt","w") as f:
            #    f.write(stat)
            """
            XX
            if csv.abuseReg.stat("records", False):
                print("Couldn't find {} abusemails for {}× IP.".format(csv.reg["local"].stat("records", False), csv.reg["local"].stat("ips", False)))
            if csv.countryReg.stat("records", False):
                print("Couldn't find {} csirtmails for {}× IP.".format(csv.reg["foreign"].stat("records", False), csv.reg["foreign"].stat("ips", False)))
            """

        if full:
            """
            [reg.soutInfo(full) for reg in self.csv.reg.values()] do this:
                    #print (', '.join(key + " ( " + value + ")") for key, value in itertools.chain(self.counters["foreign"],self.counters["local"]))
                    l = []
                    if len(self.records) < 100 or full:
                        for key, o in self.records.items():
                            s = [str(len(o.counter))]
                            o.mail is False and s.append("no mail")
                            o.cc and s.append("cc " + o.cc)
                            l.append(key + " (" + ", ".join(s) + ")")
                    else:# too much of results, print just the count
                        l.append(str(len(self.records)) + " " + self.name)

                    if self.unknowns:
                        l.append("unknown {} ({})".format(self.name, len(self.unknowns)))
                    print(", ".join(l))
            """

            print("\nResult file(s) in {}".format(Config.getCacheDir()))

            print("\nPrefixes encountered:\nprefix | location | record | asn | netname")
            if self.csv.ranges.items():
                for prefix, o in self.csv.ranges.items():
                    prefix, location, abusemail, asn, netname, country = o
                    print("{} | {} | {}".format(prefix, location, abusemail or country))

    def getStatsPhrase(self, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        csv = self.csv

        ipsUnique = len(csv.stats["ipsUnique"])
        ispCzFound = len(csv.stats["ispCzFound"])
        ipsCzMissing = len(csv.stats["ipsCzMissing"])
        ipsCzFound = len(csv.stats["ipsCzFound"])
        ipsWorldMissing = len(csv.stats["ipsWorldMissing"])
        ipsWorldFound = len(csv.stats["ipsWorldFound"])
        countriesMissing = len(csv.stats["countriesMissing"])
        countriesFound = len(csv.stats["countriesFound"])

        """         XX
        invalidLines = self.csv.invalidReg.stat()
        """


        if ipsUnique > 0:
            res = "Totally {} of unique IPs".format(ipsUnique)
        else:
            res = "No IP addresses"
        if ipsWorldFound or countriesFound:
            res += "; information sent to {} countries".format(countriesFound) \
            + " ({} unique IPs)".format(ipsWorldFound)
        if ipsWorldMissing or countriesMissing:
            res += ", to {} countries without national/goverment CSIRT didn't send".format(countriesMissing) \
            + " ({} unique IPs)".format(ipsWorldMissing)
        if ipsCzFound or ispCzFound:
            res += "; {} unique local IPs".format(ipsCzFound) \
            + " distributed for {} ISP".format(ispCzFound)
        if ipsCzMissing:
            res += " (for {} unique local IPs ISP not found).".format(ipsCzMissing)


        """ XX
        if invalidLines:
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.csv.invalidReg.getPath())"""

        return res

    def fileLen(self, fname):
        if self.csv.size < 100 * 10 ** 6:
            p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            return int(result.strip().split()[0])
        else:
            return ceil(self.csv.size / (len(self.csv.sample) / len(self.csv.sample.split("\n"))) / 1000000) * 1000000
