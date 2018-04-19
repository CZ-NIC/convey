import datetime
import subprocess
import sys
from math import ceil

from lib.config import Config
import csv

class Informer:
    """ Prints analysis data in nice manner. """

    def __init__(self, csv):
        self.csv = csv

    def sout_info(self, clear=True, full=False):
        """ Prints file information on the display. """
        if clear:
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            # os.system('cls' if os.name == 'nt' else 'clear')
        # sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        # print(chr(27) + "[2J")
        l = []
        l.append("Source file: " + self.csv.source_file)
        if self.csv.dialect:
            l.append("delimiter: '" + self.csv.dialect.delimiter + "'")
            l.append("quoting: '" + self.csv.dialect.quotechar + "'")
        if self.csv.has_header is not None:
            l.append("header: " + ("used" if self.csv.has_header else "not used"))
        if self.csv.settings["filter"]:
            l.append("Filter: " + ", ".join(["{}({})".format(self.csv.fields[f], val) for f, val in self.csv.settings["filter"]]))
        if self.csv.settings["unique"]:
            l.append("Unique col: " + ", ".join([self.csv.fields[f] for f in self.csv.settings["unique"]]))
        if self.csv.settings["split"]:
            l.append("Split by: {}".format(self.csv.fields[self.csv.settings["split"]]))

        # XX
        # if self.csv.redo_invalids is not None:
        #    l.append("Redo invalids: " + str(self.csv.redo_invalids))
        sys.stdout.write(", ".join(l))

        if self.csv.settings["add"]:
            l2 = []
            for col, i, b in self.csv.settings["add"] or []:
                l2.append("{} (from {})".format(col, self.csv.fields[i]))
            sys.stdout.write("\nComputed columns: " + ", ".join(l2))
        l = []
        if self.csv.line_count:
            if self.csv.ip_count:
                sys.stdout.write(", {} IPs".format(self.csv.ip_count))
            elif self.csv.ip_count_guess:
                sys.stdout.write(", around {} IPs".format(self.csv.ip_count_guess))
            l.append("\nLog lines processed: {}/{}, {} %".format(self.csv.line_count, self.csv.lines_total,
                                                                 ceil(100 * self.csv.line_count / self.csv.lines_total)))
        else:
            l.append("\nLog lines: {}".format(self.csv.lines_total))
        if self.csv.time_end:
            l.append("{}".format(self.csv.time_end - self.csv.time_start))
        elif self.csv.time_start:
            l.append("{}".format(datetime.datetime.now().replace(microsecond=0) - self.csv.time_start))
            l.append("{} lines / s".format(self.csv.velocity))
        sys.stdout.write(", ".join(l) + "\n")
        if self.csv.whois_stats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.csv.whois_stats.items()))

        print("\nSample:\n" + "\n".join(self.csv.sample.split("\n")[:4]) + "\n")  # show first 3rd lines

        if self.csv.settings["dialect"] or not (len(self.csv.fields) == len(self.csv.settings["chosen_cols"])) == len(self.csv.first_line_fields):
            ar = []
            for i, f in enumerate(self.csv.fields):
                if i not in self.csv.settings["chosen_cols"]:
                    ar.append(" \x1b[9m{}\x1b[0m".format(f or "empty"))
                else:
                    ar.append(" " + f)
            print("Fields after processing:", end="")
            csv.writer(sys.stdout, dialect=self.csv.settings["dialect"] or self.csv.dialect).writerow(ar)
        # if Config.isDebug(): print("Debug – Settings", self.csv.settings)

        if self.csv.is_analyzed:
            if self.csv.target_file:
                print("** Processing completed: Result file in {}/{}".format(Config.getCacheDir(), self.csv.target_file))
            else:
                print("** Processing completed: Result files in {}".format(Config.getCacheDir()))
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
            [reg.sout_info(full) for reg in self.csv.reg.values()] do this:
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
