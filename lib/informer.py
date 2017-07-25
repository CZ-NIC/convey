import subprocess, sys
import datetime
from math import log, sqrt, ceil

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

        if self.csv.urlColumn is not None:
            l.append("Url column: " + self.csv.fields[self.csv.urlColumn])
        if self.csv.ipColumn is not None:
            l.append("IP column: " + self.csv.fields[self.csv.ipColumn])
        if self.csv.asnColumn is not None:
            l.append("ASN column: " + self.csv.fields[self.csv.asnColumn])
        if self.csv.conveying is not None:
            l.append("Conveying method: " + self.csv.conveying)
        if self.csv.redo_invalids is not None:
            l.append("Redo invalids: " + str(self.csv.redo_invalids))
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
        #if self.extendCount > 0:
        #    print("+ other {} rows, because some domains had multiple IPs".format(self.extendCount))
        if self.csv.whoisStats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.csv.whoisStats.items()))

        print("\nSample:\n" + "\n".join(self.csv.sample.split("\n")[:3]) + "\n") # show first 3rd lines
        [reg.soutInfo(full) for reg in self.csv.reg.values()]

        if full:
            print("\nPrefixes encountered:\nprefix | location | record | asn | netname")
            for prefix, o in self.csv.ranges.items():
                record, location, asn, netname = o
                print("{} | {} | {}".format(prefix, location, record, asn, netname))

    def getStatsPhrase(self, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        ab = self.csv.abuseReg.stat
        co = self.csv.countryReg.stat

        ipsUnique = ab("ips", "both") + co("ips", "both")

        ispCzFound = ab("records", True)
        ipsCzMissing = ab("ips", False)
        ipsCzFound = ab("ips", True)

        ipsWorldMissing = co("ips", False)
        ipsWorldFound = co("ips", True)
        countriesMissing = co("records", False)
        countriesFound = co("records", True)

        invalidLines = self.csv.invalidReg.stat()


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
        if invalidLines:
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.csv.invalidReg.getPath())

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
