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

        for col, i, b in self.csv.settings["add"] or []:
            l.append("{} column from: {}".format(col, self.csv.fields[i]))                    
        if self.csv.settings["filter"]:
            l.append("Filtering")
            [l.append(f) for f in self.csv.settings["filter"]]
        #if self.csv.settings["unique"]:
        #    l.append("Uniquing")
        #    [l.append(self.csv.fields[f]) for f in self.csv.settings["unique"]]
        # XX
        if self.csv.settings["chosen_cols"]:
            l.append("only some cols chosen")        
        
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

        print("\nSample:\n" + "\n".join(self.csv.sample.split("\n")[:3]) + "\n") # show first 3rd lines
        """
        XX
        [reg.soutInfo(full) for reg in self.csv.reg.values()]
        """

        if full:
            print("\nPrefixes encountered:\nprefix | location | record | asn | netname")
            for prefix, o in self.csv.ranges.items():
                record, location, asn, netname = o
                print("{} | {} | {}".format(prefix, location, record, asn, netname))

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
