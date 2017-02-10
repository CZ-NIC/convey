class Informer:
    """ Prints analysis data in nice manner. """

    def soutInfo(csv, clear=True, full=False):
        """ Prints file information on the display. """
        if clear:
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            #os.system('cls' if os.name == 'nt' else 'clear')
        #sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        #print(chr(27) + "[2J")
        l = []
        l.append("Source file: " + csv.sourceFile)
        if csv.delimiter:
            l.append("delimiter: '" + csv.delimiter + "'")
        if csv.hasHeader is not None:
            l.append("header: " + ("used" if csv.hasHeader else "not used"))

        if csv.urlColumn is not None:
            l.append("Url column: " + csv.fields[csv.urlColumn])
        if csv.ipColumn is not None:
            l.append("IP column: " + csv.fields[csv.ipColumn])
        if csv.asnColumn is not None:
            l.append("ASN column: " + csv.fields[csv.asnColumn])
        if csv.conveying is not None:
            l.append("Conveying method: " + csv.conveying)
        if csv.redo_invalids is not None:
            l.append("Redo invalids: " + str(csv.redo_invalids))
        sys.stdout.write(", ".join(l))
        l = []
        if csv.lineCount:
            if csv.ipCount:
                sys.stdout.write(", {} IPs".format(csv.ipCount))
            elif csv.ipCountGuess:
                sys.stdout.write(", around {} IPs".format(csv.ipCountGuess))
            l.append("\nLog lines processed: {}/{}, {} %".format(csv.lineCount, csv.linesTotal, ceil(100 * csv.lineCount / csv.linesTotal)))
        else:
            l.append("\nLog lines: {}".format(csv.linesTotal))
        if csv.timeEnd:
            l.append("{}".format(csv.timeEnd - csv.timeStart))
        elif csv.timeStart:
            l.append("{}".format(datetime.datetime.now().replace(microsecond=0) - csv.timeStart))
            l.append("{} lines / s".format(csv.velocity))
        sys.stdout.write(", ".join(l) + "\n")
        #if self.extendCount > 0:
        #    print("+ other {} rows, because some domains had multiple IPs".format(self.extendCount))
        if csv.whoisStats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in csv.whoisStats.items()))

        print("\nSample:\n" + "\n".join(csv.sample.split("\n")[:3]) + "\n") # show first 3rd lines
        [reg.soutInfo(full) for reg in csv.reg.values()]

        if full:
            print("\nPrefixes encountered:\nprefix | location | record | asn | netname")
            for prefix, o in csv.ranges.items():
                record, location, asn, netname = o
                print("{} | {} | {}".format(prefix, location, record, asn, netname))

    def getStatsPhrase(csv, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        ab = csv.abuseReg.stat
        co = csv.countryReg.stat

        ipsUnique = ab("ips", "both") + co("ips", "both")

        ispCzFound = ab("records", True)
        ipsCzMissing = ab("ips", False)
        ipsCzFound = ab("ips", True)

        ipsWorldMissing = co("ips", False)
        ipsWorldFound = co("ips", True)
        countriesMissing = co("records", False)
        countriesFound = co("records", True)

        invalidLines = csv.invalidReg.stat()


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
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, csv.invalidReg.getPath())

        return res

    def fileLen(fname):
        if self.size < 100 * 10 ** 6:
            p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            return int(result.strip().split()[0])
        else:
            return ceil(self.size / (len(self.sample) / len(self.sample.split("\n"))) / 1000000) * 1000000
