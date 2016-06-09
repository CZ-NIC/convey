# Source file parsing
from collections import defaultdict
from collections import namedtuple
import csv
import ipdb
import itertools
from lib.config import Config
from lib.csvGuesses import CsvGuesses
from lib.dialogue import Cancelled
from lib.dialogue import Dialogue
from lib.registry import AbusemailRegistry, CountryRegistry, InvalidRegistry
from lib.whois import Whois
import logging
from math import sqrt, ceil, log
import ntpath
import os
import pdb
import pudb
import re
from shutil import move
import sys
import subprocess
import datetime
logging.FileHandler('whois.log', 'a')


class SourceParser:
    
    def soutInfo(self, clear=True, full=False):
        """ file information """
        if clear:
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            #os.system('cls' if os.name == 'nt' else 'clear')
        #sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        #print(chr(27) + "[2J")
        l = []
        l.append("Source file: " + self.sourceFile)        
        if self.delimiter:
            l.append("delimiter: '" + self.delimiter + "'")
        if self.hasHeader is not None:
            l.append("header: " + ("used" if self.hasHeader else "not used"))
        
        if self.urlColumn is not None:
            l.append("Url column: " + self.fields[self.urlColumn])
        if self.ipColumn is not None:            
            l.append("IP column: " + self.fields[self.ipColumn])
        if self.asnColumn is not None:
            l.append("ASN column: " + self.fields[self.asnColumn])
        if self.conveying is not None:
            l.append("Conveying method: " + self.conveying)
        if self.redo_invalids is not None:
            l.append("Redo invalids: " + str(self.redo_invalids))
        print(", ".join(l))
        if self.whoisStats:
            print("During analysis, whois servers were called: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.whoisStats.items()))
        if self.lineCount:
            l = []
            l.append("Log lines processed: {}/{}, {} %".format(self.lineCount, self.linesTotal, ceil(100 * self.lineCount / self.linesTotal)))
            if self.ipCountGuess:
                l.append("(around {} IPs)".format(self.ipCountGuess))
            if self.ipCount:
                l.append("({} IPs)".format(self.ipCount))
            sys.stdout.write(" ".join(l))
        else:
            sys.stdout.write("Log lines: {}".format(self.linesTotal))
        if self.timeEnd:
             print(" ({})".format(self.timeEnd - self.timeStart))
        elif self.timeStart:
             print(" ({})".format(datetime.datetime.now().replace(microsecond=0) - self.timeStart))
        #if self.extendCount > 0:
        #    print("+ other {} rows, because some domains had multiple IPs".format(self.extendCount))

        print("\nSample:\n" + "\n".join(self.sample.split("\n")[:3]) + "\n") # show first 3rd lines
        [reg.soutInfo(full) for reg in self.reg.values()]

        if full:
            print("\nPrefixes encountered:\nprefix | kind | record")
            for prefix, o in self.ranges.items():                
                record, kind = o
                print("{} | {} | {}".format(prefix, kind, record))


    def askBasics(self):
        """ Dialog to obtain basic information about CSV - delimiter, header """
        self.delimiter, self.hasHeader = CsvGuesses.guessDelimiter(self.sniffer, self.sample)        
        if not Dialogue.isYes("Is character '{}' delimiter? ".format(self.delimiter)):
            while True:
                sys.stdout.write("What is delimiter: ")
                self.delimiter = input()
                if not self.delimiter: # X"" -> None (.split fn can handle None, it cant handle empty string)
                    #self.delimiter = None
                    print("Delimiter can't be empty. Invent one (like ',').")                    
                else:
                    break
        if not Dialogue.isYes("Header " + ("" if self.hasHeader else "not " + "found; ok?")):
            self.hasHeader = not self.hasHeader
        if self.hasHeader == True:
            self.header = self.firstLine.strip()
        #if self.delimiter:
        self.fields = self.firstLine.split(self.delimiter)
        self.fields[-1] = self.fields[-1].strip()
        #else:
        #    self.fields = [self.firstLine]



    def askIpCol(self):
        fn = lambda field: Whois.checkIp(field)        
        self.ipColumn = CsvGuesses.guessCol(self, "IP/URL", fn, ["ip", "sourceipaddress", "ipaddress", "source"])

        if self.ipColumn is None:
            print("We can't live without IP/URL column. Try again or write x for cancellation.")
            return self.askIpCol()

        ip = self.sample.split("\n")[1 if self.hasHeader else 0].split(self.delimiter)[self.ipColumn].strip()
        if not Whois.checkIp(ip):# determine if it's IP column or DOMAIN column. I need to skip header. (Note there may be a 1 line file)
            #print("Domains in this column will be translated to IP.")
            Whois.checkIp(ip)
            if Dialogue.isYes("It seems this is not IP address. Is this a URL column? (If not, we take it as an IP column.)"):
                self.urlColumn, self.ipColumn = self.ipColumn, len(self.fields) #-1
                self.fields.append("will be fetched")
                if self.hasHeader == True: # add URL_IP column
                    dl = self.delimiter if self.delimiter else ","
                    self.header += dl + "URL_IP"

    def askAsnCol(self): # The function is not used now.
        fn = lambda field: re.search('AS\d+', field) != None
        self.asnColumn = CsvGuesses.guessCol(self, "ASN", fn, ["as", "asn", "asnumber"])


    def __init__(self, sourceFile):
        print("Processing file.")        
        self.isRepeating = False        
        while True:                        
            #instance attributes init
            #self.multithread = Config.get("multithread") # if True, whois will be asked multithreaded (but we may flood it)
            #self.lines = None #lines of csv file
            self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
            self.countries = defaultdict(set) # countries[gb] = {ip, ...} MailDraft structure takes IPs here.
            self.countriesMissing = defaultdict(set) # elements from self.countries that couldn't be triaged to MailDraft by whois

            self.ipColumn = None # IP column position
            self.asnColumn = None # AS number collumn position
            self.urlColumn = None # URL column position, to be translated to IP
            self.delimiter = None  #CSV dialect
            #self.whoisBCount = 0
            self.hasHeader = None
            self.header = "" # if CSV has header, it's here
            self.fields = []

            def file_len(fname):
                if self.size < 100*10^6:
                    p = subprocess.Popen(['wc', '-l', fname], stdout=subprocess.PIPE,
                                                              stderr=subprocess.PIPE)
                    result, err = p.communicate()
                    if p.returncode != 0:
                        raise IOError(err)
                    return int(result.strip().split()[0])
                else:
                    return ceil(self.size / (len(self.sample) / len(self.sample.split("\n"))) / 1000000) * 1000000

            # OTRS attributes to be linked to CSV
            self.ticketid = False
            self.ticketnum = False
            self.cookie = False
            self.token = False

            self.ticketid = Config.get("ticketid", "OTRS")
            self.ticketnum = Config.get("ticketnum", "OTRS")

            self.attachmentName = "part-" + ntpath.basename(sourceFile)

            self.ipCountGuess = None
            self.ipCount = None            

            self._reset()

            #load CSV            
            self.sourceFile = sourceFile

            self.size = os.path.getsize(self.sourceFile)

            self.sniffer = csv.Sniffer()            
            self.firstLine, self.sample = CsvGuesses.getSample(self.sourceFile)
            self.linesTotal = file_len(sourceFile) #sum(1 for line in open(sourceFile))
            try:
                for fn in [self.askBasics, self.askIpCol, self.sizeCheck]: # steps of dialogue  Xself.askAsnCol
                    self.soutInfo()
                    fn()
            except Cancelled:
                print("Cancelled.")
                return
            self.soutInfo()

            self.guessIpCount()
            if not Dialogue.isYes("Everything set alright?"):
                self.isRepeating = True
                continue # repeat
            else:
                self.isFormattedB = True
                Config.set("conveying", self.conveying) # used by Registry class
                Config.set("redo_invalids", self.redo_invalids) # used by Registry class
                break

    def _reset(self):
        """ Reset variables before new analysis. """
        #cant be pickled: self.reg = namedtuple('SourceParser.registries', 'local foreign')(AbusemailRegistry(), CountryRegistry())
        self.abuseReg = AbusemailRegistry();
        self.countryReg = CountryRegistry()
        self.invalidReg = InvalidRegistry()
        self.reg = {'local': self.abuseReg, "foreign":self.countryReg, "error": self.invalidReg}
        #self.reg = Registries        
        Config.hasHeader = self.hasHeader
        Config.header = self.header
        self.ranges = {}        
        self.lineCount = 0
        self.lineSout = 1
        self.lineSumCount = 0        
        #self.linesTotal = 0
        #self.extendCount = 0
        self.timeStart = None
        self.timeEnd = None
        self.timeLast = None
        self.isAnalyzedB = False
        self.isFormattedB = False
        self.sums = {}
        self.whoisStats = Whois.stats # so that it is saved
        self.ipSeen = dict() # ipSeen[ip] = prefix        
        self.redo_invalids = Config.getboolean("redo_invalids")
        self.conveying = Config.get("conveying")
        if not self.conveying: # default
            self.conveying = "all"
    
    def runAnalysis(self):
        """ Run main analysis of the file.
        Grab IP from every line and
        """
        self._reset()
        if Config.getboolean("autoopen_editor"):
            [r.mailDraft.guiEdit() for r in self.reg.values()]
        self.timeStart = self.timeLast = datetime.datetime.now().replace(microsecond=0)
        with open(self.sourceFile, 'r') as csvfile:
            for line in csvfile:
                self._processLine(line)
        self.timeEnd = datetime.datetime.now().replace(microsecond=0)
        self.linesTotal = self.lineCount # if we guessed the total of lines, fix the guess now

        #self.linesTotal = self.lineCount
        self.isAnalyzedB = True
        [r.update() for r in self.reg.values()]
        if self.invalidReg.stat() and self.redo_invalids:
            print("Analysis COMPLETED.\n\n")
            self.resolveInvalid()
        if self.abuseReg.stat("prefixes", found=False):
            print("Analysis COMPLETED.\n\n")
            self.resolveUnknown()        
        self.lineCount = 0
        self.soutInfo()

    def sizeCheck(self):
        mb = 10
        if self.size > mb*10^6 and self.conveying == "all":
            if Dialogue.isYes("The file is > {} MB and conveying method is set to all. Don't want to rather set the method to 'unique_ip' so that every IP had only one line and the amount of information sent diminished?".format(mb)):
                self.conveying = "unique_ip"

    def guessIpCount(self):
        """ Determine how many IPs there are in the file. """
        if self.urlColumn is None:
            try:
                max = 100000
                i = 0
                ipSet = set()
                fraction = None
                with open(self.sourceFile, 'r') as csvfile:                                   
                    for line in csvfile:
                        i += 1
                        if self.hasHeader and i == 1:
                            continue
                        ip = line.split(self.delimiter)[self.ipColumn].strip()
                        ipSet.add(ip)
                        if i == (max - 1000):
                            fraction = len(ipSet)                            
                        if i == max:
                            break
                if i != max:
                    self.ipCount = len(ipSet)
                    print("There are {} IPs.".format(self.ipCount))
                else:                    
                    delta = len(ipSet) - fraction # determine new IPs in the last portion of the sample
                    self.ipCountGuess = len(ipSet) + ceil((self.linesTotal - i) * delta / i)                                        
                    print("In the first {} lines, there are {} unique IPs. There might be around {} IPs in the file.".format(i,len(ipSet),self.ipCountGuess))
            except Exception as e:
                print("Can't guess IP count.")                


    def isAnalyzed(self):
        return self.isAnalyzedB

    def isFormatted(self):
        return self.isFormattedB
        
    def _processLine(self, row, unknownMode=False):
        """ Link every line to IP
            self.ranges[prefix] = record, kind (it,foreign; abuse@mail.com,local)
        """
        row = row.strip()
        if(row == ""):
            return
        self.lineCount += 1
        if self.lineCount == 1 and self.hasHeader: # skip header
            return
        #if sqrt(self.lineCount) % 1 == 0:
        #if self.lineCount % 10 == 0:
        #import ipdb;ipdb.set_trace()
        if self.lineCount == self.lineSout:            
            #self.lineSout = ceil(self.lineSumCount + self.lineSumCount * 0.01 * log(self.lineSumCount)) +1
            #self.lineSout = self.lineSumCount + ceil(self.lineSumCount * 0.3 * sqrt(self.lineSumCount))+1
            now = datetime.datetime.now()
            delta = (now - self.timeLast).total_seconds()
            self.timeLast = now
            if delta < 1:
                self.lineSumCount += 10
                print("PLUS") #XXX
            elif delta > 5:
                self.lineSumCount -= 100
                print("MINUS") # XXX
                if self.lineSumCount <= 0:
                    self.lineSumCount = 1
            else:
                self.lineSumCount += 1

            self.lineSout = self.lineCount + ceil(0.5 * sqrt(self.lineSumCount))
            self.soutInfo()
            print("delta {}, sum {}, o {}".format(delta, self.lineSumCount,ceil(0.5 * sqrt(self.lineSumCount)))) # XXX
        try:
            # obtain IP from the line. (Or more IPs, if theres url column).
            records = row.split(self.delimiter)
            if not unknownMode and self.urlColumn is not None: # if CSV has DOMAIN column that has to be translated to IP column
                ip = Whois.url2ip(records[self.urlColumn])
                #if len(ips) > 1:
                #    self.extendCount += len(ips) -1 # count of new lines in logs
                #    print("Url {} has {} IP addresses: {}".format(records[self.urlColumn], len(ips), ips))
            else: # only one reçord
                try:
                    ip = records[self.ipColumn].strip() # key taken from IP column
                except IndexError:
                    self.invalidReg.count(row)
                    return
                if not Whois.checkIp(ip):
                    try: # format 1.2.3.4.port
                        m = re.match("((\d{1,3}\.){4})(\d+)",ip)
                        ip = m.group(1).rstrip(".")
                    except AttributeError:
                        self.invalidReg.count(row)
                        return

            # determine the prefix
            if ip in self.ipSeen:
                if self.conveying == "unique_file" or self.conveying == "unique_ip":
                    return
                else:
                    found = True
                    prefix = self.ipSeen[ip]
                    record, kind = self.ranges[prefix]
            else:
                found = False
                for prefix, o in self.ranges.items(): # search for prefix the slow way. I dont know how to make this shorter because IP can be in shortened form so that in every case I had to put it in full form and then slowly compare strings with prefixes.                    
                    if ip in prefix:
                        found = True
                        record, kind = o
                        break
                if self.conveying == "unique_file" and found:
                    return                

            #rowNew = row
            if not unknownMode: # (in unknown mode, this was already done)
                if self.urlColumn is not None:
                    row += self.delimiter + ip # append determined IP to the last col

                #if self.asnColumn  is not None:
                #    s = records[self.asnColumn].replace(" ", "")
                #    if s[0:2] != "AS": s = "AS" + s
                #    self.ip2asn[ip] = s # key is IP XXX tohle se pouziva?

                if found == False:
                    prefix, kind, record = Whois(ip).analyze()
                    if not prefix:
                        logging.info("No prefix found for IP {}".format(ip))
                    elif prefix not in self.ranges:
                        self.ranges[prefix] = record, kind
                    else: # IP in ranges wasnt found and so that its prefix shouldnt be in ranges.
                        raise AssertionError("The prefix " + prefix + " shouldnt be already present. Tell the programmer")
                    #print("IP: {}, Prefix: {}, Record: {}, Kind: {}".format(ip, prefix,record, kind)) # XX put to logging
           
            else: # force to obtain abusemail
                if not found:
                    raise AssertionError("The prefix for ip " + ip + " should be already present. Tell the programmer.")
                if record == "unknown": # prefix is still unknown                                                        
                    record = Whois(ip).resolveUnknownMail()
                    if record != "unknown": # update prefix
                        self.ranges[prefix] = record, kind
                    else: # the row will be moved to unknown.local file again
                        print("No success for prefix {}.".format(prefix))

            # write the row to the appropriate file
            self.ipSeen[ip] = prefix
            self.reg[kind].count(row, record, ip, prefix)
        except Exception as e: # FileNotExist
            print("ROW fault" + row)            
            print("This should not happen. CSV is wrong or tell programmer to repair this.")
            Config.errorCatched()

    def resolveUnknown(self):
        """ Process all prefixes with unknown abusemails. """
        if self.abuseReg.stat("ips", found=False) < 1:
            print("No unknown abusemails.")
            return

        s = "There are {0} IPs in {1} unknown prefixes. Should I proceed additional search for these {1} items?".format(self.abuseReg.stat("ips", found=False), self.abuseReg.stat("prefixes", found=False))
        if not Dialogue.isYes(s):
            return
        
        temp = Config.getCacheDir() + ".unknown.local.temp"
        try:
            move(self.abuseReg.getUnknownPath(), temp)
        except FileNotFoundError:
            print("File with unknown IPs not found. Maybe resolving of unknown abusemails was run it the past and failed. Please run whois analysis again.")
            return False
        self.lineCount = 0
        self.abuseReg.resetUnknowns()
        with open(temp, "r") as sourceF:
            for line in sourceF:
                self._processLine(line, unknownMode=True)
        self.lineCount = 0
        self.soutInfo()

    def resolveInvalid(self):
        """ Process all invalid rows. """
        if self.invalidReg.stat() < 1:
            print("No invalid rows.")
            return

        while True:
            s = "There were {0} invalid rows. Open the file in text editor (o) and make the rows valid, when done, hit y for reanalysing them, or hit n for ignoring them. [o]/y/n ".format(self.invalidReg.stat())
            res = Dialogue.ask(s)
            if res == "n":
                return False
            elif res == "y":
                break
            else:
                subprocess.Popen(['gedit',self.invalidReg.getPath()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        temp = Config.getCacheDir() + ".unknown.invalid.temp"
        try:
            move(self.invalidReg.getPath(), temp)
        except FileNotFoundError:
            print("File with invalid lines not found. Maybe resolving of it was run it the past and failed. Please run again.")
            return False
        self.lineCount = 0
        self.invalidReg.reset()
        with open(temp, "r") as sourceF:
            for line in sourceF:
                self._processLine(line)
        self.lineCount = 0
        self.soutInfo()

    # Vypise vetu:
    # Celkem 800 unikatnich IP;
    # z toho nalezených 350 v 25 zemích a nenalezených 30 IP adres v 2 zemích;
    # 570 IP adres jsme distribuovali 57 českým ISP a pro 30 jsme ISP nenalezli.
    def getStatsPhrase(self, generate=False):
        # XZadani
        #1. Pocet unikatnich IP adres celkem
        #2. Pocet unikatnich IP adres v CR
        #3. Pocet unikatnich IP adres v jinych zemi
        #4. Kontaktovano xy ISP v CR
        #5. Naslo to xy Zemi (ne vsechny Zeme maji narodni/vladni CSIRT, ale to urcite vis)
        #6. Kontaktovano xy Zemi (kam se bude posilat)
        ab = self.abuseReg.stat
        co = self.countryReg.stat

        ipsUnique = ab("ips", "both") + co("ips", "both")

        ispCzFound = ab("records", True)
        ipsCzMissing = ab("ips", False)
        ipsCzFound = ab("ips", True)

        ipsWorldMissing = co("ips", False)
        ipsWorldFound = co("ips", True)
        countriesMissing = co("records", False)
        countriesFound = co("records", True)

        invalidLines = self.invalidReg.stat()
        

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
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.invalidReg.getPath())

        #res += "."
        return res
