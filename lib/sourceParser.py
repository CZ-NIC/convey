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
from lib.registry import AbusemailsRegistry
from lib.registry import CountriesRegistry
from lib.whois import Whois
import logging
from math import sqrt
import ntpath
import os
import pdb
import pudb
import re
from shutil import move
import sys
import threading
logging.FileHandler('whois.log', 'a')


class SourceParser:
    
    def soutInfo(self, clear=True, full = False):
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
        
        if self.hostColumn is not None:
            l.append("Host column: " + self.fields[self.hostColumn])
        if self.ipColumn is not None:            
            l.append("IP column: " + self.fields[self.ipColumn])
        if self.asnColumn is not None:
            l.append("ASN column: " + self.fields[self.asnColumn])
        print(", ".join(l))
        if self.whoisStats:
            print("During analysis, whois servers were called: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.whoisStats.items()))
        if self.lineCount:
            print("Log lines processed: {}".format(self.lineCount))
        if self.extendCount > 0:
            print("+ other {} rows, because some domains had multiple IPs".format(self.extendCount))

        print("\nSample:\n" + "\n".join(self.sample.split("\n")[:3]) + "\n") # show first 3rd lines
        [reg.soutInfo(full) for reg in self.reg.values()]

        if full:
            print("\nPrefixes encountered:\nprefix | kind | record")
            for prefix, o in self.ranges.items():                
                record, kind = o
                print("{} | {} | {}".format(prefix,kind,record))


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
        self.ipColumn = CsvGuesses.guessCol(self, "IP/HOST", fn, ["ip", "sourceipaddress", "ipaddress", "source"])

        if self.ipColumn:
            print("We can't live without IP/HOST column. Try again or write x for cancellation.")
            return self.askIpCol()
        
        if not Whois.checkIp(self.sample.split("\n")[1 if self.hasHeader else 0].split(self.delimiter)[self.ipColumn]):# determine if it's IP column or DOMAIN column. I need to skip header. (Note there may be a 1 line file)            
            print("Domains in this column will be translated to IP.")
            self.hostColumn, self.ipColumn = self.ipColumn, len(self.fields) #-1
            self.fields.append("will be fetched")
            if self.hasHeader == True: # add HOST_IP column
                dl = self.delimiter if self.delimiter else ","
                self.header += dl + "HOST_IP"

    def askAsnCol(self):
        fn = lambda field: re.search('AS\d+', field) != None
        self.asnColumn = CsvGuesses.guessCol(self, "ASN", fn, ["as", "asn", "asnumber"])


    def __init__(self, sourceFile):
        print("Processing file.")        
        self.isRepeating = False
        while True:
            self._reset()
            #instance attributes init
            self.multithread = Config.get("multithread") # if True, whois will be asked multithreaded (but we may flood it)
            #self.lines = None #lines of csv file
            self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
            self.countries = defaultdict(set) # countries[gb] = {ip, ...} MailDraft structure takes IPs here.
            self.countriesMissing = defaultdict(set) # elements from self.countries that couldn't be triaged to MailDraft by whois

            self.ipColumn = None # IP column position
            self.asnColumn = None # AS number collumn position
            self.hostColumn = None # URL column position, to be translated to IP
            self.delimiter = None  #CSV dialect
            #self.whoisBCount = 0
            self.hasHeader = None
            self.header = "" # if CSV has header, it's here
            self.fields = []

            # ASN atributy - maybe should be reworked XX
            self.isp = {} # isp["AS1025"] = {mail, ips:set() }
            self.ip2asn = dict() # ip2asn[ip] = asn

            # OTRS attributes to be linked to CSV
            self.ticketid = False
            self.ticketnum = False
            self.cookie = False
            self.token = False

            self.ticketid = Config.get("ticketid", "OTRS")
            self.ticketnum = Config.get("ticketnum", "OTRS")

            self.attachmentName = "part-" + ntpath.basename(sourceFile)

            #load CSV            
            self.sourceFile = sourceFile
            self.sniffer = csv.Sniffer()            
            self.firstLine, self.sample = CsvGuesses.getSample(self.sourceFile)
            try:
                for fn in [self.askBasics, self.askIpCol, self.askAsnCol]: # steps of dialogue
                    self.soutInfo()
                    fn()
            except Cancelled:
                print("CANCELLATION, napsal jsem x? XXX DOES IT WORK?")
                continue # XX But if analysis is in the cache, we maybe want to cancel to main menu. If its not in the cache, we cant get to main menu.

            self.soutInfo()
            if not Dialogue.isYes("Everything set alright?"):
                self.isRepeating = True
                continue # repeat
            else:                
                self.runAnalysis()
                break

    def _reset(self):
        #cant be pickled: self.reg = namedtuple('SourceParser.registries', 'local foreign')(AbusemailsRegistry(), CountriesRegistry())
        self.reg = {'local': AbusemailsRegistry(), "foreign":CountriesRegistry()}
        #self.reg = Registries
        self.ranges = {}        
        self.lineCount = 0        
        self.extendCount = 0
        self.isAnalyzedB = False
        self.sums = {}
        self.whoisStats = Whois.stats # so that it is saved

    ## ma nahradit hodne metod XXX
    def runAnalysis(self):        
        self._reset()
        if Config.getboolean("autoopen_editor"):
            [r.mailDraft.guiEdit() for r in self.reg.values()]
        with open(self.sourceFile, 'r') as csvfile:
            for line in csvfile:
                self._processLine(line)                
                        
        self.isAnalyzedB = True
        [r.update() for r in self.reg.values()]
        if self.reg["local"].stat("prefixes", found = False):
            print("Analysis COMPLETED.\n\n")
            self.resolveUnknown()

    def isAnalyzed(self):
        return self.isAnalyzedB
        
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
        if sqrt(self.lineCount) % 1 == 0:
            self.soutInfo()
        try:
            # obtain IP from the line. (Or more IPs, if theres host column).
            records = row.split(self.delimiter)
            if not unknownMode and self.hostColumn is not None: # if CSV has DOMAIN column that has to be translated to IP column
                ips = Whois.url2ip(records[self.hostColumn])
                if len(ips) > 1:
                    self.extendCount += len(ips) -1 # count of new lines in logs
                    print("Host {} has {} IP addresses: {}".format(records[self.hostColumn], len(ips), ips))
            else: # only one reçord
                ips = [records[self.ipColumn].replace(" ", "")] # key taken from IP column            
            
            for ip in ips:
                rowNew = row
                if not unknownMode: # (in unknown mode, this was already done)
                    if self.hostColumn is not None:
                        rowNew += self.delimiter + ip # append determined IP to the last col

                    if self.asnColumn  is not None:
                        str = records[self.asnColumn].replace(" ", "")
                        if str[0:2] != "AS":
                            str = "AS" + str
                        self.ip2asn[ip] = str # key is IP XXX tohle se pouziva?

                # determine the prefix
                found = False
                for prefix, o in self.ranges.items():
                    if ip in prefix:
                        found = True
                        record, kind = o
                        break

                if unknownMode: # force to obtain abusemail
                    if not found:
                        raise AssertionError("The prefix for ip " + ip + " should be already present. Tell the programmer.")
                    if record == "unknown": # prefix is still unknown                                                        
                        record = Whois(ip).resolveUnknownMail()
                        if record != "unknown": # update prefix
                            self.ranges[prefix] = record, kind
                        else: # the row will be moved to unknown.local file again
                            print("No success for prefix {}.".format(prefix))
                    #import ipdb;ipdb.set_trace()
                
                elif found == False:
                    prefix, kind, record = Whois(ip).analyze()
                    if not prefix:                        
                        logging.info("No prefix found for IP {}".format(ip))
                    elif prefix not in self.ranges:
                        self.ranges[prefix] = record, kind
                    else: # IP in ranges wasnt found and so that its prefix shouldnt be in ranges.
                        raise AssertionError("The prefix " + prefix + " shouldnt be already present. Tell the programmer")
                    #print("IP: {}, Prefix: {}, Record: {}, Kind: {}".format(ip, prefix,record, kind)) # XX put to logging

                # write the row to the appropriate file                
                method = "a" if self.reg[kind].count(record, ip, prefix) else "w"
                with open(Config.getCacheDir() + record + "." + kind, method) as f:
                    if method == "w" and self.hasHeader:
                        f.write(self.header + "\n")
                    f.write(rowNew + "\n")
        except Exception as e:
            print("ROW fault" + row)
            pdb.set_trace()
            print("This should not happen. CSV is wrong or tell programmer to repair this.")
            raise

    def resolveUnknown(self):
        """ Process all prefixes with unknown abusemails. """
        if self.reg["local"].stat("ips", found=False) < 1:
            print("No unknown abusemails.")
            return

        s = "There are {0} IPs in {1} unknown prefixes. Should I proceed additional search for these {1} items?".format(self.reg["local"].stat("ips", found=False), self.reg["local"].stat("prefixes", found=False))
        if not Dialogue.isYes(s):
            return
        
        temp = Config.getCacheDir() + ".unknown.local.temp"
        try:
            move(Config.getCacheDir() + "unknown.local", temp)
        except FileNotFoundError:
            print("File with unknown IPs not found. Maybe resolving of unknown abusemails was run it the past and failed. Please run whois analysis again.")
            return False
        self.lineCount = 0 # XX this will mess up lineCount of WhoisAnalysis. Maybe it's a bug.
        self.reg["local"].resetUnknowns()
        with open(temp, "r") as sourceF:
            for line in sourceF:
                self._processLine(line, unknownMode=True)        

###### from here down nothing has been edited yet ######
##### vetsinu smazat, az whois zafunguje ###############

    def launchWhois(self): # launches long file processing
        self._lines2logs()
        self._logs2countries()

        self.mailLocal = MailDraft("mail_local_isps", Config.get("mail_template_local")) # local mail
        self.mailForeign = MailDraft("mail_foreign_csirts", Config.get("mail_template_foreign")) # foreign mail

        if Config.get("local_country") in self.countries: # local -> abuse mails
            self._buildListCz(self.countries.pop(Config.get("local_country")))
            self.applyCzCcList() # additional Cc contacts to local abusemails

        self.buildListWorld() # Foreign -> contacts to other CSIRTs


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
        lo = self.reg["local"].stat
        fo = self.reg["foreign"].stat

        ipsUnique = lo("ips", "both") + fo("ips", "both")

        ispCzFound = lo("records", True)
        ipsCzMissing = lo("ips", False)
        ipsCzFound = lo("ips", True)

        ipsWorldMissing = fo("ips", False)
        ipsWorldFound = fo("ips", True)
        countriesMissing = fo("records", False)
        countriesFound = fo("records", True)
        

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
            res += " (for {} unique local IPs ISP not found)".format(ipsCzMissing)

        res += "."
        return res
