# Source file parsing
from collections import defaultdict
from lib.config import Config
from lib.csvGuesses import CsvGuesses
from lib.dialogue import Dialogue, Cancelled
from lib.registry import AbusemailsRegistry, CountriesRegistry
from lib.whois import Whois
import csv
import ntpath
import os
import pdb
import re
import sys
import threading
import itertools

class SourceParser:

    # file information
    def soutInfo(self, clear=True):
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

        sys.stdout.write(", ".join(l))
        sys.stdout.write("\nSample:\n" + self.sample) # XX maybe only three lines first?

        if self.reg: # print counters "ru (230), cn (12)"
            for reg in self.reg.values():
                reg.soutInfo()
                

    def askBasics(self):
        self.delimiter, self.hasHeader = CsvGuesses.guessDelimiter(self.sniffer, self.sample)        
        if not Dialogue.isYes("Is character '{}' delimiter? ".format(self.delimiter)):
            sys.stdout.write("What is delimiter: ")
            self.delimiter = input()        
        if not Dialogue.isYes("Header " + ("" if self.hasHeader else "not " + "found; ok?")):
            self.hasHeader = not self.hasHeader
        if self.hasHeader == True:
            self.header = self.firstLine
        self.fields = self.firstLine.split(self.delimiter)



    def askIpCol(self):
        fn = lambda field: Whois.checkIp(field)        
        self.ipColumn = CsvGuesses.guessCol(self, "IP/HOST", fn, ["ip", "sourceipaddress", "ipaddress", "source"])

        if self.ipColumn == -1:
            print("We can't live without IP/HOST column. Try again or write x for cancellation.")
            return self.askIpCol()

        if not Whois.checkIp(self.sample.split("\n")[1].split(self.delimiter)[self.ipColumn]):# determine if it's IP column or DOMAIN column
            print("Domains in this column will be translated to IP.")
            self.hostColumn, self.ipColumn = self.ipColumn, -1
            if self.hasHeader == True: # add HOST_IP column
                self.header += self.delimiter + "HOST_IP"

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

            self.ticketid = Config.get("ticketid","OTRS")
            self.ticketnum = Config.get("ticketnum","OTRS")

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
        self.reg = {"local": AbusemailsRegistry(), "foreign": CountriesRegistry()}
        self.ranges = {}        
        self.lineCount = 0
        self.ipCount = 0
        self.extendCount = 0
        self.isAnalyzedB = False
        self.sums = {}

    ## ma nahradit hodne metod XXX
    def runAnalysis(self):
        self._reset()
        with open(self.sourceFile, 'r') as csvfile:
            for line in csvfile:
                self._processLine(line)                

            print("IP count: {}".format(self.lineCount))
            print("Log lines count: {}".format(self.ipCount))
            if self.extendCount > 0:
                print("+ other {} rows, because some domains had multiple IPs".format(extend))
        self.isAnalyzedB = True
        for r in self.reg.values():
            r.update()

        ### XXX jeste se nikde nepridava CC k ceskkym IP. Zde, nebo az pri odeslani?

    def isAnalyzed(self):
        return self.isAnalyzedB
        

    ## link every line to IP
    # ranges[range] = name.location (it.foreign, abuse@mail.com.local)
    def _processLine(self, row):
        row = row.strip()
        if(row == ""):
            return
        self.lineCount += 1
        if self.lineCount == 1 and self.hasHeader: # skip header
            return
        try:
            records = row.split(self.delimiter)
            if self.hostColumn is not None: # if CSV has DOMAIN column that has to be translated to IP column
                ips = Whois.url2ip(records[self.hostColumn])
            else:
                ips = [records[self.ipColumn].replace(" ", "")] # key taken from IP column

            if len(ips) > 1:
                self.extendCount += len(ips) -1 # count of new lines in logs
                print("Host {} has {} IP addresses: {}".format(records[self.hostColumn], len(ips), ips))

            for ip in ips:
                self.ipCount += 1
                if self.hostColumn != -1:
                    row += self.delimiter + ip # append determined IP to the last col

                if self.asnColumn != -1:
                    str = records[self.asnColumn].replace(" ", "")
                    if str[0:2] != "AS":
                        str = "AS" + str
                    self.ip2asn[ip] = str # key is IP

                prefix, kind, name = Whois(ip).analyze()
                if prefix not in self.ranges:
                    self.ranges[prefix] = name + "." + kind
                method = "a" if self.reg[kind].count(name, 1) else "w"                
                with open(self.ranges[prefix], method) as f:
                    f.write(row)
        except:
            print("ROW fault" + row)
            print("This should not happend. CSV is wrong or tell programmer to repair this.")
            raise

    def launchWhois(self): # launches long file processing
        self._lines2logs()
        self._logs2countries()

        self.mailLocal = MailDraft("mail_local_isps", Config.get("mail_template_local")) # local mail
        self.mailForeign = MailDraft("mail_foreign_csirts", Config.get("mail_template_foreign")) # foreign mail

        if Config.get("local_country") in self.countries: # local -> abuse mails
            self._buildListCz(self.countries.pop(Config.get("local_country")))
            self.applyCzCcList() # additional Cc contacts to local abusemails

        self.buildListWorld() # Foreign -> contacts to other CSIRTs

###### from here down nothing has been edited yet ######
##### vetsinu smazat, az whois zafunguje ###############


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
        lo =self.reg["local"].stat
        fo = self.reg["foreign"].stat

        ipsUnique = lo("ips", True) + fo("ips", True)

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
