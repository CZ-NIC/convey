# Source file parsing
from collections import defaultdict
from collections import namedtuple
import datetime
import ipdb
import itertools
from lib.config import Config
from lib.csvGuesses import CsvGuesses
from lib.dialogue import Cancelled
from lib.dialogue import Dialogue
from lib.informer import Informer
from lib.processer import Processer
from lib.registry import AbusemailRegistry
from lib.registry import CountryRegistry
from lib.registry import InvalidRegistry
from lib.whois import Whois
import logging
from math import ceil
import ntpath
import os
import pdb
import pudb
import re
from shutil import move
import subprocess
import sys
logging.FileHandler('whois.log', 'a')


class SourceParser:

    def __init__(self, sourceFile):
        print("Processing file.")
        self.isRepeating = False
        while True:
            #instance attributes init
            #self.multithread = Config.get("multithread") # if True, whois will be asked multithreaded (but we may flood it)
            #self.ipColumn = None # IP column position
            #self.asnColumn = None # AS number collumn position
            #self.urlColumn = None # URL column position, to be translated to IP
            self.settings = defaultdict(list) # for processer
            self.delimiter = None  # CSV dialect
            self.hasHeader = None # CSV has header
            self.header = "" # if CSV has header, it's here
            self.fields = [] # CSV columns
            self.redo_invalids = Config.getboolean("redo_invalids")
            #self.conveying = Config.get("conveying")
            #if not self.conveying: # default
            #    self.conveying = "all"

            # OTRS attributes to be linked to CSV
            self.otrs_cookie = False
            self.otrs_ticketid = Config.get("ticketid", "OTRS")
            self.otrs_token = False
            self.otrs_ticketnum = Config.get("ticketnum", "OTRS")
            self.attachmentName = "part-" + ntpath.basename(sourceFile)
            self.ipCountGuess = None
            self.ipCount = None
            self._reset()

            #load CSV
            self.sourceFile = sourceFile
            self.size = os.path.getsize(self.sourceFile)            
            self.processer = Processer(self)
            self.informer = Informer(self)            
            self.guesses = CsvGuesses(self)
            self.firstLine, self.sample = self.guesses.getSample(self.sourceFile)
            self.linesTotal = self.informer.fileLen(sourceFile) #sum(1 for line in open(sourceFile))
            try:
                ##for fn in [, self._askPivotCol, self._sizeCheck, self._askOptions]: # steps of dialogue
                self.informer.soutInfo()
                self._askBasics()
            except Cancelled:
                print("Cancelled.")
                return
            self.informer.soutInfo()

            # X self._guessIpCount()
            if not Dialogue.isYes("Everything set alright?"):
                self.isRepeating = True
                continue
            else:
                self.isFormattedB = True # delimiter and header has been detected etc.
                break


    def _askBasics(self):
        """ Dialog to obtain basic information about CSV - delimiter, header """
        self.delimiter, self.hasHeader = self.guesses.guessDelimiter(self.sample)        
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
        self.guesses.identifyCols()
        #else:
        #    self.fields = [self.firstLine]


    """
    def _askPivotCol(self):
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

    def _askAsnCol(self): # The function is not used now.
        fn = lambda field: re.search('AS\d+', field) != None
        self.asnColumn = CsvGuesses.guessCol(self, "ASN", fn, ["as", "asn", "asnumber"])
    """


    def _reset(self):
        """ Reset variables before new analysis. """        
        self.stats = defaultdict(set)
                
        #cant be pickled: self.reg = namedtuple('SourceParser.registries', 'local foreign')(AbusemailRegistry(), CountryRegistry())
        #self.abuseReg = AbusemailRegistry();
        #self.countryReg = CountryRegistry()
        #self.invalidReg = InvalidRegistry()
        #self.reg = {'local': self.abuseReg, "foreign":self.countryReg, "error": self.invalidReg}
        #self.reg = Registries
        Config.hasHeader = self.hasHeader
        Config.header = self.header
        self.ranges = Whois.ranges # so that it is saved
        self.lineCount = 0
        self.velocity = 0
        self.lineSout = 1
        #self.appendFields = {'asn': False, "netname": False, "domain": False, "ip": False} # fields included in CSV
        # XXX: nacist z config.ini. Ma to by zde nebo v __init?

        #self.lineSumCount = 0
        #self.linesTotal = 0
        #self.extendCount = 0
        self.timeStart = None
        self.timeEnd = None
        self.timeLast = None
        self.isAnalyzedB = False
        self.isFormattedB = False
        self.sums = {}
        self.whoisStats = Whois.stats # so that it is saved        
        Whois.ipSeen = dict() # Xself.ipSeen # ipSeen[ip] = prefix
        #self.abuseReg.conveying = self.conveying
        #self.countryReg.conveying = self.conveying
        #self.invalidReg.redo_invalids = self.redo_invalids

    def runAnalysis(self):
        """ Run main analysis of the file.
        Grab IP from every line and
        """
        self._reset()
        """
        if Config.getboolean("autoopen_editor"):
            [r.mailDraft.guiEdit() for r in self.reg.values()]
        """
        self.timeStart = self.timeLast = datetime.datetime.now().replace(microsecond=0)

        self.processer.processFile(self.sourceFile)
        self.timeEnd = datetime.datetime.now().replace(microsecond=0)
        self.linesTotal = self.lineCount # if we guessed the total of lines, fix the guess now

        self.isAnalyzedB = True
        """
        [r.update() for r in self.reg.values()]
        if self.invalidReg.stat() and self.redo_invalids:
            self.informer.soutInfo()
            print("Analysis COMPLETED.\n\n")
            self.resolveInvalid()
        if self.abuseReg.stat("prefixes", found=False):
            self.informer.soutInfo()
            print("Analysis COMPLETED.\n\n")
            self.resolveUnknown()
        """
        self.lineCount = 0
        self.informer.soutInfo()

    """
    def _sizeCheck(self):
        mb = 10
        if self.size > mb * 10 ** 6 and self.conveying == "all":
            if Dialogue.isYes("The file is > {} MB and conveying method is set to all. Don't want to rather set the method to 'unique_ip' so that every IP had only one line and the amount of information sent diminished?".format(mb)):
                self.conveying = "unique_ip"
        if self.size > mb * 10 ** 6 and self.redo_invalids == True:
            if Dialogue.isYes("The file is > {} MB and redo_invalids is True. Don't want to rather set it to False and ignore all invalids? It may be faster.".format(mb)):
                self.redo_invalids = False

    def _askOptions(self):
        "" Asks user for other parameters. They can change conveying method and included columns. ""
        # XXX
        pass
    """

    def _guessIpCount(self):
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
                    print("In the first {} lines, there are {} unique IPs. There might be around {} IPs in the file.".format(i, len(ipSet), self.ipCountGuess))
            except Exception as e:
                print("Can't guess IP count.")


    def isAnalyzed(self):
        return self.isAnalyzedB

    def isFormatted(self):
        return self.isFormattedB


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
        self.processer.processFile(temp, reprocessing=True)
        self.lineCount = 0
        self.informer.soutInfo()

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
                subprocess.Popen(['gedit', self.invalidReg.getPath()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        temp = Config.getCacheDir() + ".unknown.invalid.temp"
        try:
            move(self.invalidReg.getPath(), temp)
        except FileNotFoundError:
            print("File with invalid lines not found. Maybe resolving of it was run it the past and failed. Please run again.")
            return False
        self.lineCount = 0
        self.invalidReg.reset()
        self.processer.processFile(temp)
        self.lineCount = 0
        self.informer.soutInfo()
