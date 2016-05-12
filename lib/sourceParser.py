# Source file parsing
from collections import defaultdict
from lib.config import Config
from lib.mailList import MailList
from lib.whois import Whois
from pprint import pprint
import csv
import ntpath
import os
import pickle
import re
import sys
import threading
import pdb

class SourceParser:

    def __init__(self, sourceFile):
        repeating = False
        while True:
            #instance attributes init
            self.multithread = False # if True, whois will be asked multithreaded (but we may flood it)
            self.lines = None #lines of csv file
            self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
            self.countries = defaultdict(set) # countries[gb] = {ip, ...} MailList structure takes IPs here.
            self.countriesMissing = defaultdict(set) # elements from self.countries that couldn't be triaged to MailList by whois

            self.ipField = 0 # IP column position
            self.asnField = -1 # AS number collumn position
            self.hostField = -1 # URL column position, to be translated to IP
            self.delimiter = None  #CSV dialect
            #self.whoisBCount = 0
            self.info = "" # CSV file metadata gathered
            self.header = "" # if CSV has header, it's here

            # ASN atributy - maybe should be reworked XX
            self.isp = {} # isp["AS1025"] = {mail, ips:set() }
            self.ip2asn = dict() # ip2asn[ip] = asn

            # OTRS attributes to be linked to CSV
            self.ticketid = False
            self.ticketnum = False
            self.cookie = False
            self.token = False

            self.ticketid = Config.get("ticketid")
            self.ticketnum = Config.get("ticketnum")

            self.attachmentName = "part-" + ntpath.basename(sourceFile)

            #load CSV
            self._loadCsv(sourceFile, repeating)

            sys.stdout.write("Everything set alright? [y]/n ")
            if input() == "n":
                repeating = True
                continue # repeat
            else:
                self.mailCz = False # local mail declaration
                self.mailWorld = False # foreign mail declaration
                self.launchWhois()
                break

    def launchWhois(self): # launches long file processing
        self._lines2logs()
        self._logs2countries()

        self.mailCz = MailList("mail_cz", Config.get("mail_template_local")) # local mail
        self.mailWorld = MailList("mail_world", Config.get("mail_template_foreign")) # foreign mail

        if Config.get("local_country") in self.countries: # local -> abuse mails
            self._buildListCz(self.countries.pop(Config.get("local_country")))
            self.applyCzCcList() # additional Cc contacts to local abusemails

        self.buildListWorld() # Foreign -> contacts to other CSIRTs

    def _addInfo(self, txt):
        self.info += txt + "\n"
        print(txt)

    ## Parses CSV file to fields and guesses IP field.
    def _loadCsv(self, sourceFile, repeating=False):
        # prepare CSV to analysis
        self._addInfo("Source file: " + sourceFile)
        csvfile = open(sourceFile, 'r')
        self.lines = csvfile.read().splitlines()
        sample = ""
        for i, row in enumerate(self.lines):
            if(i == 0):
                firstLine = row
            sample += row + "\n"
            if(i == 8): #XX sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                break
        
        # guess delimiter
        try:
            self.delimiter = csv.Sniffer().sniff(sample).delimiter
        except csv.Error: # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            s = sample.split("\n")[1] # we dont take header (there is no empty column for sure)
            for dl in (",",";","|"): # lets suppose the double sign is delimiter
                if s.find(dl+dl) > -1:
                    self.delimiter = dl
                    break
            
        print(sample)
        sys.stdout.write("Is character '{}' delimiter? [y]/n ".format(self.delimiter))
        if input() not in ("Y", "y", ""):
            sys.stdout.write("What is delimiter: ")
            self.delimiter = input()
            #sys.stdout.write("Correct? [y]/n ")
        else:
            self._addInfo("Delimiter: {}".format(self.delimiter))
        csvfile.seek(0)


        # cut log header
        try:
            hasHeader = csv.Sniffer().has_header(sample)
        except csv.Error: # if delimiter wasnt found automatically, this raises error two
            hasHeader = False # lets just guess the value the

        if hasHeader:
            sys.stdout.write("Header found – ok? [y]/n: ") # Header present
            if input().lower() not in ("y", ""):
                hasHeader = False
        else:
            sys.stdout.write("Header not found a won't be used - ok? [y]/n: ") # Header not present
            if input().lower() not in ("y", ""):
                hasHeader = True

        if hasHeader == True:
            self.header = firstLine
            self._addInfo("Header: used") # Header: used
            self.lines.pop(0)
        else:
            self.header = ""
            self._addInfo("Header: not used") # Header: not used

        fields = firstLine.split(self.delimiter)

        # IP column
        def _findIpCol():
            found = False
            if repeating == False: # dialog goes for first time -> autodetect
                ipNames = ["ip", "sourceipaddress", "ipaddress", "source"] # possible IP column names – no space
                for fieldname in fields:
                    field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
                    if hasHeader == True: # file has header, crawl it
                        if field in ipNames: # this may be IP column name
                            self._addInfo("IP field column: " + fieldname)
                            found = True
                            break
                    else: # CSV dont have header -> pgrep IP, or ask user
                        if Whois.checkIp(field): # no IP -> error. May want all different shortened version of IP (notably IPv6).                            
                            found = True
                            break
                    self.ipField += 1

                if found == True:
                    sys.stdout.write("Is IP field column: {}? [y]/n ".format(fieldname))
                    if input().lower() in ("y", ""):
                        self._addInfo("IP column: " + fields[self.ipField])
                    else:
                        found = False

            if found == False: # IP not found, ask user
                i = 1
                print("\nWhat is IP/HOST column:")
                for fieldname in fields:# print columns
                    print(str(i) + ". " + fieldname)
                    i += 1            

                try:
                    option = int(input('IP column: '))
                    self.ipField = option -1

                    if Whois.checkIp(self.lines[0].split(self.delimiter)[self.ipField]):# determine if it's IP column or DOMAIN column
                        self._addInfo("IP column:" + fields[self.ipField])
                    else:
                        self._addInfo("HOST column:" + fields[self.ipField])
                        print("Domains in this column will be translated to IP.")
                        self.hostField, self.ipField = self.ipField, -1

                        if hasHeader == True: # add HOST_IP column
                            self.header += self.delimiter + "HOST_IP"

                except ValueError:
                    print("This is not a number")
                    raise


            #sloupec AS
        def _findAsnCol():
            found = False            
            if repeating == False: # dialog goes for first time -> autodetect
                asNames = ["as", "asn", "asnumber"] # different types of name – no space
                self.asnField = 0
                for fieldname in fields:
                    field = fieldname.replace(" ", "").lower()
                    if hasHeader == True:
                        if field in asNames: # this may be ASN column name
                            found = True
                            break
                    else: # no header -> pgrep IP, or ask
                        if re.search('AS\d+', field) != None: #X 'AS1234'
                            found = True
                            break
                    self.asnField += 1
                if found == True: # may wrong name was found
                    sys.stdout.write("Is ASN field column: {}? [y]/n ".format(fieldname))
                    if input().lower() in ("y", ""):
                        self._addInfo("ASN column:" + fields[self.asnField])
                    else:
                        found = False

            if found == False:#ASN not found -> ask user
                i = 1
                print("\nWhat is ASN column:")
                print("[0]. no ASN column")
                for fieldname in fields:
                    print(str(i) + ". " + fieldname)
                    i += 1
                try:
                    self.asnField = int(input('ASN column: ')) -1
                except ValueError:
                    self.asnField = -1 # -> ASN not used
                if self.asnField == -1:
                    self._addInfo("ASN will not be used.")
                else:
                    self._addInfo("ASN column: " + fields[self.asnField])

        _findIpCol()
        _findAsnCol()
        csvfile.close()

    ## link every line to IP
    # logs[IP] = {log, ...}
    def _lines2logs(self):
        self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
        extend = 0
        for row in self.lines:
            if(row.strip() == ""):
                continue
            try:
                fields = row.strip().split(self.delimiter)
                if self.hostField != -1: # if CSV has DOMAIN column that has to be translated to IP column
                    ips = Whois.url2ip(fields[self.hostField])
                else:
                    ips = [fields[self.ipField].replace(" ", "")] # key taken from IP column

                if len(ips) > 1:
                    extend = len(ips) -1 # count of new lines in logs
                    print("Host {} has {} IP addresses: {}".format(fields[self.hostField], len(ips), ips))

                for ip in ips:
                    log = row
                    if self.hostField != -1:
                        log += self.delimiter + ip # append determined IP to the last col

                    if self.asnField != -1:
                        str = fields[self.asnField].replace(" ", "")
                        if str[0:2] != "AS":
                            str = "AS" + str
                        self.ip2asn[ip] = str # key is IP

                    self.logs[ip].add(log) # store new log to key
            except:
                print("ROW fault" + row)
                print("This should not happend. CSV is wrong or tell programmer to repair this.")
                raise



        print("IP count: {}".format(self.getIpCount()))
        print("Log lines count: {}".format(len(self.lines)))
        if extend > 0:
            print("+ other {} rows, because some domains had multiple IPs".format(extend))

    def getIpCount(self):
        return len(self.logs)


    ## In: logs[ip] = {log,...}
    # Out: countries[cz] = {ip, ...}
    def _logs2countries(self):
        self.countries = defaultdict(set)
        #self.countriesOriginal = defaultdict(set)
        sys.stdout.write("Asking whois for countries ...: ")
        sys.stdout.flush()

        # IP -> whois country
        if self.multithread == True:
            threads = []
            for ip in self.logs:
                #threads  XX lets hope theres optimal count of thread
                t = threading.Thread(target=self._push2countries, args=([ip]))
                threads.append(t)
                t.start()
            # consolidate domains information
            for thread in threads:
                thread.join()
        else:# do not use multithread
            for ip in self.logs:
                self._push2countries(ip)

        sys.stdout.write("\n")
        print("Countries count: " + str(len(self.countries)))


    # Append country of IP to self.countries
    lock = threading.RLock()
    def _push2countries(self, ip):
        country = Whois.queryCountry(ip)

        #if (country in self.countries) == False: # add key that does not exist XX I think if I put this condition 2×, firstly outside lock, I ll be faster
        with SourceParser.lock: # It can never happen that two threads appends the same key
            if (country not in self.countries):
                sys.stdout.write(country + ', ')
                sys.stdout.flush() # print immediately

        self.countries[country].add(ip) # store new log to key
        pass

    ##
    # Seek out abusemail contact for local IPs.
    #
    # Loads set of IPs with the same abusemail into self.mailCz[mail].
    # Set of IPs without abusemail goes to self.mailCz[""].
    # Depending to the config.ini (spare_b_flag, b_flag_threshold) it searches abusemails for every IP apart,
    # or searches abusemails for ASN. This spares whois-flag B, that is limited to cca 1500 / day.
    #
    # XX I am ready (I think) with the possibility when different IPs from ASN goes under diffent countries.
    #    If this happens, only local CZ IP logs will be sent to ASN abuse mail
    #
    def _buildListCz(self, ips):
        self.mailCz.resetMails()
        print("Querying whois for mails.")
        if Config.getboolean('spare_b_flag') == False: # do not spare B flag (directly use queryMail force = True)
            # asks every IP for abusemail
            for ip in ips:
                mail, bSpared = Whois.queryMail(ip, True)
                self.mailCz.mails[mail].add(ip) # add to local maillist            
        else:  # try to spare B flag
            doAsn = False
            threshold = int(Config.get('b_flag_threshold'))
            if threshold == -1: # search for ASN abusemail, not IP (we spares)
                self._buildListCzByAsn(ips)
            else:
                # tries, how much -b request would be needed for individual IPs (queryMail force = false)
                ipsRedo = set() # IP where B flag is needed
                try:
                    for ip in ips:
                        mail, bSpared = Whois.queryMail(ip, False)
                        #print("QUERY: " + ip)
                        #pdb.set_trace()
                        if mail and mail != "unknown": # mail not found, B flag not needed
                            self.mailCz.mails[mail].add(ip)
                        if bSpared == False: # we would need B flag
                            ipsRedo.add(ip) # redo IP again
                except:                
                    pdb.set_trace()

                if len(ipsRedo) > threshold: # we would need more B flags than threshold
                    # asks user if we use -B flags or ASN
                    print(("Without B-flags we found {} of local abusemails. " +
                          "We need to find abusemails for {} IPs. " +
                          "(Threshold for using ASN is {} addresses.)").format(len(self.mailCz.mails), len(ipsRedo), threshold))
                    print("Do we use ASN and spare B-flags? y,[n]: ")
                    doAsn = False if input().lower() in ("", "n") else True

                if doAsn == False: # do not spare B-flag
                    for ip in ipsRedo:
                        mail = Whois.queryMailForced(ip)[0]                        
                        self.mailCz.mails[mail].add(ip)
                else:# do spare B-flag and use ASN
                    self._buildListCzByAsn(ipsRedo)


        # stats
        if Whois.bCount > 0:
            print("Whois -B flag used: {} times".format(str(Whois.bCount)))
        count = len(self.mailCz.mails)
        orphL = len(self.mailCz.getOrphans())
        if orphL:
            count -= 1
            print("Count of local IPs without abusemails: {}".format(orphL))
        else:
            print("Local whois OK!")
        print("Totally found {} abusemails. " .format(count))

    ##
    # add mails from custom list to cc-copy
    def applyCzCcList(self):
        count = 0
        file = Config.get("contacts_local")
        if os.path.isfile(file) == False: # file with contacts
            print("(File with local CC contacts {} not found.) ".format(file))
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                abusemails = {rows[0]:rows[1] for rows in reader}
                for mail in self.mailCz.mails: #check domain mail
                    self.mailCz.mails[mail].cc = ""
                    for domain in MailList.getDomains(mail):
                        if domain in abusemails:
                            count += 1
                            self.mailCz.mails[mail].cc += abusemails[domain] + ";"
            if count:
                print("CC added to {} mails.".format(len(abusemails), count))
            else:
                print("File with local contacts found, no intersection with current CSV, ok.")


    # find out abuseMail for ASN
    def _buildListCzByAsn(self, ips):
        if self.asnField == -1:            
            print("Looking up AS numbers from whois")
            for ip in ips:
                self.ip2asn[ip] = Whois.getAsn(ip)            
        else:            
            print("Country CZ detected -> ASN usage.")


        # XXX ASN may be broken, it may return lot of unknowns
        asnSet = defaultdict(set)
        for ip in ips:
            asnSet[self.ip2asn[ip]].add(ip)
        for asn in asnSet:
            mail, forced = Whois.queryMailForced(asn) # XXX why directly forced?
            self.mailCz.mails[mail].update(asnSet[asn]) # connect all IP of ASN to its mail
        print("ASN count: {}".format(len(asnSet)))

    #
    # Search for country contact – from CSV file Config.get("contacts")
    #
    def buildListWorld(self):
        self.mailWorld.resetMails()
        file = Config.get("contacts_foreign")
        if os.path.isfile(file) == False: #soubor s kontakty
            print("Foreign contacts file {} not found. ".format(file))
            return False
        with open(file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            abusemails = {rows[0]:rows[1] for rows in reader}

        # pair countries with csirtmails
        missing = []
        self.countriesMissing = self.countries.copy() #list(self.countries.keys())
        for country in list(self.countries.keys()): # find abusemail for country
            if country in abusemails:
                mail = abusemails[country]
                self.mailWorld.mails[mail].update(self.countriesMissing.pop(country)) # move IPs set under maillist
            else:
                missing.append(country)

        # info, what to do with missing csirtmails
        if len(missing) > 0:
            sys.stdout.write("Missing csirtmails for {} countries: {}\n".format(len(missing), ", ".join(missing)))
            print("Add csirtmails to the foreign contacts file (see config.ini) and relaunch whois! \n")
        else:
            sys.stdout.write("Foreign whois OK! \n")
        return True


    def missingFilesInfo(self):
        return "({} files, {} foreign and {} local contacts)".format(
                                                                len(self.countriesMissing) + (1 if len(self.mailCz.getOrphans()) else 0),
                                                                len(self.countriesMissing),
                                                                len(self.mailCz.getOrphans()))


    ## Writes log files, divided by countries
    # dir - directory without ending slash
    def generateFiles(self, dir, missingOnly=False):
        if missingOnly:
            extension = "-missing.tmp"
            files = self.countriesMissing.copy()
            files["cz_unknown"] = self.mailCz.getOrphans().copy() # local IP without abusemails will be in the 'cz' file
        else: #all files
            extension = ".tmp"
            files = self.countries.copy()
            files.update(self.mailCz.mails.copy()) # CZ IP will be in files, divided by abusemails

        dir += "/"
        count = 0
        # write files from countries and abusemails
        for file in files:
            if len(files[file]) > 0: # if we have an IP for this country
                with open(dir + file + extension, 'w') as f:
                    count += 1
                    f.write(self.ips2logfile(files[file]))

        print("Generated {} files to directory {} .".format(count, dir))

    def ips2logfile(self, ips):
        result = []
        if self.header != "": # include header to every file
            result.append(self.header)
        for ip in ips:
            for log in self.logs[ip]:
                result.append(log)
        return "\n".join(result)



        #write local files – by ASN
        #for asn in self.isp:
        #    with open(dir + asn, 'w') as f:
        #        count += 1
        #        if self.header != "":
        #            f.write(self.header + "\n")
        #        for ip in self.isp[asn]['ips']:
        #            for log in self.logs[ip]:
        #                f.write(log + "\n")

        print("Generated {} files.".format(count))

    # file information
    def soutInfo(self):
        print(self.info)        

    def soutDetails(self):
        print("**************************")
        print("Internal variables state:")
        print("\nLocal\n" + str(self.mailCz))
        print("\nForeign\n" + str(self.mailWorld))
        print("\nMissing foreign mails\n" + str(self.countriesMissing) if len(self.countriesMissing) else "All foreign IP are OK linked.")

    # Vypise vetu:
    # Celkem 800 unikatnich IP;
    # z toho nalezených 350 v 25 zemích a nenalezených 30 IP adres v 2 zemích;
    # 570 IP adres jsme distribuovali 57 českým ISP a pro 30 jsme ISP nenalezli.
    def getStatsPhrase(self, generate = False):
        # XZadani
        #1. Pocet unikatnich IP adres celkem
        #2. Pocet unikatnich IP adres v CR
        #3. Pocet unikatnich IP adres v jinych zemi
        #4. Kontaktovano xy ISP v CR
        #5. Naslo to xy Zemi (ne vsechny Zeme maji narodni/vladni CSIRT, ale to urcite vis)
        #6. Kontaktovano xy Zemi (kam se bude posilat)

        ipsUnique = self.getIpCount()
        ispCzFound = len(self.mailCz.mails)

        ipsWorldMissing = len([[y for y in self.countriesMissing[x]] for x in self.countriesMissing])
        ipsWorldFound = len([[y for y in self.mailWorld.mails[x]] for x in self.mailWorld.mails])

        countriesMissing = len(self.countriesMissing)
        countriesFound = len(self.mailWorld.mails)

        ipsCzMissing = len(self.mailCz.getOrphans())
        ipsCzFound = len([[y for y in self.mailCz.mails[x]] for x in self.mailCz.mails]) - ipsCzMissing

        if ipsUnique > 0:
            res = "Totally {} of unique IPs".format(ipsUnique)
        else:
            res = "no IP address"
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

        #if(generate == True):
            #file = Config.get("generate_statistics_to_file")
            #if file != "False":
                #with open("statistics.txt","a") as f:
                    #return f.write(csv.getStatsPhrase(generate = True))

        return res

    def __exit__(self):
        pass
