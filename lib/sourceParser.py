# Patri do projektu convey.py. Stara se o praci se zdrojovym souborem.
from collections import defaultdict
import csv
import ipaddress
from lib.config import Config
from lib.mailList import MailList
from lib.whois import Whois
import os
import pickle
from pprint import pprint
import sys
import threading
import re
#import dill

__author__ = "edvard"
__date__ = "$Feb 27, 2015 5:46:15 PM$"


class SourceParser:

    def __init__(self, sourceFile):
        while True:
            #instance attributes init
            self.multithread = False #kdyz uzivatel nastavi na True, pouzije se multithread whois
            self.lines = None #lines csv souboru
            self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
            self.countries = defaultdict(set) # countries[gb] = {ip, ...} Docasne misto, nez se IP dle whois dostanou do struktur MailList
            self.countriesOriginal = defaultdict(set) # kopie self.countries, ze ktere prvky ale nemizi po spusteni whoisu
            
            self.ipField = 0 #pozice sloupce s IP adresou
            self.asnField = 0 #pozice sloupce s AS number
            self.delimiter = None  #CSV dialect
            #self.whoisBCount = 0
            self.info = "" # nasbirana metadata o CSV souboru
            self.header = "" # pokud ma CSV souboru header, je zde

            # ASN atributy - mozna se prepracuji XX
            self.isp = {} # isp["AS1025"] = {mail, ips:set() }
            self.ip2asn = dict() # ip2asn[ip] = asn
                        
            #nacist CSV
            self._loadCsv(sourceFile)

            sys.stdout.write("Is that correct? [Y/n] ")
            sys.stdout.flush()
            option = input()
            if option == "n":
                continue #zopakovat
            else:
                self.mailCz = MailList("mail_cz", Config.get("mail_template_cz")) # dopis pro CZ                
                self.mailWorld = MailList("mail_world", Config.get("mail_template_world")) # dopis pro svet
                self.launchWhois()
                break

    def launchWhois(self): #spusti dlouhotrvajici processing souboru
        self._lines2logs()
        self._logs2countries()
        self.countriesOriginal = self.countries.copy() # backup promenne, nez se z ni ubere

        if 'cz' in self.countries: #CZ -> abuse maily
            self._ips2mails(self.countries.pop("cz"))

        self._countries2mails() # World -> kontakty na maily CSIRTu

        


    def _addInfo(self, txt):
        self.info += txt + "\n"
        print(txt)


    ## Parsuje CSV file na policka a uhadne pole IP.
    def _loadCsv(self, sourceFile):
        #pripravit csv k analyze
        self._addInfo("Source file: " + sourceFile)
        csvfile = open(sourceFile, 'r')
        self.lines = csvfile.read().splitlines()    
        sample = ""
        for i, row in enumerate(self.lines):
            if(i == 0):
                firstLine = row
            sample += row + "\n"
            if(i == 3): #snifferu na zjisteni dialektu staci treba 3 linky
                break

        #uhadnout delimiter        
        self.delimiter = csv.Sniffer().sniff(sample).delimiter
        print("Sample rows:")
        print(sample)
        sys.stdout.write("Is character '{}' delimiter? [y]/n ".format(self.delimiter))
        while input() not in ("Y","y",""):
            sys.stdout.write("What is delimiter: ")
            self.delimiter = input()
            sys.stdout.write("Correct? [y]/n ")
        self._addInfo("Delimiter: {}".format(self.delimiter))
        csvfile.seek(0)


        #vyjmout z logu hlavicku
        hasHeader = csv.Sniffer().has_header(sample)
        if hasHeader == True:
            self.header = firstLine
            self._addInfo("Header: found")
            self.lines.pop(0)
        else:
            self._addInfo("Header: not found")

        fields = firstLine.split(self.delimiter)

        # sloupec IP
        found = False
        ipNames = ["ip", "sourceipaddress", "ipaddress", "source"] #mozne nazvy ip sloupcu - bez mezer
        for fieldname in fields:
            field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
            if hasHeader == True: #soubor ma hlavicku, zjistovat v ni                
                if field in ipNames: #tohle je mozna nazev ip sloupce
                    self._addInfo("IP field column: " + fieldname)
                    found = True
                    break
            else: #csv nema hlavicku -> pgrep IP, jinak se zeptat uzivatele na cislo sloupce
                try:
                    ipaddress.ip_address(field) #pokud neni IP, vyhodi chybu. Mozna nezvladne vsechny mozne zkracene verze zapisu IP.
                    self._addInfo("IP found: " + fieldname)
                    found = True
                    break
                except: #toto neni ip
                    pass
            self.ipField += 1

        if found == False:#IP jsme nenalezli, dat uzivateli na vyber
            i = 1
            print("\nWhat is IP column:")            
            for fieldname in fields:#vypsat sloupce
                print(str(i) + ". " + fieldname)
                i += 1
            #print("0. Delimiter is wrong!") to bych musel predelat tuhle velkou do jednotlivych submetod

            try: #zeptat se uzivatele na cislo sloupce
                option = int(input('IP column: '))
                self.ipField = option -1
                self._addInfo("IP column:" + fields[self.ipField])
            except ValueError:
                print("This is not a number")
                raise

        #sloupec AS
        found = False
        asNames = ["as", "asn", "asnumber"] #mozne nazvy ip sloupcu - bez mezer
        for fieldname in fields:
            field = fieldname.replace(" ", "").lower()
            if hasHeader == True: #soubor ma hlavicku, zjistovat v ni
                if field in asNames: #tohle je mozna nazev ip sloupce
                    self._addInfo("AS field column: " + fieldname)
                    found = True
                    break
            else: #csv nema hlavicku -> pgrep IP, jinak se zeptat uzivatele na cislo sloupce
                if re.search('AS\d+', 'AS1234') != "":
                    self._addInfo("AS found: " + fieldname)
                    found = True
                    break
            self.asnField += 1

        if found == False:#AS jsme nenalezli, dat uzivateli na vyber
            i = 1
            print("\nWhat is ASN column:")
            print("0. no ASN column")
            for fieldname in fields:#vypsat sloupce
                print(str(i) + ". " + fieldname)
                i += 1
            try: #zeptat se uzivatele na cislo sloupce
                self.asnField = int(input('ASN column: ')) -1                
            except ValueError:
                print("This is not a number")
                raise
            if self.asnField == -1:
                self._addInfo("ASN will not be used.")
            else:
                self._addInfo("ASN column:" + fields[self.asnField])
        csvfile.close()
        


    ## Kazdou radku logu pripoji k IP
    # logs[IP] = {log, ...}
    def _lines2logs(self):
        i = 0
        for row in self.lines:#do klice
            if(row.strip() == ""):
                continue
            i += 1
            try:
                ip = row.strip().split(self.delimiter)[self.ipField].replace(" ", "") #klic je ip
                if self.asnField != -1:
                    self.ip2asn[ip] = row.strip().split(self.delimiter)[self.asnField].replace(" ", "") #klic je ip
            except:
                print(i)
                print("ROW " + row)
                print(row.strip() == "")
                raise

            #if (ip in self.logs) == False: self.logs[ip] = set()#pridat klic, ktery neexistuje
            self.logs[ip].add(row) #ulozit novy log do klice
        print("Log lines count: " + str(len(self.lines)))
        print("IP count: {}".format(self.getIpCount()))
        
    def getIpCount(self):
        return len(self.logs)
    

    ## Vezme strukturu logs[ip] = {log,...}
    # vraci strukturu  countries[cz] = {ip, ...}
    def _logs2countries(self):
        sys.stdout.write("Asking whois for countries ...: ")
        sys.stdout.flush()

        #zjistit ke kazde IP stat dle whois
        if self.multithread == True:            
            threads = []
            for ip in self.logs:
                #threads  XX snad je threadu optimalni pocet
                t = threading.Thread(target=self._push2countries, args=([ip]))
                threads.append(t)
                t.start()
            #konsolidovat informace o domenach
            for thread in threads:
                thread.join()
        else:#nepouzivat multithread
            for ip in self.logs:
                self._push2countries(ip)

        sys.stdout.write("\n")
        print("Countries count: " + str(len(self.countries)))
        #print("COUNTRIES:")
        #print(self.countries)

    
    # Prida zemi ip-adresy do self.countries
    lock = threading.RLock()
    def _push2countries(self, ip):
        country = Whois.queryCountry(ip)

        #if (country in self.countries) == False: #pridat klic, ktery neexistuje XX Myslim si, ze kdyz polozim tuto podminku 2×, poprve mimo log, budu rychlejsi.
        with SourceParser.lock: #nesmi se stat, ze dva thready pridaji tyz klic
            if (country not in self.countries): #jiny thread mezitim klic nevytvoril .
                sys.stdout.write(country + ', ')
                sys.stdout.flush() #ihned vypsat, at uzivatel vidi, ze se neco deje            
                
        self.countries[country].add(ip) #ulozit novy log do klice
        pass

    ##
    # Dohledání abusemail kontaktu pro CZ IP.
    #
    #
    # Nacte do self.mailCz[mail] set IP adres, ktere maji totozny abusemail.
    # Set adres bez abusemailu bude pod self.mailCz[""].
    # Dle nastaveni v config.ini (spare_b_flag, b_flag_threshold) hleda abusemaily pro kazdou IP zvlast,
    # nebo hleda abusemaily pro ASN. To setri whois-flag B, ktery lze pouzit cca 1500 / den.
    #
    #
    #
    # XX Pocitam (zrejme) s existenci moznosti, kdy ruzne IP z ASN spadaji do ruznych zemi.
    #    Pokud se tak nekdy stane, na ASN abuse mail se poslou pouze logy z IP, ktere nalezi do CZ.
    #    
    def _ips2mails(self, ips):
        if Config.get('spare_b_flag') == False: # nesetrit B flag (rovnou pouzivat queryMail force = True)
            # pro kazdou IP zvlast se zepta na abusemail
            for ip in ips:
                mail, bSpared = Whois.queryMail(ip, True)
                self.mailCz.mails[mail].add(ip) # pridat do ceskeho maillistu
        else:  # snazit se setrit B flag
            doAsn = False
            threshold = int(Config.get('b_flag_threshold'))
            if threshold == -1: # zjistovat abusemail pro ASN, nikoli IP (setrime)
                self._ips2mailsByAsn(ips)
            else:
                # zkusi, kolik by bylo treba -b requestu pro jednotliva IP (queryMail force = false)
                ipsRedo = set() # IP, kde je treba udelat B flag
                for ip in ips:
                    mail, bSpared = Whois.queryMail(ip, False)
                    if mail: # mail nalezen, B flag netreba
                        self.mailCz.mails[mail].add(ip)
                    if bSpared == False: #zde bychom potrebovali B flag
                        ipsRedo.add(ip) # udelat ip znovu
                        
                
                if len(ipsRedo) > threshold: # B flagu je treba vic nez je prah
                    #zepta se uzivatele, ma-li pro zbyle IP -b requesty udelat, nebo pouzit ASN.
                    print(("Bez B-flagů jsme zjistili {} abusemailů. " +
                          "Zbývá zjistit abusemail pro {} IP adres. " +
                          "(Threshold pro to, abych se zeptal na použití ASN, byl {} adres.)").format(len(self.mailCz.mails), len(ipsRedo), threshold))
                    print("Použít ASN a ušetřit tak B-flagy? [y],n: ")
                    doAsn = True if input() in ("", "Y", "y") else False

                if doAsn == False: # rozhodli jsme se nesetrit B-flag
                    for ip in ipsRedo:
                        mail = Whois.queryMailForced(ip)[0]
                        self.mailCz.mails[mail].add(ip)
                else:# rozhodli jsme setrit B-flag a pouzit ASN
                    self._ips2mailsByAsn(ipsRed)

        # stats
        if Whois.bCount > 0:
            print("Whois -B flag used: {} times".format(str(Whois.bCount)))
        count = len(self.mailCz.mails)
        orphL = len(self.mailCz.getOrphans())
        if orphL:
            count -= 1
            print("Počet CZ IP bez abusemailů: {}".format(orphL))
            # XXX PO ODESLANI: udelat neco s temamhle adresama, asi je vygenerovat jako soubor
        else:
            print("CZ whois OK!")
        print("Nalezeno celkem {} abusemailů. " .format(count))


    # zjistit abuseMail pro ASN
    def _ips2mailsByAsn(self, ips):
        if self.asnField == -1:
            # XX Pokud pouziva ASN a v CSV neni sloupecek, dohledat ASN z whoisu.
            # a naplnit self.ip2asn pole.
            print("Country CZ detected but ASN field not found.")
            print("JE TREBA IMPLEMENTOVAT. Skript ma byt schopen nacist z whoisu ASN, do ktere jednotlive IP spadaji.")
            return False # XX dohledat ASN z whoisu
        else:
            # grupovat podle ASN
            print("Country CZ detected -> ASN usage.")

        asnSet = defaultdict(set())
        for ip in ips:
            asnSet[self.ip2asn[ip]].add(ip)
        for asn in asnSet:
            self.mailCz.mails[Whois.queryMailForce(asn)].update(asnSet[asn]) # pripojit vsechny IP ASNka k jeho mailu
        print("Počet ASN: {}".format(len(asnSet)))

    #
    #Dohledání kontaktu země - z CSV souboru Config.get("contacts")
    #
    # XX Lze rozšířit i na automatické dohledávání:
    #preferenčně hledat na
    #trusted introducer - csv (certifikát)
    #hledám podle country - FR,
    #type, radši national nebo governement (jsou tam třeba i paskvily jako national-government), když je to banka, tak ignorovat
    #hledám na first.org a zkusím dohledat tam
    #http://www.first.org/members/teams
    #
    #pak hledá statické kontakty.
    #    
    def _countries2mails(self):
        file = Config.get("contacts")
        if os.path.isfile(file) == False: #soubor s kontakty
            print("Soubor s kontakty {} nenalezen. ".format(file))
            quit()
        with open(file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            abusemails = {rows[0]:rows[1] for rows in reader}

        # sparovat zeme s abusemaily
        missing = []
        countries = list(self.countries.keys())
        for country in countries: #dohledat abusemail pro country
            if country in abusemails:
                mail = abusemails[country]
                self.mailWorld.mails[mail].update(self.countries.pop(country)) # presunout set IP adres pod maillist
            else:
                missing.append(country)

        # info, co delat s chybejicimi abusemaily
        if len(missing) > 0:
            sys.stdout.write("Chybí csirtmail na {} zemí: {}\n".format(len(missing),", ".join(missing)))
            print("Doplnte csirtmaily do souboru contacts.csv a spusťte znovu whois! \n")
        else:
            sys.stdout.write("World whois OK! \n")


    ## Zapise soubory logu, rozdelenych po zemich.
    # dir - adresar bez koncoveho lomitka
    def generateFiles(self, dir, missingOnly = False):
        files = self.countries if missingOnly else self.countriesOriginal
        #files.update(self.mailCz.mails if missingOnly else self.);
        if missingOnly:
            files = self.countries.copy()
            files["cz"] = self.mailCz.getOrphans().copy() # CZ IP bez abusemailu budou jako soubor 'cz'
        else: #vsechny soubory
            files = self.countriesOriginal.copy()
            files.update(self.mailCz.mails.copy()) # CZ IP budou v souborech dle abusemailu

        dir += "/"
        count = 0
        #zapsat soubory ze zemi a abusemailu
        for file in files:
            if len(files[file]) > 0: #pokud mame pro danou zemi nejake ip
                with open(dir + file + ".tmp", 'w') as f:
                    count += 1
                    if self.header != "": #pokud mame hlavicku, pridat ji na zacatek souboru
                        f.write(self.header + "\n")
                    for ip in files[file]:
                        for log in self.logs[ip]:
                            #print(log)
                            f.write(log + "\n")


        #zapsat soubory CZ - dle jednotlivych ASN
        #for asn in self.isp:
        #    with open(dir + asn, 'w') as f:
        #        count += 1
        #        if self.header != "": #pokud mame hlavicku, pridat ji na zacatek souboru
        #            f.write(self.header + "\n")
        #        for ip in self.isp[asn]['ips']:
        #            for log in self.logs[ip]:
        #                f.write(log + "\n")

        print("Vygenerováno {} souborů.".format(count))

    #informace o souboru
    def soutInfo(self):
        print(self.info)
        #print("Soubor obsahuje {} řádek logů. ".format(len(self.logs)))

    def soutDetails(self):        
        print("\nCZ\n"+str(self.mailCz))
        print("\nWorld\n"+str(self.mailWorld))
        print("\nMissing csirmails\n"+str(self.countries) if len(self.countries) else "Všechny abroad-IP jsou OK přiřazeny")

    def __exit__(self):
        pass