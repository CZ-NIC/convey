# Patri do projektu convey.py. Stara se o praci se zdrojovym souborem.
import csv
import ipaddress
import pickle
from pprint import pprint
from subprocess import PIPE
from subprocess import Popen
import sys
import threading
import lib.whois
#import dill

__author__ = "edvard"
__date__ = "$Feb 27, 2015 5:46:15 PM$"


class SourceParser:

    def __init__(self, sourceFile):
        while True:
            #instance attributes init
            self.multithread = False #kdyz uzivatel nastavi na True, pouzije se multithread whois
            self.lines = None #lines csv souboru
            self.logs = {} # logs[145.1.2.3] = {logline, ...}
            self.countries = dict() # countries[gb] = {ip, ...}
            
            self.ipField = 0 #pozice sloupce s IP adresou
            self.asnField = 0 #pozice sloupce s AS number
            self.delimiter = None  #CSV dialect
            self.whoisBCount = 0 #pocet adres, u nichz jsme se whoisu ptali s limitovanym flagem B
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
                self.launch()
                break

    def launch(self): #spusti dlouhotrvajici processing souboru
        self._lines2logs()
        self._logs2countries()

        if 'cz' in self.countries: #CZ -> abuse maily
            if self.asnField == -1:
                print("Country CZ detected but ASN field not found.")
                return False
            else:
                print("Country CZ detected -> ASN usage.")

            self._ips2mails(self.countries.pop("cz"))

        if self.whoisBCount > 0:
            print("Whois -B flag used:" + str(self.whoisBCount) + " times")

        



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
        self._addInfo("Delimiter: " + self.delimiter)
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
        ipNames = ["ip", "sourceipaddress", "ipaddress","source"] #mozne nazvy ip sloupcu - bez mezer
        for fieldname in fields:
            field = fieldname.replace(" ", "").replace("'","").replace('"',"").lower()
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
            try: #zeptat se uzivatele na cislo sloupce
                self.ipField = int(input('IP column: ')) -1
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

            if (ip in self.logs) == False: #pridat klic, ktery neexistuje
                self.logs[ip] = set()
            self.logs[ip].add(row) #ulozit novy log do klice
        print("Log lines count: " + str(len(self.lines)))
        print("IP count: " + str(len(self.logs)))        
        

    

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
    def _push2countries(self, ip):
        country = Whois.queryCountry(ip)

        if (country in self.countries) == False: #pridat klic, ktery neexistuje
            with threading.RLock(): #nesmi se stat, ze dva thready pridaji tyz klic
                if (country in self.countries) == False: #jiny thread mezitim klic nevytvoril . XX Myslim si, ze kdyz polozim tuto podminku 2×, poprve mimo log, budu rychlejsi.
                    self.countries[country] = set()
                    sys.stdout.write(country + ', ')
                    sys.stdout.flush() #ihned vypsat, at uzivatel vidi, ze se neco deje
        self.countries[country].add(ip) #ulozit novy log do klice
        pass



    ##
    # Zjistit zeme jednotlivych IP.
    # Pokud je zeme CR, zjisti AS.
    #
    # XX Pocitam s existenci moznosti, kdy ruzne IP z ASN spadaji do ruznych zemi.
    #    Pokud se tak nekdy stane, na ASN abuse mail se poslou pouze logy z IP, ktere nalezi do CZ.
    # XXXXX
    Nauc se struktury
    self.countries[country] = set()
    Nelze udelat pekne objektem?
    http://127.0.0.1:8888/e1d530e0-21e4-404d-b233-1811fd9ac363

    class countries(dict):
    def __getattr__(self, attr):
        if(self.get(attr) == None)
            self.attr = set()
         return self.get(attr)
        #Jestli tohle bude fungovat, nelze zkratit na??
        attr = self.get(attr)
        if attr = None:
            attr = set()
        return attr


    Dohledání kontaktu v CZ
    cz -> ip abusemaily.
    Nyní se používá jen ASN.
    Config.ini/spare_b_flag = True - zkusi, kolik by bylo treba -b requestu pro jednotliva IP (whois.queryMail force = false) a kdyz by jich bylo vice nez
    config/threshold, zepta se uzivatele, ma-li -b requesty udelat, nebo pouzit ASN.
    (config/threshold = -1 ==> vzdy pouzit ASN.)
    Pokud pouziva ASN a v CSV neni sloupecek, dohledat ASN z whoisu.
    Config.ini/spare_b_flag = False - rovnou pouzivat (queryMail force = True)


    Pro ukladani mailu nepouziva hnusny objekt
    self.isp[asn]["ips"]
    Asi bude stacit struktura: mails[email] = {ip, ...}

    Ale mohl bych to vytunit nejakou novou strukturu, zkus iPython notebook http://127.0.0.1:8888/e1d530e0-21e4-404d-b233-1811fd9ac363
    mails[email].world.ips
    mails[email].world.body
    mails[email].world.subject
    mails[email].home.

    NEBO
    contacts.world.mails[mail] = {ip, ...}
    contacts.world.body
    contacts.world.subject
    contacts.home.


Dohledání kontaktu země - metoda countries2mails

preferenčně hledat na
trusted introducer - csv (certifikát)
hledám podle country - FR,
type, radši national nebo governement (jsou tam třeba i paskvily jako national-government), když je to banka, tak ignorovat
hledám na first.org a zkusím dohledat tam
http://www.first.org/members/teams

pak hledá statické kontakty.

Posilani
Nacist text mailu pro CZ.
    Nacist text mailu pro svet. (Přidejte soubor s textem mailu.)

    def _ips2mails(self, ips):
            # grupovat podle ASN
            for ip in ips:
                asn = self.ip2asn[ip]
                if (asn in self.isp) == False:
                    self.isp[asn] = {"mail": None, "ips": set()}
                self.isp[asn]["ips"].add(ip)

            # zjistit abuseMail pro ASN
            for asn in self.isp:
                self.isp[asn]["mail"], spared = Whois.queryMail(asn, force = True)
                if spared == False: #neusetrili jsme flagB
                    self.whoisBCount += 1


    ## Zapise soubory logu, rozdelenych po zemich.
    # dir - adresar bez koncoveho lomitka
    def generateFiles(self, dir):
        dir += "/"
        count = 0
        #zapsat soubory zemi
        for country in self.countries:
            with open(dir + country, 'w') as f:
                count += 1
                if self.header != "": #pokud mame hlavicku, pridat ji na zacatek souboru
                    f.write(self.header + "\n")
                for ip in self.countries[country]:
                    for log in self.logs[ip]:
                        #print(log)
                        f.write(log + "\n")

        #zapsat soubory CZ - dle jednotlivych ASN
        for asn in self.isp:
            with open(dir + asn, 'w') as f:
                count += 1
                if self.header != "": #pokud mame hlavicku, pridat ji na zacatek souboru
                    f.write(self.header + "\n")
                for ip in self.isp[asn]['ips']:
                    for log in self.logs[ip]:
                        f.write(log + "\n")

        print("Vygenerováno {} souborů.".format(count))

    ## Vraci maily. XX
    def detectMails(self):
        pass

    #informace o souboru
    def soutInfo(self):
        print(self.info)
        #print("Soubor obsahuje {} řádek logů. ".format(len(self.logs)))

    def __exit__(self):
        pass