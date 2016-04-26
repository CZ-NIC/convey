# Patri do projektu convey.py. Stara se o praci se zdrojovym souborem.
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

__author__ = "edvard"
__date__ = "$Feb 27, 2015 5:46:15 PM$"


class SourceParser:

    def __init__(self, sourceFile):
        repeating = False
        while True:
            #instance attributes init
            self.multithread = False #kdyz uzivatel nastavi na True, pouzije se multithread whois
            self.lines = None #lines csv souboru
            self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
            self.countries = defaultdict(set) # countries[gb] = {ip, ...} Odtud jdou IP dle whois do struktur MailList
            self.countriesMissing = defaultdict(set) # takove prvky self.countries, ktere se nepodarilo zaradit dle whois do MailList

            self.ipField = 0 #pozice sloupce s IP adresou
            self.asnField = -1 #pozice sloupce s AS number
            self.hostField = -1 # pozice sloupce s URL, ktere se prelozi na IP
            self.delimiter = None  #CSV dialect
            #self.whoisBCount = 0
            self.info = "" # nasbirana metadata o CSV souboru
            self.header = "" # pokud ma CSV souboru header, je zde

            # ASN atributy - mozna se prepracuji XX
            self.isp = {} # isp["AS1025"] = {mail, ips:set() }
            self.ip2asn = dict() # ip2asn[ip] = asn

            # atributy OTRS, ktere se k CSV vazou
            self.ticketid = False
            self.ticketnum = False
            self.cookie = False
            self.token = False

            self.ticketid = Config.get("ticketid") # XX MISC vytvorit si vlastni ticket! Treba si vytvor nejaky novy testovaci tiket a potom ho presun do fronty MISC, nebo to klidne zkousej na kterymkoliv tiketu ve fronte MISC ;-)
            self.ticketnum = Config.get("ticketnum")

            self.attachmentName = "part-" + ntpath.basename(sourceFile)

            #nacist CSV
            self._loadCsv(sourceFile, repeating)

            sys.stdout.write("Bylo všechno zadáno v pořádku? [y]/n ")
            if input() == "n":
                repeating = True
                continue #zopakovat
            else:
                self.mailCz = False #deklarace dopisu pro cz
                self.mailWorld = False #deklarace dopisu pro svet
                self.launchWhois()
                break

    def launchWhois(self): #spusti dlouhotrvajici processing souboru
        self._lines2logs()
        self._logs2countries()

        self.mailCz = MailList("mail_cz", Config.get("mail_template_cz")) # dopis pro CZ
        self.mailWorld = MailList("mail_world", Config.get("mail_template_world")) # dopis pro svet

        if 'cz' in self.countries: #CZ -> abuse maily
            self._buildListCz(self.countries.pop("cz"))
            self.applyCzCcList() # doplnujici Cc kontakty na cz abusemaily

        self.buildListWorld() # World -> kontakty na maily CSIRTu

    def _addInfo(self, txt):
        self.info += txt + "\n"
        print(txt)

    ## Parsuje CSV file na policka a uhadne pole IP.
    def _loadCsv(self, sourceFile, repeating=False):
        #pripravit csv k analyze
        self._addInfo("Source file: " + sourceFile)
        csvfile = open(sourceFile, 'r')
        self.lines = csvfile.read().splitlines()
        sample = ""
        for i, row in enumerate(self.lines):
            if(i == 0):
                firstLine = row
            sample += row + "\n"
            if(i == 8): #XX snifferu na zjisteni dialektu nestaci 3 linky, ale 7+ (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), nevim proc
                break

        #uhadnout delimiter
        self.delimiter = csv.Sniffer().sniff(sample).delimiter
        print("Sample rows:")
        print(sample)
        sys.stdout.write("Is character '{}' delimiter? [y]/n ".format(self.delimiter))
        if input() not in ("Y", "y", ""):
            sys.stdout.write("What is delimiter: ")
            self.delimiter = input()
            #sys.stdout.write("Correct? [y]/n ")
        else:
            self._addInfo("Delimiter: {}".format(self.delimiter))
        csvfile.seek(0)


        #vyjmout z logu hlavicku
        hasHeader = csv.Sniffer().has_header(sample)

        if hasHeader:
            sys.stdout.write("Header nalezen - ok? [y]/n: ") # Header present
            if input().lower() not in ("y", ""):
                hasHeader = False
        else:
            sys.stdout.write("Header nenalezen a nepoužije se - ok? [y]/n: ") # Header not present
            if input().lower() not in ("y", ""):
                hasHeader = True

        if hasHeader == True:
            self.header = firstLine
            self._addInfo("Header: použije se") # Header: used
            self.lines.pop(0)
        else:
            self.header = ""
            self._addInfo("Header: nepoužije se") # Header: not used

        fields = firstLine.split(self.delimiter)

        # sloupec IP
        def _findIpCol():
            found = False
            if repeating == False: # dialog jede poprve, zkusit autodetekci
                ipNames = ["ip", "sourceipaddress", "ipaddress", "source"] #mozne nazvy ip sloupcu - bez mezer
                for fieldname in fields:
                    field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
                    if hasHeader == True: #soubor ma hlavicku, zjistovat v ni
                        if field in ipNames: #tohle je mozna nazev ip sloupce
                            self._addInfo("IP field column: " + fieldname)
                            found = True
                            break
                    else: #csv nema hlavicku -> pgrep IP, jinak se zeptat uzivatele na cislo sloupce
                        if Whois.checkIp(field): #pokud neni IP, vyhodi chybu. Mozna nezvladne vsechny mozne zkracene verze zapisu IP.
                            #self._addInfo("IP found: " + fieldname)
                            found = True
                            break #toto je ip, konec hledani
                    self.ipField += 1

                if found == True:
                    sys.stdout.write("Is IP field column: {}? [y]/n ".format(fieldname))
                    if input().lower() in ("y", ""):
                        self._addInfo("IP column: " + fields[self.ipField])
                    else:
                        found = False

            if found == False:#IP jsme nenalezli, dat uzivateli na vyber
                i = 1
                print("\nWhat is IP/HOST column:")
                for fieldname in fields:#vypsat sloupce
                    print(str(i) + ". " + fieldname)
                    i += 1
                #print("0. Delimiter is wrong!") to bych musel predelat tuhle velkou do jednotlivych submetod

                try: #zeptat se uzivatele na cislo sloupce
                    option = int(input('IP column: '))
                    self.ipField = option -1

                    if Whois.checkIp(self.lines[0].split(self.delimiter)[self.ipField]):# zjistit, zda je to IP column, nebo column s domenami
                        self._addInfo("IP column:" + fields[self.ipField])
                    else:
                        self._addInfo("HOST column:" + fields[self.ipField])
                        print("Domény v tomto sloupci budou přeloženy na IP.")
                        self.hostField, self.ipField = self.ipField, -1

                        if hasHeader == True: # pridame sloupec s nazvem HOST_IP
                            self.header += self.delimiter + "HOST_IP"

                except ValueError:
                    print("This is not a number")
                    raise


            #sloupec AS
        def _findAsnCol():
            found = False
            print("debug 222")
            if repeating == False: # dialog jede poprve, zkusit autodetekci
                asNames = ["as", "asn", "asnumber"] #mozne nazvy ip sloupcu - bez mezer
                self.asnField = 0
                for fieldname in fields:
                    field = fieldname.replace(" ", "").lower()
                    if hasHeader == True: #soubor ma hlavicku, zjistovat v ni
                        if field in asNames: #tohle je mozna nazev ip sloupce
                            found = True
                            break
                    else: #csv nema hlavicku -> pgrep IP, jinak se zeptat uzivatele na cislo sloupce
                        if re.search('AS\d+', field) != None: #X 'AS1234'
                            found = True
                            break
                    self.asnField += 1
                if found == True: # mozna to naslo blby nazev
                    sys.stdout.write("Is ASN field column: {}? [y]/n ".format(fieldname))
                    if input().lower() in ("y", ""):
                        self._addInfo("ASN column:" + fields[self.asnField])
                    else:
                        found = False

            if found == False:#AS jsme nenalezli, dat uzivateli na vyber
                i = 1
                print("\nWhat is ASN column:")
                print("[0]. no ASN column")
                for fieldname in fields:#vypsat sloupce
                    print(str(i) + ". " + fieldname)
                    i += 1
                try: #zeptat se uzivatele na cislo sloupce
                    self.asnField = int(input('ASN column: ')) -1
                except ValueError:
                    #print("This is not a number.")
                    self.asnField = -1 # -> ASN not used
                if self.asnField == -1:
                    self._addInfo("ASN will not be used.")
                else:
                    self._addInfo("ASN column: " + fields[self.asnField])

        _findIpCol()
        _findAsnCol()
        csvfile.close()

    ## Kazdou radku logu pripoji k IP
    # logs[IP] = {log, ...}
    def _lines2logs(self):
        self.logs = defaultdict(set) # logs[145.1.2.3] = {logline, ...}
        extend = 0
        for row in self.lines:#do klice
            if(row.strip() == ""):
                continue
            try:
                fields = row.strip().split(self.delimiter)
                if self.hostField != -1:#pokud CSV obsahuje sloupec s URL, ktery teprve mame prelozit do sloupce s IP
                    ips = Whois.url2ip(fields[self.hostField])
                else:
                    ips = [fields[self.ipField].replace(" ", "")] #klic bereme ze sloupce ip

                if len(ips) > 1:
                    extend = len(ips) -1 # kolik novych radku do logs pribyva
                    print("Host {} má {} ip adres: {}".format(fields[self.hostField], len(ips), ips))

                for ip in ips:
                    log = row
                    if self.hostField != -1:
                        log += self.delimiter + ip # do posledniho sloupce prida nove zjistenou ip

                    if self.asnField != -1:
                        str = fields[self.asnField].replace(" ", "")
                        if str[0:2] != "AS":
                            str = "AS" + str
                        self.ip2asn[ip] = str #klic je ip

                    self.logs[ip].add(log) #ulozit novy log do klice
            except:
                print("ROW fault" + row)
                print("Tohle by se nemělo stát. Buď je špatně CSV soubor, nebo řekněte Edvardovi, ať to opraví.")
                raise



        print("IP count: {}".format(self.getIpCount()))
        print("Log lines count: {}".format(len(self.lines)))
        if extend > 0:
            print("+ dalších {} řádků, protože některé domény měly více IP".format(extend))

    def getIpCount(self):
        return len(self.logs)


    ## Vezme strukturu logs[ip] = {log,...}
    # vraci strukturu  countries[cz] = {ip, ...}
    def _logs2countries(self):
        self.countries = defaultdict(set)
        #self.countriesOriginal = defaultdict(set)
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
    def _buildListCz(self, ips):
        self.mailCz.resetMails()
        print("Querying whois for mails.")
        if Config.getboolean('spare_b_flag') == False: # nesetrit B flag (rovnou pouzivat queryMail force = True)
            # pro kazdou IP zvlast se zepta na abusemail
            for ip in ips:
                mail, bSpared = Whois.queryMail(ip, True)
                self.mailCz.mails[mail].add(ip) # pridat do ceskeho maillistu
        else:  # snazit se setrit B flag
            doAsn = False
            threshold = int(Config.get('b_flag_threshold'))
            if threshold == -1: # zjistovat abusemail pro ASN, nikoli IP (setrime)
                self._buildListCzByAsn(ips)
            else:
                # zkusi, kolik by bylo treba -b requestu pro jednotliva IP (queryMail force = false)
                ipsRedo = set() # IP, kde je treba udelat B flag
                for ip in ips:
                    mail, bSpared = Whois.queryMail(ip, False)
                    if mail and mail != "unknown": # mail nalezen, B flag netreba
                        self.mailCz.mails[mail].add(ip)
                    if bSpared == False: #zde bychom potrebovali B flag
                        ipsRedo.add(ip) # udelat ip znovu


                if len(ipsRedo) > threshold: # B flagu je treba vic nez je prah
                    #zepta se uzivatele, ma-li pro zbyle IP -b requesty udelat, nebo pouzit ASN.
                    print(("Bez B-flagů jsme zjistili {} abusemailů. " +
                          "Zbývá zjistit abusemail pro {} IP adres. " +
                          "(Threshold pro to, abych se zeptal na použití ASN, byl {} adres.)").format(len(self.mailCz.mails), len(ipsRedo), threshold))
                    print("Použít ASN a ušetřit tak B-flagy? y,[n]: ")
                    doAsn = False if input().lower() in ("", "n") else True

                if doAsn == False: # rozhodli jsme se nesetrit B-flag
                    for ip in ipsRedo:
                        mail = Whois.queryMailForced(ip)[0]
                        #print("x pridavam mail")# xx smaz
                        #print(mail)
                        self.mailCz.mails[mail].add(ip)
                else:# rozhodli jsme setrit B-flag a pouzit ASN
                    self._buildListCzByAsn(ipsRedo)


        # stats
        if Whois.bCount > 0:
            print("Whois -B flag used: {} times".format(str(Whois.bCount)))
        count = len(self.mailCz.mails)
        orphL = len(self.mailCz.getOrphans())
        if orphL:
            count -= 1
            print("Počet CZ IP bez abusemailů: {}".format(orphL))
        else:
            print("CZ whois OK!")
        print("Nalezeno celkem {} abusemailů. " .format(count))

    ##
    # pridat maily z vlastniho listu do cc-kopie
    def applyCzCcList(self):
        count = 0
        file = Config.get("contacts_cz")
        if os.path.isfile(file) == False: #soubor s kontakty
            print("(Soubor s cz kontakty {} nenalezen.) ".format(file))
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
                print("Z listu cz kontaktů ({}) přidáno Cc do {} mailů.".format(len(abusemails), count))
            else:
                print("Soubor s cz kontakty nalezen, nepáruje s nimi však žádný, ok.")


    # zjistit abuseMail pro ASN
    def _buildListCzByAsn(self, ips):
        if self.asnField == -1:
            # XX Pokud pouziva ASN a v CSV neni sloupecek, dohledat ASN z whoisu.
            # a naplnit self.ip2asn pole.
            #print("Country CZ detected but ASN field not found.")
            #print("JE TREBA IMPLEMENTOVAT. Skript ma byt schopen nacist z whoisu ASN, do ktere jednotlive IP spadaji.")
            #print("Nyni dejte pregenerovat whois informace.")
            print("Looking up AS numbers from whois")
            for ip in ips:
                self.ip2asn[ip] = Whois.getAsn(ip)
            #return False # XX dohledat ASN z whoisu
        else:
            # grupovat podle ASN
            print("Country CZ detected -> ASN usage.")


        # XXX mam podezreni, ze ASN vubec nefunguje, vraci sama unknown.
        asnSet = defaultdict(set)
        for ip in ips:
            asnSet[self.ip2asn[ip]].add(ip)
        for asn in asnSet:
            mail, forced = Whois.queryMailForced(asn) # XXX proc rovnou forced?
            self.mailCz.mails[mail].update(asnSet[asn]) # pripojit vsechny IP ASNka k jeho mailu
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
    def buildListWorld(self):
        self.mailWorld.resetMails()
        file = Config.get("contacts_world")
        if os.path.isfile(file) == False: #soubor s kontakty
            print("Soubor s world kontakty {} nenalezen. ".format(file))
            return False
        with open(file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            abusemails = {rows[0]:rows[1] for rows in reader}

        # sparovat zeme s abusemaily
        missing = []
        self.countriesMissing = self.countries.copy() #list(self.countries.keys())
        for country in list(self.countries.keys()): #dohledat abusemail pro country
            if country in abusemails:
                mail = abusemails[country]
                self.mailWorld.mails[mail].update(self.countriesMissing.pop(country)) # presunout set IP adres pod maillist
            else:
                missing.append(country)

        # info, co delat s chybejicimi abusemaily
        if len(missing) > 0:
            sys.stdout.write("Chybí csirtmail na {} zemí: {}\n".format(len(missing), ", ".join(missing)))
            print("Doplňte csirtmaily do souboru s kontakty zemí (viz config.ini) a spusťte znovu whois! \n")
        else:
            sys.stdout.write("World whois OK! \n")
        return True


    def missingFilesInfo(self):
        return "({} souborů, {} world a {} cz kontaktů)".format(
                                                                len(self.countriesMissing) + (1 if len(self.mailCz.getOrphans()) else 0),
                                                                len(self.countriesMissing),
                                                                len(self.mailCz.getOrphans()))


    ## Zapise soubory logu, rozdelenych po zemich.
    # dir - adresar bez koncoveho lomitka
    def generateFiles(self, dir, missingOnly=False):
        if missingOnly:
            extension = "-missing.tmp"
            files = self.countriesMissing.copy()
            files["cz_unknown"] = self.mailCz.getOrphans().copy() # CZ IP bez abusemailu budou jako soubor 'cz'
        else: #vsechny soubory
            extension = ".tmp"
            files = self.countries.copy() # X countriesOriginal
            files.update(self.mailCz.mails.copy()) # CZ IP budou v souborech dle abusemailu

        dir += "/"
        count = 0
        #zapsat soubory ze zemi a abusemailu
        for file in files:
            if len(files[file]) > 0: #pokud mame pro danou zemi nejake ip
                with open(dir + file + extension, 'w') as f:
                    count += 1
                    f.write(self.ips2logfile(files[file]))

        print("Generated {} files to directory {} .".format(count, dir))

    def ips2logfile(self, ips):
        result = []
        if self.header != "": #pokud mame hlavicku, pridat ji na zacatek souboru
            result.append(self.header)
        for ip in ips:
            for log in self.logs[ip]:
                #print(log)
                result.append(log)
        return "\n".join(result)



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
        print("**************************")
        print("Stav interních proměnných:")
        print("\nCZ\n" + str(self.mailCz))
        print("\nWorld\n" + str(self.mailWorld))
        print("\nMissing world mails\n" + str(self.countriesMissing) if len(self.countriesMissing) else "Všechny world IP jsou OK přiřazeny")
        #print("\nStatistický přehled:")print(self.getStatsPhrase())

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
            res = "Celkem {} unikátních IP".format(ipsUnique)
        else:
            res = "žádná IP adresa"
        if ipsWorldFound or countriesFound:
            res += "; informace zaslána do {} zemí".format(countriesFound) \
            + " ({} unikátních IP adres)".format(ipsWorldFound)
        if ipsWorldMissing or countriesMissing:
            res += ", do {} zemí neposláno, nemají národní/vládní CSIRT".format(countriesMissing) \
            + " ({} unikátních IP adres)".format(ipsWorldMissing)
        if ipsCzFound or ispCzFound:
            res += "; {} unikátních IP adres v ČR".format(ipsCzFound) \
            + " distribuováno pro {} ISP".format(ispCzFound)
        if ipsCzMissing:
            res += " (pro {} unikátních IP adres v ČR jsme ISP nenalezli)".format(ipsCzMissing)

        res += "."

        #if(generate == True):
            #file = Config.get("generate_statistics_to_file")
            #if file != "False":
                #with open("statistics.txt","a") as f:
                    #return f.write(csv.getStatsPhrase(generate = True))

        return res

    def __exit__(self):
        pass
