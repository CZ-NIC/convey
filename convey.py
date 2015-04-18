#! /usr/bin/python3
# -*- coding: utf-8 -*-
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
from lib.mailSender import MailSender
import os.path
import sys
__shortdoc__ = """OTRS Convey -> tlumočník pro OTRS"""
__doc__ = """Tlumočník pro OTRS.
 Spouští se příkazem: convey.py [filename], přičemž [filename] je cesta ke zdrojovému souboru logů ve formátu CSV.
 Pokud [filename] není zadán, skript se na něj zeptá.
 Skript se jej pokusí parsovat a zjistit sloupec s IP a ASN.

 Místo sloupce IP lze užít sloupec s URL. V takovém případě skript z každé URL vytáhne doménu, přeloží ji na IP a přidá do CSV sloupec 'HOST_IP'. Pokud nalezne více IP, řádek s URL zduplikuje.

 Je třeba mít knihovnu tkinter, apt-get install python3-tkinter
 -h, --help Nápověda
"""
__author__ = "edvard"
__date__ = "$Feb 26, 2015 8:13:25 PM$"


#def __serialize(self):
#        with open( "pickle3.tmp", "wb" ) as output:
#            #data = (self.lines, self.logs, self.countries, self.ipMapping, self.isp, self.ipField, self.asnField, self.delimiter, self.whoisBCount)
#            pickle.dump(self,output,-1)

#def __deserialize(self):
    #       obj = pickle.load( open( "pickle3.tmp", "rb" ) )
        #      (self.lines, self.logs, self.countries, self.ipMapping, self.isp, self.ipField, self.asnField, self.delimiter, self.whoisBCount) = obj


if __name__ == "__main__":    
    #module findSource - ziskat zdrojovy soubor. Bud parametrem, nebo vyhledat ve strukture jeste nepouzity.
    #module parseSource - vypsat prvni dva radky, overit, zda program zdrojovemu CSV rozumi

    #DEBUG:
    #file = "lab/zdroj.csv"
    #csv = SourceWrapper(file)

    print(__shortdoc__)

    #flagy prikazove radky - kontroler behu programu
    if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    file = SourcePicker() # cesta ke zdrojovemu souboru
    wrapper = SourceWrapper(file) # "lab/zdroj.csv"
    csv = wrapper.csv

    #menu
    while True:
        print("\n Stats - IP: {}, CZ IP abusemailů: {}, world IP csirtmailů: {} ".format(
              csv.getIpCount(),
              len(csv.mailCz.mails),
              len(csv.mailWorld.mails)
              ))
        if len(csv.mailCz.getOrphans()):
            print("Nezdařilo se dohledat abusemaily pro {} CZ IP.".format(len(csv.mailCz.getOrphans())))
        if len(csv.countries):
            print("Nezdařilo se dohledat csirtmaily pro {} zemí.".format(len(csv.countries)))

        
        print("\n Hlavní menu:")
        print("1 - Zaslat přes OTRS")
        print("2 - Generovat soubory s IP bez kontaktu ({} souborů)".format(len(csv.countries)))
        print("--")
        print("3 - Seznam abusemailů a počet IP")
        print("4 - Změnit text mailu")
        print("5 - Generovat všechny soubory ({} souborů)".format(len(csv.countriesOriginal)))
        print("6 - Zpracovat znovu")
        print("7 - Zpracovat znovu jen whois")


XX

X* kdyz to vrati pet zemi, vrati prvni
kdyz to vrati a zacne "EU", zeptat se celosvětově whois (bez ripedb2)

X* Místo sloupce IP  může existovat sloupec s doménami.
Ty se v csv natvrdo přiloží do IP a IP se připojí jako poslední column.

XAutomaticka detekce ASN: zeptat se vzdy, co je ASN sloupec, byt s detekci.

honeypot, ramney, nbu

Kdyz jsme testovali Nbu/zdroj:
Ctyri maily na 1 radce tam jsou. To neprojde!!
Když budou takhle ctyri, poslat jim to na ctyri soucasne. -> pridat hlavicku Cc
Flaggovat, ktere maily se poslaly.

Pokud domena toho mailu je shona s certim seznamem (napri cdt.cz), pridat do cc certi mail.
Kdyz to pujde do O2 -> at to jde certim mailum.
Soubor certs.csv, sloupce domain,cc

Testcase:
Spatny cache. Vygenerovali jsme Whois pro IP. Pak jsme zminili jiny IP sloupec. Ale tam zustaly tam viset predchozi IP. (pripad nbu? - snad jsem opravil)

        print("x - Konec")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        #option = "7" #XX
        print("******")
        if option == "x":
            wrapper.save() # preulozit cache soubor
            break
        elif option == "6":
            wrapper.clear()
            continue
        elif option == "7":
            csv.launchWhois()
            continue        
        elif option == "3":
            csv.soutDetails()
            continue
        elif option == "2":
            csv.generateFiles(os.path.dirname(file), True)
            continue
        elif option == "5":
            csv.generateFiles(os.path.dirname(file))
            continue
        elif option == "4":
            csv.mailCz.guiEdit()
            csv.mailWorld.guiEdit()
            continue
        elif option == "1":
            print("XX") #XX
            csv.ticketid = "7056" # MISC vytvorit si vlastni ticket! Treba si vytvor nejaky novy testovaci tiket a potom ho presun do fronty MISC, nebo to klidne zkousej na kterymkoliv tiketu ve fronte MISC ;-)
            csv.ticketnum = "20100224213000171"
            csv.cookie = "228bdc286be05e9b37e3fd31a2bebb3e7b0"
            csv.token = "4d64db6c6aee207c5c7853778ff57f27"
            MailSender.assureTokens(csv)
            sys.stdout.write("Poslat CZ abusemailům:")
            if MailSender.sendList(csv.mailCz, csv): # poslat ceske maily
                sys.stdout.write("Poslat světovým csirtmailům:")
                if MailSender.sendList(csv.mailWorld, csv): # poslat svetove maily
                    if len(csv.countries) > 0:
                        print("Nyní můžete vygenerovat soubory bez kontaktu.")
            else:
                print("Nezdařilo se zaslat všechny české maily. Nebudu se pokoušet o zaslání světových mailů.")
            continue
        else:
            continue #zopakovat volbu

    
    

    #csv.generateFiles()
    #csv.detectMails()

    print("Finished.")
    
    #module extractIP - CSV -> IPs -> sort, uniq
    #module extractAS - CSV -> AS -> sort, uniq
    
    #module detectCountry - s/bez logu (adekvatnich radku z CSV) (skript_zeme, skript_zeme_s_logy) - IPs -> countries (-> + CSV )
    # Tento skript projde cely soubor IP s IP adresama a vytvori soubory ktere jsou pojmenovane podle country codu zemi a do techto souboru pripise vsechny IP adresy pro danou zemi
    # Tento skript projde cely soubor IP s IP adresama a vytvori soubory ktere jsou pojmenovane podle country codu zemi a do techto souboru pripise vsechny IP adresy a logy ze souboru zdroj pro danou zemi.
    # obcas je zeme: EU -> prostě to v RIPE databázi neni. Pro tyhle případy se bude muset zeptat ARINu, ale nevím jak.
    
    
    #module detectEmails (skript_email_v3_s_logy_rozrzeni_podle_mailu) IP/AS, fixni kontakty -> radky logu, fixni+whois email kontakt
    #
    #
    #
    #Co dale skript nyni? Skript projde cely soubor IP s IP adresama a vypise IP adresu a e-maily do souboru contacts
    # skript_email_v3: contacts >> IP: 223.94.12.232\nCONTACTS: abuse@chinamobile.com\n
    # s_logy: contacts >> IP: 2015-02-15 01:44:58.059 0.000 TCP 223.80.49.154 22370 91.239.200.165 80 0xc2 0 1 40 1\nCONTACTS: abuse@chinamobile.com\n
    # rozvrzeni: abuse@chinamobile.com >> 2015-02-15 01:44:58.059 0.000 TCP 223.80.49.154 22370 91.239.200.165 80 0xc2 0 1 40 1\n
    # 
    #
    # skript_prejmenovani_souboru_2
    # soubor maily (ten nevim, kde se vzal):
    #  Vytvori soubor contacts
    #     CONTACTS: email
    #     FILENAME: file
    # Prejmenuje ripe@blue4.cz na file=blue4
    # auscert-send.6.py pak odesle tyto soubory jako prilohu
    
    #module sendEmail (auscert-send.6.py) Email, radky logu, message body, otrs access -> send email
    # na maily odesle prilohu, sestavajici z logu
    