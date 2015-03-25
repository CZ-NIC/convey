#! /usr/bin/python3
# -*- coding: utf-8 -*-
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
import os.path
import sys
import configparser


__shortdoc__= """OTRS Convey -> tlumočník pro OTRS"""
__doc__ = """Tlumočník pro OTRS.
 Spouští se příkazem: convey.py [filename], přičemž [filename] je cesta ke zdrojovému souboru logů ve formátu CSV.
 Pokud [filename] není zadán, skript se na něj zeptá.
 Skript se jej pokusí parsovat a zjistit sloupec s IP a ASN.

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
    if set(["-h", "--help","-?","?","/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    file = SourcePicker() # cesta ke zdrojovemu souboru
    wrap = SourceWrapper(file) # "lab/zdroj.csv"

    #menu
    while True:
        print("\n Hlavní menu:")
        print("1 - Zpracovat znovu")
        print("2 - Generovat soubory")
        print("x - Konec")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        if option == "x":
            break
        elif option == "1":
            wrap.clear()
            continue
        elif option == "2":
            wrap.csv.generateFiles(os.path.dirname(file))
            continue
        else:
            continue #zopakovat volbu


    #print(csv.isp)
    #print(csv.countries)

    #print(csv.generateFiles())


    # XXXX opatrit kontakty pro countries
    # spojit s OTRS pro odeslani. Zjisim, ktery skript pouzivat soubory prikaz a body a prepisu auscert do pythonu3


    

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
    