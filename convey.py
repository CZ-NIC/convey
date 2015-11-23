#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
    import traceback
    import os.path
    import sys, getopt
    from lib.sourcePicker import SourcePicker
    from lib.sourceWrapper import SourceWrapper
    from lib.mailSender import MailSender
    from lib.config import Config
except ImportError:
    traceback.print_exc()
    print("\nZkuste nainstalovat knihovny spuštěním přiloženého skriptu install.sh")
    quit()
__shortdoc__ = """OTRS Convey -> tlumočník pro OTRS"""
__doc__ = """Tlumočník pro OTRS.
 Syntaxe:
    ./convey.py [--id <OTRS ticket id>] [--num <OTRS ticket number>] [--cookie <OTRS cookie>] [--token <OTRS token>] [<filename>]
 Parametr [filename] je cesta ke zdrojovému souboru logů ve formátu CSV.
 Pokud [filename] není zadán, skript se na něj zeptá.
 Skript se jej pokusí parsovat a zjistit sloupec s IP a ASN.

 Místo sloupce IP lze užít sloupec s URL. V takovém případě skript z každé URL vytáhne doménu, přeloží ji na IP a přidá do CSV sloupec 'HOST_IP'. Pokud nalezne více IP, řádek s URL zduplikuje.

 Potřebné knihovny se nainstalují skriptem install.sh .
 -h, --help Nápověda
"""
__author__ = "edvard"
__date__ = "$Feb 26, 2015 8:13:25 PM$"


if __name__ == "__main__":    
    print(__shortdoc__)

    #flagy prikazove radky - kontroler behu programu; parametry --id, --ticket, --cookie --token --attachmentName
    if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    file = SourcePicker() # cesta ke zdrojovemu souboru
    wrapper = SourceWrapper(file) # "lab/zdroj.csv"
    csv = wrapper.csv

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["","id=", "num=","cookie=","token="])
    except getopt.GetoptError:
        print(__doc__)        
        sys.exit(2)
    for opt, arg in opts:
        #if opt in ('-h','-?',"--help"):
        #    print(__doc__)
        #    sys.exit()
        if opt in ("--id"):
            #Config.setTemp("ticketid",arg)
            csv.ticketid = arg
            print("Ticket id: {}".format(arg))            
        elif opt in ("--num"):
            csv.ticketnum = arg
            #Config.setTemp("ticketnum",arg)
            print("Ticket num: {}".format(arg))
        elif opt in ("--cookie"):
            csv.cookie = arg
            #Config.setTemp("cookie",arg)
            print("OTRS cookie: {}".format(arg))
        elif opt in ("--token"):
            csv.token = arg
            #Config.setTemp("token",arg)
            print("OTRS token: {}".format(arg))    
    

    #menu
    while True:        
        #print("\n Stats - IP: {}, CZ (abuse)mailů: {}, world (csirt)mailů: {} ".format(
            #csv.getIpCount(),
            #len(csv.mailCz.mails),
            #len(csv.mailWorld.mails)
            #))
        if Config.get('debug') == "True":
            print("\n*** DEBUG MOD - maily budou zaslany na mail {} ***\n (Pro zrušení debug módu nastavte debug = False v config.ini.)".format(Config.get('debugMail')))
        stat = csv.getStatsPhrase()
        print("Statistický přehled: " + stat)
        with open("statistics.txt","w") as f:
                    f.write(stat)
        if len(csv.mailCz.getOrphans()):
            print("Nezdařilo se dohledat abusemaily pro {} CZ IP.".format(len(csv.mailCz.getOrphans())))
        if len(csv.countriesMissing):
            print("Nezdařilo se dohledat csirtmaily pro {} zemí.".format(len(csv.countriesMissing)))

        print("\n Hlavní menu:")
        print("1 - Zaslat přes OTRS...")
        print("2 - Generovat... (soubory s IP bez kontaktu: {})".format(csv.missingFilesInfo()))
        print("3 - Seznamy mailů a počet IP (interní proměnné)")
        print("4 - Zpracovat znovu...")
        print("x - Konec")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        #option = "7" #XX
        print("******")
        if option == "x":
            wrapper.save() # preulozit cache soubor
            break
        elif option == "4":
            print("1 - Zpracovat celý soubor znovu")
            print("2 - Zpracovat znovu jen whois")
            print("3 - Renačíst světové csirtmaily ze souboru")
            print("4 - Editovat texty mailů")
            print("[x] - Storno")

            sys.stdout.write("? ")
            sys.stdout.flush()
            option2 = input()

            if option2 == "1":
                wrapper.clear()
            elif option2 == "2":
                csv.launchWhois()
            elif option2 == "3":
                csv.buildListWorld()
            elif option2 == "4":
                csv.mailCz.guiEdit()
                csv.mailWorld.guiEdit()

            continue        
        elif option == "3":            
            csv.soutDetails()
            continue
        elif option == "2":
            print("1 - Generovat soubory s IP bez kontaktu {}".format(csv.missingFilesInfo()))
            print("2 - Generovat všechny soubory ({} souborů)".format(len(csv.countries) + len(csv.mailCz.mails)))
            print("3 - Generovat statistiky pro Martina")
            print("[x] - Storno")
            sys.stdout.write("? ")
            sys.stdout.flush()
            option2 = input()

            if option2 == "1":
                csv.generateFiles(os.path.dirname(file), True)
            elif option2 == "2":
                csv.generateFiles(os.path.dirname(file))
            elif option2 == "3":
                with open("statistics.txt","w") as f:
                    f.write(csv.getStatsPhrase())
                    
                    

            continue
        elif option == "1":
            MailSender.assureTokens(csv)
            print("\nV příštím kroku se přípojíme k OTRS a odešleme maily.")
            print(" Template českého mailu začíná: {}".format(csv.mailCz.getMailPreview()))
            print(" Template světového mailu začíná: {}".format(csv.mailWorld.getMailPreview()))
            print("Opravdu si přejete odeslat maily nyní?")
            print("1 - Zaslat do CZ i do světa")
            print("2 - Zaslat jen do CZ")
            print("3 - Zaslat jen do světa")            
            print("[x] - Storno")
            sys.stdout.write("? ")
            sys.stdout.flush()
            option = input()
            if option == "1" or option == "2":
                print("Posíláme do CZ...")
                if not MailSender.sendList(csv.mailCz, csv): # poslat ceske maily
                    print("Nezdařilo se zaslat všechny české maily. (Detaily v mailSender.log.)")
            if option == "1" or option == "3":
                print("Posíláme do světa...")
                if not MailSender.sendList(csv.mailWorld, csv): # poslat svetove maily
                    print("Nezdařilo se zaslat všechny světové maily. (Detaily v mailSender.log.)")
                    #if len(csv.countries) > 0: print("Nyní můžete vygenerovat soubory bez kontaktu.")
            continue
        elif option == "debug":
            import pdb; pdb.set_trace()
        else:
            continue #zopakovat volbu


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
    