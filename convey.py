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
    print("\nTry installing the libraries by install.sh")
    quit()
__shortdoc__ = """OTRS Convey -> translator for OTRS"""
__doc__ = """Translator for OTRS.
 Syntax:
    ./convey.py [--id <OTRS ticket id>] [--num <OTRS ticket number>] [--cookie <OTRS cookie>] [--token <OTRS token>] [<filename>]
 Parameter [filename] is path to source log file in CSV format.
 If [filename] not present, script asks for it.
 Script tries to parse and determine IP and ASN columns.

 Instead of IP column we may use URL column. In that case, script takes the URL domain, translates it to IP and adds a column 'HOST_IP' to CSV. If it finds more IP, it duplicates URL row.

 Dependencies needed are installed by install.sh script.
 -h, --help Show help.
"""
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"


if __name__ == "__main__":    
    print(__shortdoc__)

    #command line flags - it controls the program flow; parameters --id, --ticket, --cookie --token --attachmentName
    if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    file = SourcePicker() # source file path
    wrapper = SourceWrapper(file)
    csv = wrapper.csv

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["","id=", "num=","cookie=","token="])
    except getopt.GetoptError:
        print(__doc__)        
        sys.exit(2)
    for opt, arg in opts:        
        if opt in ("--id"):
            csv.ticketid = arg
            print("Ticket id: {}".format(arg))            
        elif opt in ("--num"):
            csv.ticketnum = arg
            print("Ticket num: {}".format(arg))
        elif opt in ("--cookie"):
            csv.cookie = arg
            print("OTRS cookie: {}".format(arg))
        elif opt in ("--token"):
            csv.token = arg
            print("OTRS token: {}".format(arg))    
    

    #menu
    while True:                
        if Config.get('debug') == "True":
            print("\n*** DEBUG MOD - mails will be send to mail {} ***\n (To cancel the debug mode set debug = False in config.ini.)".format(Config.get('debugMail')))
        stat = csv.getStatsPhrase()
        print("Statistics overview: " + stat)
        with open(os.path.dirname(file) + "/statistics.txt","w") as f:
                    f.write(stat)
        if len(csv.mailCz.getOrphans()):
            print("Couldn't find abusemails for {} CZ IP.".format(len(csv.mailCz.getOrphans())))
        if len(csv.countriesMissing):
            print("Couldn't find csirtmaily for {} countries.".format(len(csv.countriesMissing)))

        print("\n Main menu:")
        print("1 – Send by OTRS...")
        print("2 – Generate... (file with IP without contact: {})".format(csv.missingFilesInfo()))
        print("3 – List mails and IP count (internal variables)")
        print("4 – Rework again...")
        print("x – End")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        #option = "7" #XX
        print("******")
        if option == "x":
            wrapper.save() # resave cache file
            break
        elif option == "4":
            print("1 – Rework whole file again")
            print("2 – Rework again whois only")
            print("3 – Reload foreign csirtmails from file")
            print("4 – Edit mail texts")
            print("[x] – Cancel")

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
            print("1 - Generate files with IP without contacts {}".format(csv.missingFilesInfo()))
            print("2 - Generate all files ({} files)".format(len(csv.countries) + len(csv.mailCz.mails)))
            print("[x] - Cancel")
            sys.stdout.write("? ")
            sys.stdout.flush()
            option2 = input()

            if option2 == "1":
                csv.generateFiles(os.path.dirname(file), True)
            elif option2 == "2":
                csv.generateFiles(os.path.dirname(file))                                    
            continue
        elif option == "1":
            MailSender.assureTokens(csv)
            print("\nIn the next step, we connect to OTRS and send e-mails.")
            print(" Template of local mail starts: {}".format(csv.mailCz.getMailPreview()))
            print(" Template of foreign mail starts: {}".format(csv.mailWorld.getMailPreview()))
            print("Do you really want to send e-mails now?")
            print("1 - Send both local and foreign")
            print("2 - Send local only")
            print("3 - Send foreign only")
            print("[x] - Cancel")
            sys.stdout.write("? ")
            sys.stdout.flush()
            option = input()
            if option == "1" or option == "2":
                print("Sending to local country...")
                if not MailSender.sendList(csv.mailCz, csv): 
                    print("Couldn't send all local mails. (Details in mailSender.log.)")
            if option == "1" or option == "3":
                print("Sending to foreigns...")
                if not MailSender.sendList(csv.mailWorld, csv): 
                    print("Couldn't send all foreign e-mails. (Details in mailSender.log.)")
            continue
        elif option == "debug":
            import pdb; pdb.set_trace()
        else:
            continue #repeat options


    print("Finished.")    