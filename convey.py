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
    import logging
except ImportError:
    traceback.print_exc()
    print("\nTry installing the libraries by install.sh")
    quit()
__shortdoc__ = """Incident log in CSV -> mails to responsible people (via OTRS)"""
with open("README.md", "r") as f:
    __doc__ = f.read()
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"
logging.basicConfig(level=logging.DEBUG)

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
        if Config.get('testing') == "True":
            print("\n*** TESTING MOD - mails will be send to mail {} ***\n (To cancel the testing mode set testing = False in config.ini.)".format(Config.get('testingMail')))
        stat = csv.getStatsPhrase()
        if csv.isAnalyzed():
            print("\n Statistics overview:\n" + stat)
            with open(os.path.dirname(file) + "/statistics.txt","w") as f:
                f.write(stat)
        else:
            print("\n Not analyzed yet. Rework.")
        if csv.reg["local"].stat("records", False):
            print("Couldn't find {} abusemails for {}× IP.".format(csv.reg["local"].stat("records", False), csv.reg["local"].stat("ips", False)))
        if csv.reg["foreign"].stat("records", False):
            print("Couldn't find {} csirtmails for {}× IP.".format(csv.reg["foreign"].stat("records", False), csv.reg["foreign"].stat("ips", False)))

        print("\n Main menu:")
        print("1 – Send by OTRS...")        
        print("2 – Print all details")
        print("3 – Rework again...")
        print("x – End")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        #option = "7" #XX
        print("******")
        if option == "x":
            wrapper.save() # resave cache file
            break
        elif option == "3":
            print("1 – Rework whole file again")
            print("2 – Rework again whois only")
            print("3 – Resolve unknown abusemails")
            print("4 – Reload csirtmails and local cc's from file")
            print("5 – Edit mail texts")
            print("[x] – Cancel")

            sys.stdout.write("? ")
            sys.stdout.flush()
            option2 = input()

            if option2 == "1":
                wrapper.clear()
            elif option2 == "2":
                csv.runAnalysis()
            elif option2 == "3":
                csv.resolveUnknown()
            elif option2 == "4":
                [r.update() for r in csv.reg.values()]
            elif option2 == "5":
                csv.reg["local"].mailDraft.guiEdit()
                csv.reg["foreign"].mailDraft.guiEdit()

            continue        
        elif option == "2":
            csv.soutInfo(full = True)
            continue
        elif option == "1":
            MailSender.assureTokens(csv)
            print("\nIn the next step, we connect to OTRS and send e-mails.")
            print(" Template of local mail starts: {}".format(csv.mailLocal.getMailPreview()))
            print(" Template of foreign mail starts: {}".format(csv.mailForeign.getMailPreview()))
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
                if not MailSender.sendList(csv.mailLocal, csv): 
                    print("Couldn't send all local mails. (Details in mailSender.log.)")
            if option == "1" or option == "3":
                print("Sending to foreigns...")
                if not MailSender.sendList(csv.mailForeign, csv): 
                    print("Couldn't send all foreign e-mails. (Details in mailSender.log.)")
            continue
        elif option == "debug":
            import ipdb; ipdb.set_trace()
        else:
            continue #repeat options


    print("Finished.")    