#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import traceback
import sys
try:
    pass
    #import networkx as nx ## networkx - XX if implemented without networkx, we may suppress the dependency (2 MB)
except ImportError:
    traceback.print_exc()
    print("\nTry installing the libraries by install.sh")
    quit()
from lib.controller import Controller
__shortdoc__ = """Incident log in CSV -> mails to responsible people (via OTRS)"""
with open("README.md", "r") as f:
    __doc__ = f.read()
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"
import logging
logging.basicConfig(level=logging.DEBUG, filename="convey.log", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


if __name__ == "__main__":
    print(__shortdoc__),

    #command line flags - it controls the program flow; parameters --id, --ticket, --cookie --token --attachmentName
    if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    # XX parseargs
    try:
        Controller()
    except SystemExit as e:
        pass
    except:
        import traceback
        try:
            import pudb
            m = pudb
        except:
            import pdb
            m = pdb
        type, value, tb = sys.exc_info()
        traceback.print_exc()
        m.post_mortem(tb)



if __name__ == "XXOLDMAIN TO BE MIGRATED":


    #menu

        print("\n Main menu:")
        print("1 – Send by OTRS...")
        print("2 – Print all details")
        print("3 – Rework again...")
        print("x – End")
        sys.stdout.write("? ")
        sys.stdout.flush()
        option = input()
        if option == "3":
            print("1 – Rework whole file again")
            print("2 – Rework again whois only")
            print("3 – Resolve unknown abusemails")
            print("4 – Resolve invalid lines")
            print("5 – Reload csirtmails and local cc's from file")
            print("6 – Edit mail texts")
            print("[x] – Cancel")

            sys.stdout.write("? ")
            sys.stdout.flush()
            option2 = input()

            if option2 == "3":
                csv.resolveUnknown()
            elif option2 == "4":
                csv.resolveInvalid()
            elif option2 == "5":
                [r.update() for r in csv.reg.values()]
            elif option2 == "6":
                csv.reg["local"].mailDraft.guiEdit()
                csv.reg["foreign"].mailDraft.guiEdit()

        elif option == "1":
            MailSender.assureTokens(csv)
            wrapper.save()
            print("\nIn the next step, we connect to OTRS and send e-mails.")
            if csv.abuseReg.getMailCount() > 0:
                print(" Template of local mail starts: {}".format(csv.abuseReg.mailDraft.getMailPreview()))
            else:
                print(" No local mail in the set.")
            if csv.countryReg.getMailCount() > 0:
                print(" Template of foreign mail starts: {}".format(csv.countryReg.mailDraft.getMailPreview()))
            else:
                print(" No foreign mail in the set.")
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
                if not MailSender.sendList(csv.abuseReg, csv):
                    print("Couldn't send all local mails. (Details in mailSender.log.)")
            if option == "1" or option == "3":
                print("Sending to foreigns...")
                if not MailSender.sendList(csv.countryReg, csv):
                    print("Couldn't send all foreign e-mails. (Details in mailSender.log.)")