#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import traceback
import sys
import argparse
import os.path
try:
    pass
    #import networkx as nx ## networkx - XX if implemented without networkx, we may suppress the dependency (2 MB)
except ImportError:
    traceback.print_exc()
    print("\nTry installing the libraries by install.sh")
    quit()
from lib.config import Config
from lib.dialogue import Dialogue, Cancelled, Debugged
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
from lib.mailSender import MailSender
from lib.whois import Whois
from lib.graph import Graph
__shortdoc__ = """Incident log in CSV -> mails to responsible people (via OTRS)"""
with open("README.md", "r") as f:
    __doc__ = f.read()
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"
import logging
logging.basicConfig(level=logging.DEBUG, filename="convey.log", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class _Controller:

    # ********************************* JESTE NEMAZAT ******************************
    # url → hostname → ip → prefix ∨ asn ∨ (whois-abuse ∨ whois-abuse-forced ∨ country → csirt-mail ∨ abuse-contact)
    # anyIP, portIP, cms

    """
    1. filtruj podle netname ze sloupce 20  .. compute["netname", 20, [lambda x, ...]]; filters.add([20, "value"])
    2. přidej netname ze sloupce 20 .. chosenColumns.add(20)
    3. processing: cols[20] = val = lambda x(compute[1])
    4. filters[ cols[20] ]
    5. chosenCols
    """


    def __init__(self):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('file', nargs='?')
        parser.add_argument('--otrs_id')
        parser.add_argument('--otrs_num')
        parser.add_argument('--otrs_cookie')
        parser.add_argument('--otrs_token')
        self.args = parser.parse_args()
        self.processable = False

        file = SourcePicker() # source file path
        self.wrapper = SourceWrapper(file)
        csv = self.csv = self.wrapper.csv

        if self.args.otrs_id:
            csv.otrs_ticketid = self.args.otrs_id
            print("Ticket id: {}".format(self.args.otrs_id))
        elif self.args.otrs_num:
            csv.otrs_ticketnum = self.args.otrs_num
            print("Ticket num: {}".format(self.args.otrs_num))
        elif self.args.otrs_cookie:
            csv.cookie = self.args.otrs_cookie
            print("OTRS cookie: {}".format(self.args.otrs_cookie))
        elif self.args.otrs_token:
            csv.token = self.args.otrs_token
            print("OTRS token: {}".format(self.args.otrs_token))

        fn = lambda: print("Not yet implemented!")
        xxhaveSomeOptionsChosen = False
        #csv = _Controller
        #csv.isProcessed = True

        # main menu
        while True:
            if Config.get('testing') == "True":
                print("\n*** TESTING MOD - mails will be send to mail {} ***\n (To cancel the testing mode set testing = False in config.ini.)".format(Config.get('testingMail')))
            if csv.isAnalyzed():
                stat = csv.informer.getStatsPhrase()
                print("\n Statistics overview:\n" + stat)
                with open(os.path.dirname(file) + "/statistics.txt","w") as f:
                    f.write(stat)
                """
                XX
                if csv.abuseReg.stat("records", False):
                    print("Couldn't find {} abusemails for {}× IP.".format(csv.reg["local"].stat("records", False), csv.reg["local"].stat("ips", False)))
                if csv.countryReg.stat("records", False):
                    print("Couldn't find {} csirtmails for {}× IP.".format(csv.reg["foreign"].stat("records", False), csv.reg["foreign"].stat("ips", False)))
                """
            print("Settings", csv.settings)

            print("Fields", csv.fields)

            #else:
            #    print("\n Analysis has not been completed. Please rework again.")

            # XX list actions
            menu = []
            menu.append(("1","Pick or delete columns", self.choseCols))
            menu.append(("2","Add a column",self.addColumn))
            menu.append(("3","Unique filter", self.setUnique)) # XXX Dialogue.pickOption from csv.fields + netname, asn... and other computable
            menu.append(("4","Value filter", self.addFilter))
            menu.append(("5","Split by a column", self.addSplitting))
            menu.append(("p","process", csv.runAnalysis) if self.processable else (None, "process  (choose some actions)", None))
            menu.append(("s","send", fn) if csv.isAnalyzedB else (None, "send (split first)", None))
            menu.append(("d","show all details", lambda: csv.soutInfo(full = True)) if csv.isAnalyzedB else (None, "show all details (process first)", None))
            menu.append(("r","Refresh everything", self.wrapper.clear))
            menu.append(("x","exit", self.close))

            try:
                Dialogue.tupled_menu(menu, title="Main menu – how the file should be processed?")
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                import ipdb; ipdb.set_trace()



    def extendColumn(self, new_field):
        """ we know what is new column, now determine how we should extend it """
        print("\nWhat column we base {} on?".format(new_field))

        g = Graph()
        for m in self.csv.guesses.methods:
            g.add_edge(*m[:2])

        validTypes = list(g.dijkstra(new_field))
        possibleCols = []
        for key, types in self.csv.guesses.fieldType.items():
            for val in types:
                if val in validTypes:
                    possibleCols.append(key)
        sourceColI = Dialogue.pickOption(self.csv.fields, colName="Searching source for "+new_field, guesses=possibleCols)

        try:
            _min = 999, None
            for _type in self.csv.guesses.fieldType[self.csv.fields[sourceColI]]:
                # a column may have multiple types (url, hostname), use the best
                if _type not in g.dijkstra(new_field):
                    continue
                i = g.dijkstra(new_field)[_type]
                if i < _min[0]:
                    _min = i, _type
            path = g.dijkstra(new_field, start= _min[1]) #nx.dijkstra_path(g, 'anyIP', 'whois')
        except KeyError:
            print("No known method for making {} from {}".format(new_field,sourceColI))
            input()
            # XX ask how should be treated the column as, even it seems not valid (if as a hostname, url...)
            return
        except:
            print("Error finding a method for making {} from {}".format(new_field,sourceColI))
            input()
            return

        methods = []
        for i in range(len(path)-1):
            methods.append(self.csv.guesses.methods[path[i],path[i+1]])

        self.csv.settings["add"].append((new_field, sourceColI, methods))
        return len(self.csv.fields) + len(self.csv.settings["add"]) - 1


    def choseCols(self):
        print("TBD XX")
        pass


    def selectCol(self, colName="", only_extendables=False):
        fields = [] + (self.csv.fields if not only_extendables else [])
        fields += self.csv.guesses.extendable_fields
        colI = Dialogue.pickOption(fields, colName)
        if colI >= len(self.csv.fields):
            colI = self.extendColumn(self.csv.guesses.extendable_fields[colI - len(self.csv.fields)])
        return colI

    def addFilter(self):
        colI = self.selectCol("filter")
        val = Dialogue.ask("What value should the field have to keep the line?")
        self.csv.settings["filter"].append((colI, val))
        self.processable = True

    def addSplitting(self):
        self.csv.settings["split"] = self.selectCol("filter")
        self.processable = True

    def addColumn(self):
        colI = self.selectCol("new column", only_extendables=True)
        self.extendColumn(self.csv.guesses.extendable_fields[colI])
        self.processable = True

    def setUnique(self):
        colI = self.selectCol("unique")
        self.csv.settings["unique"].append(colI)
        self.processable = True

    def close(self):
        self.wrapper.save()  # resave cache file
        print("Finished.")
        sys.exit(0)

if __name__ == "__main__":
    print(__shortdoc__),

    #command line flags - it controls the program flow; parameters --id, --ticket, --cookie --token --attachmentName
    if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
        print(__doc__)
        quit()

    # XX parseargs
    try:
        _Controller()
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
        #option = "7" #XX
        print("******")
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

#            continue

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
            #continue
   #
   #     else:
   #         continue #repeat options
