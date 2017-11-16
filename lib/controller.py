import argparse
import os.path
from collections import defaultdict
from lib.config import Config
from sys import exit
from lib.dialogue import Dialogue, Cancelled, Debugged
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
from lib.mailSender import MailSender
from lib.whois import Whois
from lib.graph import Graph


class Controller:

    def __init__(self):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('file', nargs='?')
        parser.add_argument('--fresh', help="Do not attempt to load previous results", default=False, action="store_true")
        parser.add_argument('--otrs_id')
        parser.add_argument('--otrs_num')
        parser.add_argument('--otrs_cookie')
        parser.add_argument('--otrs_token')
        args = parser.parse_args()
        self.processable = False

        file = SourcePicker() # source file path
        self.wrapper = SourceWrapper(file, args.fresh)
        csv = self.csv = self.wrapper.csv

        # load flags
        if args.otrs_id:
            csv.otrs_ticketid = args.otrs_id
            print("Ticket id: {}".format(args.otrs_id))
        elif args.otrs_num:
            csv.otrs_ticketnum = args.otrs_num
            print("Ticket num: {}".format(args.otrs_num))
        elif args.otrs_cookie:
            csv.cookie = args.otrs_cookie
            print("OTRS cookie: {}".format(args.otrs_cookie))
        elif args.otrs_token:
            csv.token = args.otrs_token
            print("OTRS token: {}".format(args.otrs_token))

        fn = lambda: print("Not yet implemented!")
        #self.csv.settings = defaultdict(list) # every program launch, the settings resets

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
            print("Settings", self.csv.settings)

            print("Fields", csv.fields)

            #else:
            #    print("\n Analysis has not been completed. Please rework again.")

            # XX list actions
            menu = []
            menu.append(("1","Pick or delete columns", self.choseCols))
            menu.append(("2","Add a column",self.addColumn))
            menu.append(("3","Unique filter", self.addUniquing)) # XXX Dialogue.pickOption from csv.fields + netname, asn... and other computable
            menu.append(("4","Value filter", self.addFiltering))
            menu.append(("5","Split by a column", self.addSplitting))
            menu.append(("p","process", csv.runAnalysis) if self.processable else (None, "process  (choose some actions)", None))
            menu.append(("s","send", fn) if csv.isAnalyzedB else (None, "send (split first)", None))
            menu.append(("d","show all details", lambda: csv.soutInfo(full=True)) if csv.isAnalyzedB else (None, "show all details (process first)", None))
            menu.append(("r","Refresh...", self.refreshMenu))
            menu.append(("x","exit", self.close))

            try:
                Dialogue.tupled_menu(menu, title="Main menu - how the file should be processed?")
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                import ipdb; ipdb.set_trace()


    def refreshMenu(self):
        menu = []
        menu.append(("1", "Rework whole file again", self.wrapper.clear))
        menu.append(("2", "Delete processing settings", self.csv.resetSettings))
        menu.append(("3", "Delete whois cache", self.csv.resetWhois))
        Dialogue.tupled_menu(menu, title="What should be reprocessed?")


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
            path = g.dijkstra(new_field, start= _min[1]) # list of method-names to calculate new fields
        except KeyError:
            print("No known method for making {} from {}".format(new_field,sourceColI))
            input()
            # XX ask how should be treated the column as, even it seems not valid (if as a hostname, url...)
            return
        except:
            print("Error finding a method for making {} from {}".format(new_field,sourceColI))
            input()
            return

        methods = [] # list of lambdas to calculate new field
        for i in range(len(path)-1):
            methods.append(self.csv.guesses.methods[path[i],path[i+1]])

        self.csv.settings["add"].append((new_field, sourceColI, methods))
        self.csv.fields.append(new_field)
        return len(self.csv.fields) - 1 #+ len(self.csv.settings["add"]) - 1


    def choseCols(self):
        print("TBD XX")
        # XX maybe use python library dialog for multiple choice or something
        pass


    def selectCol(self, colName="", only_extendables=False):
        fields = [] + (self.csv.fields if not only_extendables else [])
        fields += ["COMPUTED " + x for x in self.csv.guesses.extendable_fields]
        colI = Dialogue.pickOption(fields, colName)
        if colI >= len(self.csv.fields):
            colI = self.extendColumn(self.csv.guesses.extendable_fields[colI - len(self.csv.fields)])
        return colI

    def addFiltering(self):
        colI = self.selectCol("filter")
        val = Dialogue.ask("What value should the field have to keep the line?")
        self.csv.settings["filter"].append((colI, val))
        self.processable = True

    def addSplitting(self):
        self.csv.settings["split"] = self.selectCol("splitting")
        self.processable = True

    def addColumn(self):
        colI = self.selectCol("new column", only_extendables=True)
        self.extendColumn(self.csv.guesses.extendable_fields[colI])
        self.processable = True

    def addUniquing(self):
        colI = self.selectCol("unique")
        self.csv.settings["unique"].append(colI)
        self.processable = True

    def close(self):
        self.wrapper.save()  # resave cache file
        print("Finished.")
        exit(0)