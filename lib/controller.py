import argparse
from collections import defaultdict
from lib.config import Config
from sys import exit
from lib.contacts import Contacts
from lib.dialogue import Cancelled, Debugged, Dialogue, Menu
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
from lib.mailSender import MailSender
from lib.whois import Whois
from lib.graph import Graph
from dialog import Dialog


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
        Contacts.refresh()

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

        #self.csv.settings = defaultdict(list) # every program launch, the settings resets

        # main menu
        while True:
            csv.informer.soutInfo()
            if Config.get('testing') == "True":
                print("\n*** TESTING MOD - mails will be send to mail {} ***\n (To cancel the testing mode set testing = False in config.ini.)".format(Config.get('testingMail')))
            #print("Settings", self.csv.settings)
            #print("Fields", csv.fields)

            #else:
            #    print("\n Analysis has not been completed. Please rework again.")

            # XX list actions
            menu = Menu(title="Main menu - how the file should be processed?")
            menu.add("Pick or delete columns", self.chooseCols)
            menu.add("Add a column",self.addColumn)
            menu.add("Unique filter", self.addUniquing)
            menu.add("Value filter", self.addFiltering)
            menu.add("Split by a column", self.addSplitting)
            if self.processable:
                menu.add("process", csv.runAnalysis, key="p")
            else:
                menu.add("process  (choose some actions)")
            if csv.isAnalyzed():
                menu.add("send", self.sendMenu, key="s")
                menu.add("show all details", lambda: csv.informer.soutInfo(full=True), key="d")
            else:
                menu.add("send (split first)")
                menu.add("show all details (process first)")
            menu.add("Refresh...", self.refreshMenu, key="r")
            menu.add("exit", self.close, key="x")

            try:
                menu.sout()
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                import ipdb; ipdb.set_trace()

    def sendMenu(self):
        if Config.get("otrs_enabled", "OTRS"):
            menu = Menu(title="What sending method do we want to use?", callbacks=False, fullscreen=True)
            menu.add("Send by SMTP...")
            menu.add("Send by OTRS...")
            o = menu.sout()
            if o == 1:
                method = "smtp"
            elif o == 2:
                method = "otrs"
            else:
                print("Unknown option")
                return
        else:
            method = "smtp"

        menu = Menu("Do you really want to send e-mails now?", callbacks=False)

        MailSender.assureTokens(self.csv)
        self.wrapper.save()
        print("\nIn the next step, we connect to OTRS and send e-mails.")
        a = b = False
        if self.csv.stats["ispCzFound"]:
            print(" Template of local mail starts: {}".format(Contacts.mailDraft["local"].getMailPreview()))
            a = True
        else:
            print(" No local mail in the set.")
        if self.csv.stats["countriesFound"]:
            print(" Template of foreign mail starts: {}".format(Contacts.mailDraft["local"].getMailPreview()))
            b = True
        else:
            print(" No foreign mail in the set.")

        if a and b:
            menu.add("Send both local and foreign", key=1)
        if a:
            menu.add("Send local only", key=2)
        if b:
            menu.add("Send foreign only", key=3)

        option = menu.sout()
        if option == "x":
            return
        if option == "1" or option == "2":
            print("Sending to local country...")
            if not MailSender.sendList(self.csv,
                    Contacts.getContacts(self.csv.stats["ispCzFound"]),
                    Contacts.mailDraft["local"],
                    len(self.csv.stats["ispCzFound"]),
                    method=method):
                print("Couldn't send all local mails. (Details in mailSender.log.)")
        if option == "1" or option == "3":
            print("Sending to foreigns...")
            if not MailSender.sendList(self.csv,
                    Contacts.getContacts(self.csv.stats["countriesFound"], checkCountries=True),
                    Contacts.mailDraft["foreign"],
                    len(self.csv.stats["countriesFound"]),
                    method=method):
                print("Couldn't send all foreign e-mails. (Details in mailSender.log.)")

    def refreshMenu(self):
        menu = Menu(title="What should be reprocessed?", fullscreen=True)
        menu.add("Rework whole file again", self.wrapper.clear)
        menu.add("Delete processing settings", self.csv.resetSettings)
        menu.add("Delete whois cache", self.csv.resetWhois)
        menu.add("Resolve unknown abusemails", self.csv.resolveUnknown)
        menu.add("Resolve invalid lines", self.csv.resolveInvalid)
        menu.add("Edit mail texts", lambda: Contacts.mailDraft["local"].guiEdit() and Contacts.mailDraft["foreign"].guiEdit())
        menu.sout()


    def extendColumn(self, new_field):
        """ we know what is new column, now determine how we should extend it """
        print("\nWhat column we base {} on?".format(new_field))

        g = Graph()
        for m in self.csv.guesses.methods:
            g.add_edge(*m[:2])

        validTypes = list(g.dijkstra(new_field))
        possibleCols = []
        for (i, key), types in self.csv.guesses.fieldType.items():
            for val in types:
                if val in validTypes:
                    possibleCols.append(i)
                    break
        sourceColI = Dialogue.pickOption(self.csv.fields, colName="Searching source for "+new_field, guesses=possibleCols)

        try:
            _min = 999, None
            for _type in self.csv.guesses.fieldType[sourceColI, self.csv.fields[sourceColI]]:
                # a column may have multiple types (url, hostname), use the best
                if _type not in g.dijkstra(new_field):
                    continue
                i = g.dijkstra(new_field)[_type]
                if i < _min[0]:
                    _min = i, _type
            if _min[1] is None:
                raise KeyError
            path = g.dijkstra(new_field, start= _min[1]) # list of method-names to calculate new fields
        except KeyError:
            print("No known method for making {} from {}".format(new_field, self.csv.fields[sourceColI]))
            input()
            # XX ask how should be treated the column as, even it seems not valid (if as a hostname, url...)
            return
        except:
            print("Error finding a method for making {} from {}".format(new_field, self.csv.fields[sourceColI]))
            input()
            return

        methods = [] # list of lambdas to calculate new field
        for i in range(len(path)-1):
            methods.append(self.csv.guesses.methods[path[i],path[i+1]])

        self.csv.settings["add"].append((new_field, sourceColI, methods))
        self.csv.fields.append(new_field)

        if input("Do you want to include this field as a new column? [y]/n") in ["n","no"]:
            if not self.csv.settings["chosen_cols"]:
                self.csv.settings["chosen_cols"] = [True] * (len(self.csv.fields) -1)
            self.csv.settings["chosen_cols"].append(False)
        return len(self.csv.fields) - 1 #+ len(self.csv.settings["add"]) - 1


    def chooseCols(self):
        # XX possibility un/check all
        chosens = [(str(i+1),f,i in self.csv.settings["chosen_cols"] if self.csv.settings["chosen_cols"] else True) for i,f in enumerate(self.csv.fields)]
        d = Dialog()
        ret, values = d.checklist("What fields should be included in the output file?",
            choices=chosens)
        if ret == "ok":
            self.csv.settings["chosen_cols"] = [int(v)-1 for v in values]
            self.processable = True


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