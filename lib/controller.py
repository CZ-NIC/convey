import argparse
from collections import defaultdict
from dialog import Dialog
from heapq import nsmallest
from sys import exit

from lib.config import Config
from lib.contacts import Contacts
from lib.dialogue import Cancelled, Debugged, Dialogue, Menu
from lib.sourcePicker import SourcePicker
from lib.sourceWrapper import SourceWrapper
from lib.mailSender import MailSender



class Controller:

    def __init__(self):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('file', nargs='?')
        parser.add_argument('--debug', help="On error, enter ipdb session", default=False, action="store_true")
        parser.add_argument('--fresh', help="Do not attempt to load any previous settings / results", default=False, action="store_true")
        flags = [("otrs_id", "Ticket id"), ("otrs_num", "Ticket num"), ("otrs_cookie", "OTRS cookie"), ("otrs_token", "OTRS token")]
        for flag in flags:
            parser.add_argument('--'+flag[0], help=flag[1])
        parser.add_argument('--csirt-incident', action="store_true", help="Macro that lets you split CSV by fetched incident-contact (whois abuse mail for local country or csirt contact for foreign countries) and send everything by OTRS. You set local countries in config.ini, currently set to: {}".format(Config.get("local_country")))
        args = parser.parse_args()
        if args.debug:
            Config.set("debug", True)

        file = SourcePicker() # source file path
        self.wrapper = SourceWrapper(file, args.fresh)
        csv = self.csv = self.wrapper.csv
        Contacts.refresh()

        # load flags
        for flag in flags:
            if args.__dict__[flag[0]]:
                csv.__dict__[flag[0]] = args.__dict__[flag[0]]
                print("{}: {}".format(flag[1], flag[0]))

        #self.csv.settings = defaultdict(list) # every program launch, the settings resets
        if args.csirt_incident and not csv.isAnalyzed:
            csv.settings["split"] = self.extendColumn("incident-contact", add=False)
            csv.isProcessable = True
            csv.runAnalysis()

        # main menu
        while True:
            csv = self.csv = self.wrapper.csv # may be changed by reprocessing
            csv.informer.soutInfo()

            if Config.get('testing') == "True":
                print("\n*** TESTING MOD - mails will be send to mail {} ***\n (To cancel the testing mode set testing = False in config.ini.)".format(Config.get('testingMail')))

            #else:
            #    print("\n Analysis has not been completed. Please rework again.")

            # XX list actions
            menu = Menu(title="Main menu - how the file should be processed?")
            menu.add("Pick or delete columns", self.chooseCols)
            menu.add("Add a column", self.addColumn)
            menu.add("Unique filter", self.addUniquing)
            menu.add("Value filter", self.addFiltering)
            menu.add("Split by a column", self.addSplitting)
            if self.csv.isProcessable:
                menu.add("process", csv.runAnalysis, key="p")
            else:
                menu.add("process  (choose some actions)")
            if csv.isAnalyzed:
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
            if o == '1':
                method = "smtp"
            elif o == '2':
                method = "otrs"
            else:
                print("Unknown option")
                return
        else:
            method = "smtp"

        menu = Menu("Do you really want to send e-mails now?", callbacks=False)

        MailSender.assureTokens(self.csv)
        self.wrapper.save()
        print("\nIn the next step, we connect to server to send e-mails.")
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

        #import ipdb; ipdb.set_trace()

    def extendColumn(self, new_field, add=None):
        """ We know what is new column, now determine how we should extend it
                add - bool if the column should be added to the table; None ask
        """
        print("\nWhat column we base {} on?".format(new_field))
        g = self.csv.guesses.getGraph()
        validTypes = list(g.dijkstra(new_field))
        possibleCols = []
        for (i, key), types in self.csv.guesses.fieldType.items():
            for val in types:
                if val in validTypes:
                    possibleCols.append(i)
                    break
        sourceColI = Dialogue.pickOption(self.csv.getFieldsWithAutodetection(), title="Searching source for "+new_field, guesses=possibleCols)

        dialog = Dialog()
        try:
            _min = 999
            method =None
            for _type in self.csv.guesses.fieldType[sourceColI, self.csv.fields[sourceColI]]:
                # a column may have multiple types (url, hostname), use the best
                if _type not in g.dijkstra(new_field):
                    continue
                i = g.dijkstra(new_field)[_type]
                if i < _min:
                    _min, method = i, _type
            if method is None:
                raise KeyError
        except KeyError:
            # ask how should be treated the column as, even it seems not valid
            # list all known methods to compute the desired new_field (e.g. for incident-contact it is: ip, hostname, ...)
            choices = [(k,self.csv.guesses.getDescription(k)) for k, _ in sorted(self.csv.guesses.getGraph().dijkstra(new_field, ignore_private=True).items(), key=lambda v:v[1], reverse=True)] # whois is an internal keyword
            if choices:
                title="Choose the right method\n\nNo known method for making {} from column {} because the column type wasn't identified. How should I treat the column?".format(new_field, self.csv.fields[sourceColI])
                button, method = dialog.menu(title, choices=choices)
                if button == "cancel":
                    return
            else:
                dialog.msgbox("No known method for making {}. Raise your usecase as an issue at {}.".format(new_field, Config.PROJECT_SITE))
        except:
            print("Error finding a method for making {} from {}".format(new_field, self.csv.fields[sourceColI]))
            input()
            return

        self.csv.settings["add"].append((new_field, sourceColI, method))
        self.csv.fields.append(new_field)

        if add is None:
            if dialog.yesno("New field added: {}\n\nDo you want to include this field as a new column?".format(new_field)) == "ok":
                add = True

        if add is True: # or (add is None and input("Do you want to include this field as a new column? [y]/n ") not in ["n","no"]):
            self.csv.settings["chosen_cols"].append(len(self.csv.fields)-1)
        #if add is False or (add is None and input("Do you want to include this field as a new column? [y]/n ") in ["n","no"]):
            #self.csv.settings["chosen_cols"].append(False)
        return len(self.csv.fields) - 1 #+ len(self.csv.settings["add"]) - 1


    def chooseCols(self):
        # XX possibility un/check all
        chosens = [(str(i+1),f,i in self.csv.settings["chosen_cols"]) for i,f in enumerate(self.csv.fields)]
        d = Dialog()
        ret, values = d.checklist("What fields should be included in the output file?",
            choices=chosens)
        if ret == "ok":
            self.csv.settings["chosen_cols"] = [int(v)-1 for v in values]
            self.csv.isProcessable = True


    def selectCol(self, colName="", only_extendables=False, add=None):
        fields = self.csv.getFieldsWithAutodetection() if not only_extendables else []
        for f in self.csv.guesses.extendable_fields:
            d = self.csv.guesses.getGraph().dijkstra(f, ignore_private=True)
            s = "from " + ", ".join(sorted([k for k in nsmallest(3, d, key=d.get)]))
            if len(d) > 3:
                s += "..."
            fields.append(("new " + f + "...", s))
        colI = Dialogue.pickOption(fields, colName)
        if only_extendables or colI >= len(self.csv.fields):
            new_fieldI = colI if only_extendables else colI - len(self.csv.fields)
            colI = self.extendColumn(self.csv.guesses.extendable_fields[new_fieldI], add=add)
        return colI

    def addFiltering(self):
        colI = self.selectCol("filter")
        val = Dialogue.ask("What value should the field have to keep the line?")
        self.csv.settings["filter"].append((colI, val))
        self.csv.isProcessable = True

    def addSplitting(self):
        self.csv.settings["split"] = self.selectCol("splitting")
        self.csv.isProcessable = True

    def addColumn(self):
        colI = self.selectCol("new column", only_extendables=True, add=True)
        #self.extendColumn(self.csv.guesses.extendable_fields[colI])
        self.csv.isProcessable = True

    def addUniquing(self):
        colI = self.selectCol("unique")
        self.csv.settings["unique"].append(colI)
        self.csv.isProcessable = True

    def close(self):
        self.wrapper.save()  # resave cache file
        print("Finished.")
        exit(0)