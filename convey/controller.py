import argparse
import csv
import logging
import re
import sys
from pathlib import Path
from sys import exit

import pkg_resources
from Levenshtein import distance
from dialog import Dialog, DialogError
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import clear

from .config import Config, get_terminal_size
from .contacts import Contacts, Attachment
from .dialogue import Cancelled, Debugged, Menu, pick_option, ask
from .identifier import Types, TypeGroup, types, Type, graph, PickMethod, methods, PickBase, PickInput
from .mailSender import MailSenderOtrs, MailSenderSmtp
from .parser import Parser, Field
from .wizzard import Preview, bottom_plain_style
from .wrapper import Wrapper

logger = logging.getLogger(__name__)

try:
    __version__ = pkg_resources.require("convey")[0].version
except pkg_resources.DistributionNotFound:
    __version__ = "unknown"


class BlankTrue(argparse.Action):
    """ When left blank, this flag produces True. (Normal behaviour is to produce None which I use for not being set."""

    def __call__(self, _, namespace, values, option_string=None):
        if values in [None, []]:  # blank argument with nargs="?" produces None, with ="*" produces []
            values = True
        elif values.lower() in ["0", "false", "off"]:
            values = False
        elif values.lower() in ["1", "true", "on"]:
            values = True
        else:
            raise ValueError(f"Unrecognised value {values} of {self.dest}")
        setattr(namespace, self.dest, values)


new_fields = []


class FieldExcludedAppend(argparse.Action):
    def __call__(self, _, namespace, values, option_string=None):
        new_fields.append((False, values))


class FieldVisibleAppend(argparse.Action):
    def __call__(self, _, namespace, values, option_string=None):
        new_fields.append((True, values))


class SmartFormatter(argparse.HelpFormatter):

    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


class Controller:
    def __init__(self):
        Types.refresh()  # load types so that we can print out computable types in the help text
        epilog = "To launch a web service see README.md."
        column_help = "COLUMN is ID the column (1, 2, 3...), the exact column name, field type name or its usual name."
        parser = argparse.ArgumentParser(description="Data conversion swiss knife", formatter_class=SmartFormatter, epilog=epilog)
        parser.add_argument('file_or_input', nargs='?', help="File name to be parsed or input text. "
                                                             "In nothing is given, user will input data through stdin.")
        parser.add_argument('--debug', help="On error, enter an ipdb session", action="store_true")
        parser.add_argument('-F', '--fresh', help="Do not attempt to load any previous settings / results."
                                                  " Do not load convey's global WHOIS cache."
                                                  " (But merge WHOIS results in there afterwards.)", action="store_true")
        parser.add_argument('-y', '--yes', help="Assume non-interactive mode and the default answer to questions.",
                            action="store_true")
        parser.add_argument('--file', help="Treat <file_or_input> parameter as a file, never as an input",
                            action="store_true")
        parser.add_argument('-i', '--input', help="Treat <file_or_input> parameter as an input text, not a file name",
                            action="store_true")
        parser.add_argument('-o', '--output', help="Save output to this file", metavar="FILENAME")
        parser.add_argument('--delimiter', help="Force delimiter")
        parser.add_argument('--quote-char', help="Force quoting character")
        parser.add_argument('--header', help="Treat file as having header", action="store_true")
        parser.add_argument('--no-header', help="Treat file as not having header", action="store_true")
        parser.add_argument('-d', '--delete', help="Delete a column. You may comma separate multiple columns." + column_help,
                            metavar="COLUMN,[COLUMN]")
        parser.add_argument('-v', '--verbose', help="Sets the verbosity to see DEBUG messages.", action="store_true")
        parser.add_argument('-q', '--quiet', help="R|Sets the verbosity to see WARNINGs and ERRORs only."
                                                  " Prints out the least information possible."
                                                  "\n(Ex: if checking single value outputs a single word, prints out just that.)",
                            action="store_true")
        parser.add_argument('-f', '--field',
                            help="R|Compute field."
                                 "\n* FIELD is a field type (see below) that may be appended with a [CUSTOM] in square brackets."
                                 "\n* " + column_help +
                                 "\n* SOURCE_TYPE is either field type or usual field type. "
                                 "That way, you may specify processing method."
                                 "\n* CUSTOM is any string dependent on the new FIELD type (if not provided, will be asked it for)."
                                 "\nEx: --field tld[gTLD]  # would add TLD from probably a hostname, filtered by CUSTOM=gTLD"
                                 "\nEx: --field netname,ip  # would add netname column from any IP column"
                                 "\n    (Note the comma without space behind 'netname'.)"
                                 "\n\nComputable fields: " + "".join("\n* " + t.doc() for t in Types.get_computable_types()) +
                                 "\n\nThis flag May be used multiple times.",
                            action=FieldVisibleAppend, metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]")
        parser.add_argument('-fe', '--field-excluded', help="The same as field but its column will not be added to the output.",
                            action=FieldExcludedAppend, metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]")
        parser.add_argument('--split', help="Split by this COLUMN.",
                            metavar="COLUMN")
        parser.add_argument('-s', '--sort', help="List of columns.",
                            metavar="[COLUMN],...")
        csv_flags = [("otrs_id", "Ticket id"), ("otrs_num", "Ticket num"), ("otrs_cookie", "OTRS cookie"),
                     ("otrs_token", "OTRS token")]
        for flag in csv_flags:
            parser.add_argument('--' + flag[0], help=flag[1])
        parser.add_argument('--csirt-incident', action="store_true",
                            help="Macro that lets you split CSV by fetched incident-contact (whois abuse mail for local country"
                                 " or csirt contact for foreign countries) and send everything by OTRS."
                                 " You set local countries in config.ini, currently set to:"
                                 f" {Config.get('local_country', 'FIELDS')}")
        parser.add_argument('--whois', help="R|Allowing Whois module: Leave blank for True or put true/on/1 or false/off/0.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--nmap', help="R|Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--dig', help="R|Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--web', help="R|Allowing Web module: Leave blank for True or put true/on/1 or false/off/0."
                                          "\nWhen single value input contains a web page, we could fetch it and add"
                                          " status (HTTP code) and text fields. Text is just mere text, no tags, style,"
                                          " script, or head. ",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--disable-external', help="R|Disable external function registered in config.ini to be imported.",
                            action="store_true", default=False)
        parser.add_argument('--json', help="When checking single value, prefer JSON output rather than text.", action="store_true")
        parser.add_argument('--config', help="Open config file and exit."
                                             " (GUI over terminal editor preferred and tried first.)", action="store_true")
        parser.add_argument('-H', '--headless',
                            help="Launch program in a headless mode which imposes --yes and --quiet. No menu is shown.",
                            action="store_true")
        parser.add_argument('--user-agent', help="Change user agent to be used when scraping a URL")
        parser.add_argument('-S', '--single-query', help="Consider the input as a single value, not a CSV.",
                            action="store_true")
        parser.add_argument('--single-detect', help="Consider the input as a single value, not a CSV,"
                                                    " and just print out possible types of the input."
                            , action="store_true")
        parser.add_argument('-C', '--csv-processing', help="Consider the input as a CSV, not a single.", action="store_true")
        parser.add_argument('--multiple-hostname-ip', help="Hostname can be resolved into multiple IP addresses."
                                                           " Duplicate row for each.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--multiple-cidr-ip', help="CIDR can be resolved into multiple IP addresses."
                                                       " Duplicate row for each.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--whois-ttl', help="How many seconds will a WHOIS answer cache will be considered fresh.",
                            type=int, metavar="SECONDS")
        parser.add_argument('--show-uml', help="R|Show UML of fields and methods and exit."
                                               " Methods that are currently disabled via flags or config file are grayed out."
                                               " * FLAGs:"
                                               "    * +1 to gray out disabled fields/methods" 
                                               "    * +2 to include usual field names",
                            type=int, const=1, nargs='?')
        parser.add_argument('--compute-preview', help="When adding new columns, show few first computed values.",
                            action=BlankTrue, nargs="?", metavar="blank/false")
        parser.add_argument('--delete-whois-cache', help="Delete convey's global WHOIS cache.", action="store_true")
        parser.add_argument('--version', help=f"Show the version number (which is currently {__version__}).", action="store_true")
        self.args = args = parser.parse_args()
        if args.config:
            self.edit_configuration()
            quit()
        for flag in ["output", "web", "whois", "nmap", "dig", "delimiter", "quote_char", "compute_preview", "user_agent",
                     "multiple_hostname_ip", "multiple_cidr_ip", "whois_ttl", "disable_external"]:
            if getattr(args, flag) is not None:
                Config.set(flag, getattr(args, flag))
        Types.refresh()  # reload Types for the second time so that the methods reflect CLI flags
        for module in ["whois", "web", "nmap", "dig"]:
            if Config.get(module, "FIELDS") is False:
                if module == "dig":
                    module = "dns"
                getattr(TypeGroup, module).disable()
        if args.debug:
            Config.set("debug", True)
        if args.headless:
            args.yes = True
            args.quiet = True
        Config.init_verbosity(args.yes, 30 if args.quiet else (10 if args.verbose else None))
        if args.show_uml is not None:
            print(Types.get_uml(args.show_uml))
            quit()
        if args.version:
            print(__version__)
            quit()
        Config.integrity_check()
        if args.header:
            Config.set("header", True)
        if args.no_header:
            Config.set("header", False)
        if args.csv_processing:
            Config.set("single_query", False)
        if args.single_query or args.single_detect:
            Config.set("single_query", True)
        Config.set("adding-new-fields", bool(new_fields))

        self.wrapper = Wrapper(args.file_or_input, args.file, args.input, args.fresh, args.delete_whois_cache)
        self.parser: Parser = self.wrapper.parser

        # load flags
        for flag in csv_flags:
            if args.__dict__[flag[0]]:
                self.parser.__dict__[flag[0]] = args.__dict__[flag[0]]
                logger.debug("{}: {}".format(flag[1], flag[0]))

        # prepare some columns to be removed
        if args.delete:
            for c in args.delete.split(","):
                try:
                    self.parser.fields[self.parser.identifier.get_column_i(c)].is_chosen = False
                except TypeError:
                    logger.error(f"Cannot identify COLUMN {c} to be deleted, "
                                 f"put there an exact column name or the numerical order starting with 1.")
                    quit()
            self.parser.is_processable = True

        # append new fields from CLI
        for add, task in new_fields:
            # FIELD,[COLUMN],[SOURCE_TYPE], ex: `netname 3|"IP address" ip|sourceip`
            task = [x for x in csv.reader([task])][0]
            custom = []
            target_type = task[0]
            m = re.search(r"(\w*)\[([^]]*)\]", target_type)
            if m:
                target_type = m.group(1)
                custom = [m.group(2)]
            try:
                target_type = types[types.index(target_type)]  # determine FIELD by exact name
            except ValueError:
                d = {t.name: distance(task[0], t.name) for t in Types.get_computable_types()}
                rather = min(d, key=d.get)
                logger.error(f"Unknown field '{task[0]}', did not you mean '{rather}'?")
                quit()
            source_field, source_type, c = self.parser.identifier.get_fitting_source(target_type, *task[1:])
            custom = c + custom
            self.source_new_column(target_type, add, source_field, source_type, custom)
            self.parser.is_processable = True

        if args.sort:
            self.parser.resort(list(csv.reader([args.sort]))[0])
            self.is_processable = True

        if args.split:
            self.parser.settings["split"] = self.parser.identifier.get_column_i(args.split)
            self.parser.is_processable = True

        # run single value check if the input is not a CSV file
        if args.single_detect:
            quit()
        if self.parser.is_single_query:
            res = self.parser.run_single_query(json=args.json)
            if res:
                print(res)
            quit()

        # start csirt-incident macro
        if args.csirt_incident and not self.parser.is_analyzed:
            self.parser.settings["split"] = len(self.parser.fields)
            self.source_new_column(Types.incident_contact, add=False)
            self.parser.is_processable = True
            self.process()
            self.parser.is_processable = False

        self.start_debugger = False

        if self.parser.is_processable and Config.get("yes"):
            self.process()

        if args.headless:
            self.close()

        # main menu
        while True:
            self.parser = self.wrapper.parser  # may be changed by reprocessing
            self.parser.informer.sout_info()

            if self.start_debugger:
                parser = self.parser
                print("\nDebugging mode, you may want to see `self.parser` variable:")
                self.start_debugger = False
                Config.get_debugger().set_trace()

            menu = Menu(title="Main menu - how the file should be processed?")
            menu.add("Pick or delete columns", self.choose_cols)
            menu.add("Add a column", self.add_column)
            menu.add("Unique filter", self.add_uniquing)
            menu.add("Value filter", self.add_filtering)
            menu.add("Split by a column", self.add_splitting)
            menu.add("Change CSV dialect", self.add_dialect)
            if self.parser.is_processable:
                menu.add("process", self.process, key="p", default=True)
            else:
                menu.add("process  (choose some actions)")
            if self.parser.is_analyzed and self.parser.is_split:
                if self.parser.is_processable:
                    menu.add("send (process first)")
                else:
                    menu.add("send", self.send_menu, key="s", default=True)
            else:
                menu.add("send (split first)")
            if self.parser.is_analyzed:
                menu.add("show all details", lambda: (self.parser.informer.sout_info(full=True), input()), key="d")
            else:
                menu.add("show all details (process first)")
            menu.add("Refresh...", self.refresh_menu, key="r")
            menu.add("Config...", self.config_menu, key="c")
            menu.add("exit", self.close, key="x")

            try:
                bindings = KeyBindings()
                session = PromptSession()

                def refresh():
                    session.app.exit(session.layout.current_buffer.text or "refresh")

                @bindings.add('right')  # select column
                def _(_):
                    self.parser.move_selection(1)
                    refresh()

                @bindings.add('left')  # select column
                def _(_):
                    self.parser.move_selection(-1)
                    refresh()

                @bindings.add('c-right')  # control-right to move the column
                def _(_):
                    self.parser.move_selection(1, True)
                    refresh()

                @bindings.add('c-left')  # control-left to move the column
                def _(_):
                    self.parser.move_selection(-1, True)
                    refresh()

                @bindings.add('delete')  # enter to toggle selected field
                def _(_):
                    [f.toggle_chosen() for f in self.parser.fields if f.is_selected]
                    refresh()

                options = {'key_bindings': bindings,
                           "bottom_toolbar": HTML("Ctrl+<b>←/→</b> arrows for column manipulation, <b>Delete</b> for exclusion"),
                           "style": bottom_plain_style
                           }
                menu.sout(session, options)
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                Config.get_debugger().set_trace()

    def send_menu(self):
        method = "smtp"
        if self.args.csirt_incident:
            if Config.get("otrs_enabled", "OTRS"):
                method = "otrs"
            else:
                print("You are using csirt-incident macro but otrs_enabled key is set to False in config.ini. Exiting.")
                quit()
        elif Config.get("otrs_enabled", "OTRS"):
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

        if method == "otrs":
            sender = MailSenderOtrs(self.parser)
            sender.assure_tokens()
            self.wrapper.save()
        else:
            sender = MailSenderSmtp(self.parser)

        info = ["In the next step, we connect to the server to send e-mails:"]
        cond1 = cond2 = False
        st = self.parser.stats
        if st["abuse_count"][0]:  # XX should be equal if just split by computed column! = self.csv.stats["ispCzFound"]:
            info.append(f" Template of a basic e-mail starts: \n\n{Contacts.mailDraft['local'].get_mail_preview()}\n")
            cond1 = True
        else:
            info.append(" No non-partner e-mail in the set.")
        if st["partner_count"][0]:  # self.csv.stats["countriesFound"]:
            info.append(f" Template of a partner e-mail starts: \n\n{Contacts.mailDraft['foreign'].get_mail_preview()}\n")
            cond2 = True
        else:
            info.append(" No partner e-mail in the set.")

        info.append("Do you really want to send e-mails now?")
        if Config.is_testing():
            info.append("\n\n\n*** TESTING MOD - mails will be sent to the address: {} ***"
                        "\n (For turning off testing mode set `testing = False` in config.ini.)".format(Config.get('testing_mail')))
        menu = Menu("\n".join(info), callbacks=False, fullscreen=True, skippable=False)
        if cond1 and cond2:
            menu.add("Send both partner and other e-mails ({}×)".format(st["abuse_count"][0] + st["partner_count"][0]), key="both")
        if cond2:
            menu.add("Send partner e-mails ({}×)".format(st["partner_count"][0]), key="partner")
        if cond1:
            menu.add("Send non-partner e-mails ({}×)".format(st["abuse_count"][0]), key="basic")
        if len(menu.menu) == 0:
            print("No e-mails in the set. Can't send. Continue to the main menu...")
            input()
            return

        option = menu.sout()

        self.parser.informer.sout_info()  # clear screen
        print("\n\n\n")

        if option is None:
            return

        # XX Terms are equal: abuse == local == other == basic  What should be the universal noun? Let's invent a single word :(
        if option == "both" or option == "basic":
            print("Sending basic e-mails...")
            if not sender.send_list(Attachment.get_basic(self.parser.attachments), Contacts.mailDraft["local"], method=method):
                print("Couldn't send all abuse mails. (Details in convey.log.)")
        if option == "both" or option == "partner":
            print("Sending to partner mails...")
            if not sender.send_list(Attachment.get_partner(self.parser.attachments), Contacts.mailDraft["foreign"], method=method):
                print("Couldn't send all partner mails. (Details in convey.log.)")

        input("\n\nPress enter to continue...")

    def process(self):
        self.parser.run_analysis()
        self.wrapper.save()

    def config_menu(self):
        def start_debugger():
            self.start_debugger = True

        menu = Menu(title="Config menu")
        menu.add("Edit configuration", self.edit_configuration)
        menu.add("Fetch whois for an IP", self.debug_ip)
        menu.add("Start debugger", start_debugger)
        menu.sout()

    @staticmethod
    def edit_configuration():
        print("Opening {}... restart Convey when done.".format(Config.path))
        Config.edit_configuration()

    def debug_ip(self):
        ip = input("Debugging whois – get IP: ")
        if ip:
            from .whois import Whois
            self.parser.reset_whois(assure_init=True)
            whois = Whois(ip.strip())
            print(whois.analyze())
            print(whois.whois_response)
        input()

    def refresh_menu(self):
        menu = Menu(title="What should be reprocessed?", fullscreen=True)
        menu.add("Rework whole file again", self.wrapper.clear)
        menu.add("Delete processing settings", self.parser.reset_settings)
        menu.add("Delete whois cache", self.parser.reset_whois)
        menu.add("Resolve unknown abuse-mails", self.parser.resolve_unknown)
        menu.add("Resolve invalid lines", self.parser.resolve_invalid)
        menu.add("Resolve queued lines", self.parser.resolve_queued)
        menu.add("Edit mail texts",
                 lambda: Contacts.mailDraft["local"].gui_edit() and Contacts.mailDraft["foreign"].gui_edit())
        menu.sout()

    def source_new_column(self, target_type, add=None, source_field: Field = None, source_type: Type = None, custom: list = None):
        """ We know what Field the new column should be of, now determine how we should extend it:
            Summarize what order has the source field and what type the source field should be considered alike.
                :type source_field: Field
                :type source_type: Type
                :type target_type: Type
                :type add: bool if the column should be added to the table; None ask
                :type custom: List
                :return Field
        """
        if custom is None:
            # default [] would be evaluated at the time the function is defined, multiple columns may share the same function
            custom = []
        dialog = Dialog(autowidgetsize=True)
        if not source_field or not source_type:
            print("\nWhat column we base {} on?".format(target_type))
            guesses = self.parser.identifier.get_fitting_source_i(target_type)
            source_col_i = pick_option(self.parser.get_fields_autodetection(),
                                       title="Searching source for " + str(target_type),
                                       guesses=guesses)
            source_field = self.parser.fields[source_col_i]
            source_type = self.parser.identifier.get_fitting_type(source_col_i, target_type, try_plaintext=True)
            if source_type is None:
                # ask how should be treated the column as, even it seems not valid
                # list all known methods to compute the desired new_field (e.g. for incident-contact it is: ip, hostname, ...)
                choices = [(k.name, k.description)
                           for k, _ in graph.dijkstra(target_type, ignore_private=True).items()]

                # if len(choices) == 1 and choices[0][0] == Types.plaintext:
                #     # if the only method is derivable from a plaintext, no worries that a method
                #     # converting the column type to "plaintext" is not defined; everything's plaintext
                #     source_type = Types.plaintext
                # el
                if choices:
                    s = ""
                    if self.parser.sample_parsed:
                        s = f"\n\nWhat type of value '{self.parser.sample_parsed[0][source_col_i]}' is?"
                    title = f"Choose the right method\n\nNo known method for making {target_type} from column {source_field} because the column type wasn't identified. How should I treat the column?{s}"
                    code, source_type = dialog.menu(title, choices=choices)
                    if code == "cancel":
                        return
                    source_type = getattr(Types, source_type)
                else:
                    dialog.msgbox("No known method for making {}. Raise your usecase as an issue at {}.".format(target_type,
                                                                                                                Config.PROJECT_SITE))
                    return
            clear()

        if not custom:
            if target_type.group == TypeGroup.custom:
                if target_type == Types.code:
                    print("What code should be executed? Change 'x'. Ex: x += \"append\";")
                    custom = Preview(source_field, source_type).code()
                elif target_type in [Types.reg, Types.reg_m, Types.reg_s]:
                    *custom, target_type = Preview(source_field, source_type, target_type).reg()
                elif target_type == Types.external:  # choose a file with a needed method
                    while True:
                        title = "What .py file should be used as custom source?"
                        try:
                            code, path = dialog.fselect(str(Path.cwd()), title=title)
                        except DialogError as e:
                            try:  # I do not know why, fselect stopped working and this helped
                                code, path = dialog.fselect(str(Path.cwd()), title=title,
                                                            height=max(get_terminal_size()[0] - 20, 10))
                            except DialogError as e:
                                input("Unable launch file dialog. Please post an issue to the Github! Hit any key...")
                                return

                        if code != "ok" or not path:
                            return
                        module = self.parser.identifier.get_module_from_path(path)
                        if module:
                            # inspect the .py file, extract methods and let the user choose one
                            code, method_name = dialog.menu(f"What method should be used in the file {path}?",
                                                            choices=[(x, "") for x in dir(module) if not x.startswith("_")])
                            if code == "cancel":
                                return

                            custom = path, method_name
                            break
                        else:
                            dialog.msgbox("The file {} does not exist or is not a valid .py file.".format(path))
                if not custom:
                    return
            path = graph.dijkstra(target_type, start=source_type, ignore_private=True)
            for i in range(len(path) - 1):
                m = methods[path[i], path[i + 1]]
                if isinstance(m, PickBase):
                    c = None
                    if Config.get("yes"):
                        pass
                    elif type(m) is PickMethod:
                        m: PickMethod
                        code, c = dialog.menu(f"Choose subtype", choices=m.get_options())
                        if code == "cancel":
                            return
                    elif type(m) is PickInput:
                        m: PickInput
                        c = Preview(source_field, source_type, target_type).pick_input(m)
                    custom.insert(0, c)
        if add is None:
            if dialog.yesno("New field added: {}\n\nDo you want to include this field as a new column?".format(
                    target_type)) == "ok":
                add = True

        f = Field(target_type, is_chosen=add,
                  source_field=source_field,
                  source_type=source_type,
                  new_custom=custom)
        self.parser.settings["add"].append(f)
        self.parser.add_field(append=f)
        return f

    def choose_cols(self):
        # XX possibility un/check all
        chosens = [(str(i + 1), str(f), f.is_chosen) for i, f in enumerate(self.parser.fields)]
        d = Dialog(autowidgetsize=True)
        ret, values = d.checklist("What fields should be included in the output file?", choices=chosens)
        if ret == "ok":
            for f in self.parser.fields:
                f.is_chosen = False
            for v in values:
                self.parser.fields[int(v) - 1].is_chosen = True
            self.parser.is_processable = True

    def select_col(self, col_name="", only_computables=False, add=None):
        fields = [] if only_computables else self.parser.get_fields_autodetection()
        for field in Types.get_computable_types():
            if field.from_message:
                s = field.from_message
            else:
                node_distance = graph.dijkstra(field, ignore_private=True)
                s = field.group.name + " " if field.group != TypeGroup.general else ""
                s += "from " + ", ".join([str(k) for k in node_distance][:3])
                if len(node_distance) > 3:
                    s += "..."
            fields.append((f"new {field}...", s))
        col_i = pick_option(fields, col_name)
        if only_computables or col_i >= len(self.parser.fields):
            target_type_i = col_i if only_computables else col_i - len(self.parser.fields)
            col_i = len(self.parser.fields)
            self.source_new_column(Types.get_computable_types()[target_type_i], add=add)
        return col_i

    def add_filtering(self):
        col_i = self.select_col("filter")
        val = ask("What value should the field have to keep the line?")
        self.parser.settings["filter"].append((col_i, val))
        self.parser.is_processable = True

    def add_splitting(self):
        self.parser.settings["split"] = self.select_col("splitting")
        self.parser.is_processable = True

    def add_dialect(self):
        dialect = type('', (), {})()
        for k, v in self.parser.dialect.__dict__.copy().items():
            setattr(dialect, k, v)
        # XX not ideal and mostly copies Parser.__init__ but this is a great start for a use case we haven't found yet
        # There might be a table with all the csv.dialect properties or so.
        while True:
            sys.stdout.write("What should be the delimiter: ")
            dialect.delimiter = input()
            if len(dialect.delimiter) != 1:
                print("Delimiter must be a 1-character string. Invent one (like ',').")
                continue
            sys.stdout.write("What should be the quoting char: ")
            dialect.quotechar = input()
            break
        dialect.quoting = csv.QUOTE_NONE if not dialect.quotechar else csv.QUOTE_MINIMAL

        self.parser.settings["dialect"] = dialect
        self.parser.is_processable = True

    def add_column(self):
        self.select_col("New column", only_computables=True, add=True)
        self.parser.is_processable = True

    def add_uniquing(self):
        col_i = self.select_col("unique")
        self.parser.settings["unique"].append(col_i)
        self.parser.is_processable = True

    def close(self):
        self.wrapper.save(last_chance=True)  # re-save cache file
        if not Config.get("yes"):
            print("Finished.")
        exit(0)
