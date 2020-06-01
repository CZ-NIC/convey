import argparse
import csv
import logging
import os
import re
import socket
import subprocess
import sys
from ast import literal_eval
from difflib import SequenceMatcher
from io import StringIO
from pathlib import Path
from sys import exit
from tempfile import NamedTemporaryFile

import pkg_resources
from colorama import init as colorama_init, Fore
from dialog import Dialog, DialogError
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import clear
from validate_email import validate_email

from .attachment import Contacts, Attachment
from .config import Config, get_terminal_size, console_handler, edit, get_path
from .decorators import PickBase, PickMethod, PickInput
from .dialogue import Cancelled, Debugged, Menu, pick_option, ask, ask_number, is_yes
from .field import Field
from .ipc import socket_file, recv, send, daemon_pid
from .mail_sender import MailSenderOtrs, MailSenderSmtp
from .parser import Parser
from .types import Types, TypeGroup, types, Type, graph, methods, Aggregate, get_module_from_path
from .wizzard import Preview, bottom_plain_style
from .wrapper import Wrapper

logger = logging.getLogger(__name__)
aggregate_functions = [f for f in Aggregate.__dict__ if not f.startswith("_")]
aggregate_functions_str = "".join("\n* " + f for f in aggregate_functions)

try:
    __version__ = pkg_resources.require("convey")[0].version
except pkg_resources.DistributionNotFound:
    __version__ = "unknown"


def send_ipc(pipe, msg, refresh_stdout):
    sys.stdout = sys.stderr = StringIO()  # creating a new one is faster than truncating the old
    console_handler.setStream(sys.stdout)
    sys.stdout_real.write(refresh_stdout)
    return send(pipe, msg)


def control_daemon(cmd, in_daemon=False):
    if cmd == "stop":
        Config.set("daemonize", False)  # daemon should not be started at the end
        print("Convey daemon stopping.")
    if cmd in ["restart", "start"]:
        if in_daemon:
            raise ConnectionResetError("restart.")
        else:
            Config.set("daemonize", True)
            control_daemon("kill")
        if cmd == "start":
            print("Convey daemon starting.")
            quit()
    if cmd in ["kill", "stop"]:
        if in_daemon:
            raise ConnectionResetError("stop.")
        else:
            pid = daemon_pid()
            if pid:
                subprocess.run(["kill", pid])
            if Path(socket_file).exists():
                Path(socket_file).unlink()
    if cmd == "stop":
        quit()
    if cmd == "status":
        if daemon_pid():
            print(f"Convey daemon is listening at socket {socket_file}")
        else:
            print("Convey daemon seems not to be running.")
        quit()
    if cmd is False:
        if in_daemon:
            raise ConnectionAbortedError("Daemon should not be used")
        else:
            Config.set("daemonize", False)
    if cmd == "server":
        if in_daemon:
            raise ConnectionAbortedError("The new process will become the new server.")
        else:
            control_daemon("kill")
    return cmd


class BlankTrue(argparse.Action):
    """ When left blank, this flag produces True. (Normal behaviour is to produce None which I use for not being set.)
        Return boolean for 0/false/off/1/true/on.
        Return a metavar value if metavar is a list.
        Else raises ValueError.
    """

    def __call__(self, _, namespace, values, option_string=None, allow_string=False):
        if values in [None, []]:  # blank argument with nargs="?" produces None, with ="*" produces []
            values = True
        elif values.lower() in ["0", "false", "off"]:
            values = False
        elif values.lower() in ["1", "true", "on"]:
            values = True
        elif not allow_string \
                and (type(self.metavar) is not list or values.lower() not in self.metavar) \
                and (len(self.metavar.split("/")) < 2 or values.lower() not in self.metavar.split("/")):
            print(f"Unrecognised value '{values}' of '{self.dest}'. Allowed values are 0/1/BLANK."
                             f" Should the value be considered a positional parameter, move '{self.dest}' behind.")
            exit()
        setattr(namespace, self.dest, values)


class BlankTrueString(BlankTrue):
    """ When left blank, this flag produces True.
        Return boolean for 0/false/off/1/true/on.
        Else returns input value or None if flag omitted.
    """

    def __call__(self, *args, **kwargs):
        super().__call__(*args, **kwargs, allow_string=True)


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
    def __init__(self, parser=None):
        self.parser = parser

    def run(self):
        if "--disable-external" in sys.argv:
            Config.set("disable_external", True)
        Types.refresh()  # load types so that we can print out computable types in the help text
        epilog = "To launch a web service see README.md."
        column_help = "COLUMN is ID of the column (1, 2, 3...), the exact column name, field type name or its usual name."
        parser = argparse.ArgumentParser(description="Data conversion swiss knife", formatter_class=SmartFormatter, epilog=epilog)

        group = parser.add_argument_group("Input/Output")
        group.add_argument('file_or_input', nargs='?', help="File name to be parsed or input text. "
                                                            "In nothing is given, user will input data through stdin.")
        group.add_argument('--file', help="Treat <file_or_input> parameter as a file, never as an input",
                           action="store_true")
        group.add_argument('-i', '--input', help="Treat <file_or_input> parameter as an input text, not a file name",
                           action="store_true")
        group.add_argument('-o', '--output', help="Save output to this file."
                                                  " If left blank, pass output to STDOUT."
                                                  " If omitted, a filename will be produced automatically."
                                                  " May be combined with --headless.",
                           action=BlankTrueString, nargs="?", metavar="blank/FILENAME")
        group.add_argument('-S', '--single-query', help="Consider the input as a single value, not a CSV.",
                           action="store_true")
        group.add_argument('--single-detect', help="Consider the input as a single value, not a CSV,"
                                                   " and just print out possible types of the input."
                           , action="store_true")
        group.add_argument('-C', '--csv-processing', help="Consider the input as a CSV, not a single.", action="store_true")

        group = parser.add_argument_group("CLI experience")
        group.add_argument('--debug', help="On error, enter a pdb session",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('-v', '--verbose', help="Sets the verbosity to see DEBUG messages.", action="store_true")
        group.add_argument('-q', '--quiet', help="R|Sets the verbosity to see WARNINGs and ERRORs only."
                                                 " Prints out the least information possible."
                                                 "\n(Ex: if checking single value outputs a single word, prints out just that.)",
                           action="store_true")
        group.add_argument('-y', '--yes', help="Assume non-interactive mode and the default answer to questions. "
                                               "Will not send e-mails unless --send is on too.",
                           action="store_true")
        group.add_argument('-H', '--headless',
                           help="Launch program in a headless mode which imposes --yes and --quiet. No menu is shown.",
                           action="store_true")
        group.add_argument('--compute-preview', help="When adding new columns, show few first computed values.",
                           action=BlankTrue, nargs="?", metavar="blank/false")

        parser.add_argument('--csirt-incident', action="store_true",
                            help="Macro that lets you split CSV by fetched incident-contact (whois abuse mail for local country"
                                 " or csirt contact for foreign countries) and send everything by OTRS."
                                 " You set local countries in config.ini, currently set to"
                                 f" '{Config.get('local_country', 'FIELDS')}'")

        group = parser.add_argument_group("Environment")
        group.add_argument('--config', help="R|Open a config file and exit."
                                            "\n File: config (default)/uwsgi/template/template_abroad"
                                            "\n Mode: 1 terminal / 2 GUI / 3 try both (default)",
                           nargs='*', metavar=("FILE", "MODE"))
        group.add_argument('--show-uml', help="R|Show UML of fields and methods and exit."
                                              " Methods that are currently disabled via flags or config file are grayed out."
                                              "\n * FLAGs:"
                                              "\n    * +1 to gray out disabled fields/methods"
                                              "\n    * +2 to include usual field names",
                           type=int, const=1, nargs='?')
        group.add_argument('--get-autocompletion', help="Get bash autocompletion.", action="store_true")
        group.add_argument('--version', help=f"Show the version number (which is currently {__version__}).", action="store_true")

        group = parser.add_argument_group("Processing")
        group.add_argument('--threads', help="Set the thread processing number.",
                           action=BlankTrueString, nargs="?", metavar="blank/false/auto/INT")
        group.add_argument('-F', '--fresh', help="Do not attempt to load any previous settings / results."
                                                 " Do not load convey's global WHOIS cache."
                                                 " (But merge WHOIS results in there afterwards.)", action="store_true")
        group.add_argument('-R', '--reprocess', help="Do not attempt to load any previous settings / results."
                                                     " But load convey's global WHOIS cache.", action="store_true")

        parser.add_argument('--server', help=f"Launches simple web server", action="store_true")
        parser.add_argument('--daemon', help=f"R|Run a UNIX socket daemon to speed up single query requests."
                                             "\n  * 1/true/on – allow using the daemon"
                                             "\n  * 0/false/off – do not use the daemon"
                                             "\n  * start – start the daemon and exit"
                                             "\n  * stop – stop the daemon and exit"
                                             "\n  * status – print out the status of the daemon"
                                             "\n  * restart – restart the daemon and continue"
                                             "\n  * server – run the server in current process (I.E. for debugging)",
                            action=BlankTrue, nargs="?", metavar="start/restart/stop/status/server")

        group = parser.add_argument_group("CSV dialect")
        group.add_argument('--delimiter', help="Treat file as having this delimiter. For tab use either \\t or tab.")
        group.add_argument('--quote-char', help="Treat file as having this quoting character")
        group.add_argument('--header', help="Treat file as having header", action="store_true")
        group.add_argument('--no-header', help="Treat file as not having header", action="store_true")
        group.add_argument('--delimiter-output', help="Output delimiter. For tab use either \\t or tab.", metavar="DELIMITER")
        group.add_argument('--quote-char-output', help="Output quoting char", metavar="QUOTE_CHAR")
        group.add_argument('--header-output', help="If false, header is omitted when processing..",
                           action=BlankTrue, nargs="?", metavar="blank/false")

        group = parser.add_argument_group("Actions")
        group.add_argument('-d', '--delete', help="Delete a column. You may comma separate multiple columns." + column_help,
                           metavar="COLUMN,[COLUMN]")
        group.add_argument('-f', '--field',
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
        group.add_argument('-fe', '--field-excluded', help="The same as field but its column will not be added to the output.",
                           action=FieldExcludedAppend, metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]")
        group.add_argument('-t', '--type', help="R|Determine column type(s)."
                                                "\nEx: --type country,,phone"
                                                " # 1st column is country, 2nd unspecified, 3rd is phone",
                           metavar="[TYPE],...")
        group.add_argument('--split', help="Split by this COLUMN.",
                           metavar="COLUMN")
        group.add_argument('-s', '--sort', help="List of columns.",
                           metavar="COLUMN,...")
        group.add_argument('-u', '--unique', help="Cast unique filter on this COLUMN.",
                           metavar="COLUMN,VALUE")
        group.add_argument('-ef', '--exclude-filter', help="Filter include this COLUMN by a VALUE.",
                           metavar="COLUMN,VALUE")
        group.add_argument('-if', '--include-filter', help="Filter include this COLUMN by a VALUE.",
                           metavar="COLUMN,VALUE")
        group.add_argument('-a', '--aggregate', help="R|Aggregate"
                                                     "\nEx: --aggregate 2,sum # will sum the second column"
                                                     "\nEx: --aggregate 2,sum,3,avg # will sum the second column and average the third"
                                                     "\nEx: --aggregate 2,sum,1 # will sum the second column grouped by the first"
                                                     "\nEx: --aggregate 1,count # will count the grouped items in the 1st column"
                                                     " (count will automatically set grouping column to the same)"
                                                     f"\n\nAvailable functions: {aggregate_functions_str}",
                           metavar="[COLUMN, FUNCTION], ..., [group-by-COLUMN]")

        group = parser.add_argument_group("Enabling modules")
        group.add_argument('--whois', help="R|Allowing Whois module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--nmap', help="R|Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--dig', help="R|Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--web', help="R|Allowing Web module: Leave blank for True or put true/on/1 or false/off/0."
                                         "\nWhen single value input contains a web page, we could fetch it and add"
                                         " status (HTTP code) and text fields. Text is just mere text, no tags, style,"
                                         " script, or head. ",
                           action=BlankTrue, nargs="?", metavar="blank/false")

        group = parser.add_argument_group("Field computing options")
        group.add_argument('--disable-external', help="R|Disable external function registered in config.ini to be imported.",
                           action="store_true", default=False)
        group.add_argument('--json', help="When checking single value, prefer JSON output rather than text.", action="store_true")
        group.add_argument('--user-agent', help="Change user agent to be used when scraping a URL")
        group.add_argument('--multiple-hostname-ip', help="Hostname can be resolved into multiple IP addresses."
                                                          " Duplicate row for each.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--multiple-cidr-ip', help="CIDR can be resolved into multiple IP addresses."
                                                      " Duplicate row for each.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--web-timeout', help="Timeout used when scraping a URL", type=int, metavar="SECONDS")

        group = parser.add_argument_group("WHOIS module options")
        group.add_argument('--whois-ttl', help="How many seconds will a WHOIS answer cache will be considered fresh.",
                           type=int, metavar="SECONDS")
        group.add_argument('--whois-delete', help="Delete convey's global WHOIS cache.", action="store_true")
        group.add_argument('--whois-delete-unknown', help="Delete unknown prefixes from convey's global WHOIS cache.",
                           action="store_true")
        group.add_argument('--whois-reprocessable-unknown', help="Make unknown lines reprocessable while single file processing,"
                                                                 " do not leave unknown cells empty.", action="store_true")
        group.add_argument('--whois-cache', help="Use whois cache.", action=BlankTrue, nargs="?", metavar="blank/false")

        group = parser.add_argument_group("Sending options")
        group.add_argument('--send', help="Automatically send e-mails when split.",
                           action=BlankTrueString, nargs="?", metavar="blank/smtp/otrs")
        group.add_argument('--send-test', help="Display e-mail message that would be generated for given e-mail.",
                           nargs=2, metavar=("E-MAIL", "TEMPLATE_FILE"))
        group.add_argument('--jinja', help="Process e-mail messages with jinja2 templating system",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--attach-files', help="Split files are added as e-mail attachments",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--testing', help="Do not be afraid, e-mail messages will not be sent."
                                             " They will get forwarded to the testing e-mail"
                                             " (and e-mails in Cc will not be sent at all)",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--subject', help="E-mail subject used if no template has been created yet."
                                             " May be in BASE64 if started with \"data:text/plain;base64,\"", metavar="SUBJECT")
        group.add_argument('--body', help="E-mail body text used if no template has been created yet."
                                          " May be in BASE64 if started with \"data:text/plain;base64,\"", metavar="TEXT")

        group = parser.add_argument_group("OTRS")
        csv_flags = [("otrs_id", "Ticket id"), ("otrs_num", "Ticket num"), ("otrs_cookie", "OTRS cookie"),
                     ("otrs_token", "OTRS token")]
        for flag in csv_flags:
            group.add_argument('--' + flag[0], help=flag[1])

        self.args = args = parser.parse_args()
        see_menu = True
        is_daemon = None
        if args.server:
            # XX not implemeneted: allow or disable fields via CLI by ex: `--web`
            print(f"Webserver configuration can be changed by `convey --config uwsgi`")
            print(get_path("uwsgi.ini").read_text())
            cmd = ["uwsgi", "--ini", get_path("uwsgi.ini"), "--wsgi-file", Path(Path(__file__).parent, "wsgi.py")]
            subprocess.run(cmd)
            quit()
        if args.daemon is not None and control_daemon(args.daemon) == "server":
            # XX :( after a thousand requests, we start to slow down. Memory leak must be somewhere
            is_daemon = True
            Config.set("daemonize", False)  # do not restart daemon when killed, there must be a reason this daemon was killed
            if Path(socket_file).exists():
                Path(socket_file).unlink()

            try:
                Config.init_verbosity(args.yes, 30 if args.quiet else (10 if args.verbose else None), True)
                Config.integrity_check()
            except ConnectionAbortedError:
                print("Config file integrity check failed. Launch convey normally to upgrade config parameters.")
                quit()

            print("Opening socket...")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_file)
            server.listen()
            sys.stdout_real = stdout = sys.stdout
            sys.stdout = sys.stderr = StringIO()
            if sys.version_info >= (3, 7):  # XX remove when dropped Python 3.6 support.
                # In 3.6, logging message from the daemon will not work.
                console_handler.setStream(sys.stdout)
            PromptSession.__init__ = lambda _, *ar, **kw: (_ for _ in ()).throw(ConnectionAbortedError('Prompt raised.'))

        if not is_daemon and not sys.stdin.isatty():  # piping to the process, no terminal
            try:
                sys.stdin = open("/dev/tty")
            except OSError:
                # this might work on Windows platform
                # Return "" for every input we got.
                PromptSession.prompt = lambda *ar, **kw: ""
            else:
                # Let's make a safe_prompt that is able to read from /dev/tty.
                # prompt_toolkit does not work with /dev/tty stdin
                # because it is a POSIX pipe only and it needs a "pseudo terminal pipe"
                # see https://github.com/prompt-toolkit/python-prompt-toolkit/issues/502
                # and menu does not work good
                def safe_prompt_2(*ar, **kw):
                    return input(ar[1] if len(ar) > 1 else kw["message"] if "message" in kw else "?")

                def safe_prompt(*ar, **kw):
                    print("This is just an emergency input mode because convey interactivity works bad when piping into.")
                    PromptSession.prompt = safe_prompt_2
                    return safe_prompt_2(*ar, **kw)

                PromptSession.prompt = safe_prompt

            see_menu = False
            args.yes = True

        colorama_init()
        while True:
            try:
                if is_daemon:
                    stdout.write("Listening...\n")
                    stdout.flush()
                    pipe, addr = server.accept()
                    msg = recv(pipe)
                    if not msg:
                        continue
                    stdout.write("Accepted: " + msg + "\n")
                    stdout.flush()
                    argv = literal_eval(msg)
                    if not argv:
                        raise ConnectionAbortedError("No arguments passed")
                    elif "--disable-external" in argv:
                        # Param "disable_external" is parsed before the help text normally
                        # but we are in daemon and the help text has already been prepared with externals.
                        raise ConnectionAbortedError("Disable externals might change the behaviour (help text, ...)")
                    try:
                        os.chdir(Path(argv[0]))
                    except OSError:
                        stdout.write("Invalid cwd\n")
                        continue
                    new_fields.clear()  # reset new fields so that they will not be remembered in another query
                    Config.cache.clear()
                    try:
                        self.args = args = parser.parse_args(argv[2:])  # the daemon has receives a new command
                    except SystemExit as e:
                        if not sys.stdout.getvalue():
                            # argparse sent usage to stderr, we do not have in in stdout instance will rerun the command
                            raise ConnectionAbortedError("Error in help text")
                        else:
                            # argparse put everything in stdout
                            quit()
                    see_menu = True
                    control_daemon(args.daemon, True)

                # this try-block may send the results to the client convey processes when a daemon is used
                if args.server:
                    raise ConnectionAbortedError("web server request")
                if args.config is not None:
                    edit(*args.config, restart_when_done=True)
                    quit()
                Config.set("stdout", args.output is True or None)
                if args.output is True:
                    # --output=True means no output will be produced in favour of stdout
                    args.output = None
                for flag in ["output", "web", "whois", "nmap", "dig", "delimiter", "quote_char", "compute_preview", "user_agent",
                             "multiple_hostname_ip", "multiple_cidr_ip", "web_timeout", "whois_ttl", "disable_external", "debug",
                             "testing", "attach_files", "jinja", "subject", "body",
                             "whois_delete_unknown", "whois_reprocessable_unknown", "whois_cache"]:
                    if getattr(args, flag) is not None:
                        Config.set(flag, getattr(args, flag))
                if args.headless or args.send_test:
                    args.yes = True
                    args.quiet = True
                    see_menu = False
                Config.init_verbosity(args.yes, 30 if args.quiet else (10 if args.verbose else None), is_daemon)
                if is_daemon:
                    logger.debug("This result is from the daemon.")
                Types.refresh()  # reload Types for the second time so that the methods reflect CLI flags
                TypeGroup.init()
                if args.show_uml is not None:
                    print(Types.get_uml(args.show_uml))
                    quit()
                if args.get_autocompletion:
                    print(self.get_autocompletion(parser))
                    quit()
                if args.version:
                    print(__version__)
                    quit()
                if not is_daemon:  # in daemon, we checked it earlier
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
                self.wrapper = Wrapper(args.file_or_input, args.file, args.input,
                                       args.type, args.fresh, args.reprocess,
                                       args.whois_delete)
                self.parser: Parser = self.wrapper.parser

                if args.threads is not None:
                    Config.set("threads", args.threads)

                def get_column_i(col, check):
                    self.parser.is_processable = True
                    return self.parser.identifier.get_column_i(col, check=check)

                # load flags
                for flag in csv_flags:
                    if args.__dict__[flag[0]]:
                        self.parser.__dict__[flag[0]] = args.__dict__[flag[0]]
                        logger.debug("{}: {}".format(flag[1], flag[0]))

                # prepare some columns to be removed
                if args.delete:
                    for c in args.delete.split(","):
                        self.parser.fields[get_column_i(c, "to be deleted")].is_chosen = False

                # append new fields from CLI
                for add, task in new_fields:
                    self.add_new_column(task, add)

                # run single value check if the input is not a CSV file
                if args.single_detect:
                    quit()
                if self.parser.is_single_query:
                    res = self.parser.run_single_query(json=args.json)
                    if res:
                        print(res)
                    quit()
                if is_daemon and see_menu:
                    # if we will need menu, daemon must stop here
                    send_ipc(pipe, chr(4), "Could not help with.\n")
                    continue

                if args.aggregate:
                    params = [x for x in csv.reader([args.aggregate])][0]
                    group = get_column_i(params.pop(), "to be grouped by") if len(params) % 2 else None
                    l = []
                    if not params:
                        l.append([Aggregate.count, group])
                    else:
                        for i in range(0, len(params), 2):
                            column, fn = params[i:i + 2]
                            fn = getattr(Aggregate, fn, None)
                            if not fn:
                                logger.error(f"Unknown aggregate function {fn}. Possible functions are: {aggregate_functions_str}")
                            column = get_column_i(column, "to be aggregated with")
                            l.append([fn, column])

                            if fn == Aggregate.count:
                                if group is None:
                                    group = column
                                elif column != group:
                                    logger.error(f"Count column {self.parser.fields[column].name} must be the same"
                                                 f" as the grouping column {self.parser.fields[group].name}")
                                    quit()
                    self.parser.settings["aggregate"] = group, l

                if args.sort:
                    self.parser.resort(list(csv.reader([args.sort]))[0])
                    self.parser.is_processable = True

                if args.split:
                    self.parser.settings["split"] = get_column_i(args.split, "to be split with")

                if args.include_filter:
                    col, val = [x for x in csv.reader([args.include_filter])][0]
                    self.add_filtering(True, get_column_i(col, "to be filtered with"), val)

                if args.exclude_filter:
                    col, val = [x for x in csv.reader([args.exclude_filter])][0]
                    self.add_filtering(False, get_column_i(col, "to be filtered with"), val)

                if args.unique:
                    self.add_uniquing(get_column_i(args.unique, "to be put a single time"))

                # set output dialect
                # Taken from config.ini or flags. If differs from the current one, parser marked as processable.
                self.parser.settings["dialect"] = dialect = type('', (), {})()
                for k, v in self.parser.dialect.__dict__.copy().items():
                    setattr(dialect, k, v)

                def change_dialect(s, s2):
                    # delimiter_output, quote_char_output
                    v = getattr(args, s + "_output") or Config.get(s + "_output", "CSV")
                    if v and v != getattr(dialect, s2):
                        v = v.replace(r"\t", "\t").replace("TAB", "\t").replace("tab", "\t")
                        if len(v) != 1:
                            print(f"Output {s2} has to be 1 character long: {v}")
                            quit()
                        setattr(dialect, s2, v)
                        self.parser.is_processable = True

                change_dialect("delimiter", "delimiter")
                change_dialect("quote_char", "quotechar")
                self.parser.settings["header"] = self.parser.has_header
                if self.parser.has_header and args.header_output is not None:
                    # If current parser has header, we may cut it off
                    # However, this is such a small change, we will not turning parser.is_processable on.
                    self.parser.settings["header"] = args.header_output

                # start csirt-incident macro XX deprecated
                if args.csirt_incident and not self.parser.is_analyzed:
                    self.parser.settings["split"] = len(self.parser.fields)
                    self.source_new_column(Types.incident_contact, add=False)
                    self.parser.is_processable = True
                    self.process()
                    self.parser.is_processable = False

                if self.parser.is_processable and Config.get("yes"):
                    self.process()

                if args.send and self.parser.is_analyzed and self.parser.is_split and not self.parser.is_processable:
                    # Config.set("yes", True)
                    see_menu = False
                    if args.send is not True:
                        self.send_menu(args.send, send_now=True)
                    else:
                        self.send_menu(send_now=True)
                if args.send_test:
                    c = Path(args.send_test[1]).read_text()
                    Path(Config.get_cache_dir(), Config.get("mail_template")).write_text(c)
                    Path(Config.get_cache_dir(), Config.get("mail_template_abroad")).write_text(c)
                    self.send_menu(test_attachment=args.send_test[0])

                if not see_menu:
                    self.close()
                if is_daemon:  # if in daemon, everything important has been already sent to STDOUT
                    quit()
            except ConnectionRefusedError as e:
                send_ipc(pipe, chr(3), f"Daemon has insufficient input: {e}\n")
                continue
            except ConnectionAbortedError as e:
                send_ipc(pipe, chr(4), "Daemon cannot help: " + (str(e) or "Probably a user dialog is needed.") + "\n")
                continue
            except ConnectionResetError as e:
                send_ipc(pipe, chr(17), f"Daemon killed: {e}\n")
                quit()
            except SystemExit:
                if is_daemon:
                    send_ipc(pipe, sys.stdout.getvalue(), "Result sent.\n")
                    continue  # wait for next IPC connection
                else:
                    raise
            break

        # main menu
        self.start_debugger = False
        session = None
        while True:
            if session and hasattr(session, "process"):
                # session.prompt keybinding asked processing
                # (we cannot reprocess from keybinding due to the deadlock if an input had been encountered,
                # no clear way to call a prompt within another prompt)
                self.process()
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
            menu.add("Filter", self.add_filter)
            menu.add("Split by a column", self.add_splitting)
            menu.add("Change CSV dialect", self.add_dialect)
            menu.add("Aggregate", self.add_aggregation)
            if self.parser.is_processable:
                menu.add("process", self.process, key="p", default=True)
            else:
                menu.add("process  (choose some actions)")
            if self.parser.is_analyzed and self.parser.is_split:
                if self.parser.is_processable:
                    menu.add("send (process first)")
                else:
                    menu.add("send...", self.send_menu, key="s", default=True)
            else:
                menu.add("send (split first)")
            if self.parser.is_analyzed:
                menu.add("show all details", lambda: (self.parser.informer.sout_info(full=True), input()), key="d")
            else:
                menu.add("show all details (process first)")
            menu.add("redo...", self.redo_menu, key="r")
            menu.add("config...", self.config_menu, key="c")
            menu.add("exit", self.close, key="x")

            try:
                bindings = KeyBindings()
                session = PromptSession()

                def refresh():
                    # exiting the app makes the main menu redraw again
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

                @bindings.add('escape', 'a')  # alt-a to aggregate
                def _(_):
                    for f in self.parser.fields:
                        if f.is_selected:
                            self.parser.settings["aggregate"] = f.col_i, [[Aggregate.count, f.col_i]]
                            self.parser.is_processable = True
                            session.process = True
                            break
                    refresh()

                # @bindings.add('escape', 'n')  # alt-n to rename header
                # def _(_):
                #     for f in self.parser.fields:
                #         if f.is_selected:
                #             break
                #     refresh()

                options = {'key_bindings': bindings,
                           "bottom_toolbar": HTML("Ctrl+<b>←/→</b> arrows for column manipulation,"
                                                  " <b>Delete</b> for exclusion,"
                                                  " <b>Alt+a</b> to aggregate count"),
                           "style": bottom_plain_style
                           }
                menu.sout(session, options)
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                Config.get_debugger().set_trace()

    def add_new_column(self, task, add=True):
        """
        :type task: str FIELD,[COLUMN],[SOURCE_TYPE], ex: `netname 3|"IP address" ip|sourceip`
        :type add: bool Add to the result.
        """
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
            d = {t.name: SequenceMatcher(None, task[0], t.name).ratio() for t in Types.get_computable_types()}
            rather = max(d, key=d.get)
            logger.error(f"Unknown field '{task[0]}', did not you mean '{rather}'?")
            quit()
        source_field, source_type, c = self.parser.identifier.get_fitting_source(target_type, *task[1:])
        custom = c + custom
        if not self.source_new_column(target_type, add, source_field, source_type, custom):
            print("Cancelled")
            quit()
        self.parser.is_processable = True
        return target_type

    def send_menu(self, method="smtp", test_attachment=None, send_now=False):
        # choose method SMTP/OTRS
        if self.args.csirt_incident:
            if Config.get("otrs_enabled", "OTRS"):
                method = "otrs"
            else:
                print("You are using csirt-incident macro but otrs_enabled key is set to False in config.ini. Exiting.")
                quit()
        elif Config.get("otrs_enabled", "OTRS") and self.args.otrs_id:
            method = "otrs"
        elif Config.get("otrs_enabled", "OTRS") and not Config.get("yes"):
            menu = Menu(title="What sending method do we want to use?", callbacks=False, fullscreen=True)
            menu.add("Send by SMTP...")
            menu.add("Send by OTRS...")
            o = menu.sout()
            clear()
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
        elif method == "smtp":
            sender = MailSenderSmtp(self.parser)
        else:
            raise RuntimeError("Unknown sending method: {method}")

        # sending dialog loop
        st = self.parser.stats
        limit = float("inf")
        limitable = lambda max_: f"limited to: {limit}/{max_}" if limit < max_ else max_

        while True:
            # clear screen
            info = []

            # display info
            def display_recipients(abroad, text):
                draft = "abroad" if abroad else "local"
                c = st[draft]
                if sum(c) > 0:
                    info.append(f"{text}")
                    if c[0]:
                        info.append(f"Recipient list ({c[0]}/{sum(c)}): "
                                    + ", ".join([o.mail for o in Attachment.get_all(abroad, False, 5, True)]))
                    if c[1]:
                        info.append(f"Already sent ({c[1]}/{sum(c)}): "
                                    + ", ".join([o.mail for o in Attachment.get_all(abroad, True, 5, True)]))
                    info.append(f"\n{Contacts.mail_draft[draft].get_mail_preview()}\n")
                    return True
                return False

            seen_local = display_recipients(False, "  *** E-mail template ***")
            seen_abroad = display_recipients(True, "  *** Abroad template ***")

            if Config.is_testing():
                info.append(f"\n\n\n*** TESTING MOD - mails will be sent to the address: {Config.get('testing_mail')} ***"
                            f"\n (For turning off testing mode set `testing = False` in config.ini.)")
            info.append("*" * 50)
            sum_ = st['local'][0] + st['abroad'][0]
            everything_sent = False
            if sum_ < 1:
                everything_sent = True
                info.append("No e-mail to be sent.")
            method_s = "OTRS" if method == "otrs" else Config.get("smtp_host", "SMTP")

            if test_attachment:
                option = "test"
            elif send_now:  # XConfig.get("yes")
                option = "1"
                send_now = False  # while-loop must not re-send
            else:
                clear()
                menu = Menu("\n".join(info), callbacks=False, fullscreen=False, skippable=False)

                if seen_local or seen_abroad:
                    menu.add(f"Send all e-mails ({limitable(sum_)}) via {method_s}", key="1")
                if seen_local and seen_abroad:
                    menu.add(f"Send local e-mails ({limitable(st['local'][0])})", key="2")
                    menu.add(f"Send abroad e-mails ({limitable(st['abroad'][0])})", key="3")
                if len(menu.menu) == 0:
                    print("No e-mails in the set. Cannot send.")

                t = f" from {limit}" if limit < float("inf") else ""
                menu.add(f"Limit sending amount{t} to...", key="l")
                menu.add("Edit template...", key="e")
                menu.add("Choose recipients...", key="r")
                menu.add("Send test e-mail...", key="t", default=not everything_sent)
                menu.add("Print e-mails to a file...", key="p")
                menu.add(f"Attach files (toggle): {Config.get('attach_files', 'SMTP', get=bool)}", key="a")
                menu.add("Go back...", key="x", default=everything_sent)

                option = menu.sout()
                if option is None:
                    return

            # sending menu processing - all, abuse and abroad e-mails
            limit_csirtmails_when_all = limit - st['local'][0]
            if option in ("1", "2") and st['local'][0] > 0:
                print("Sending e-mails...")
                sender.send_list(Attachment.get_all(False, False, limit))
            if option in ("1", "3") and st['abroad'][0] > 0:
                # decrease the limit by the number of e-mails that was just send in basic list
                l = {"1": limit_csirtmails_when_all, "3": limit}[option]
                if l < 1:
                    print("Cannot send abroad e-mails due to limit.")
                else:
                    print("Sending to abroad e-mails...")
                    sender.send_list(Attachment.get_all(True, False, l))
            if option in ["1", "2", "3"]:
                if Config.get("yes"):
                    return
                self.wrapper.save()  # save what message has been sent right now
                input("\n\nPress Enter to continue...")
                continue

            # other menu options
            if option == "e":
                local, abroad = st['local'][0], st['abroad'][0]
                if local:
                    Contacts.mail_draft["local"].edit_text()
                if abroad:
                    Contacts.mail_draft["abroad"].edit_text()
                if not (local or abroad):
                    print("Neither local nor abroad e-mails are to be sent, no editor was opened.")
            elif option == "l":
                limit = ask_number("How many e-mails should be send at once: ")
                if limit < 0:
                    limit = float("inf")
            elif option == "a":
                Config.set("attach_files", not Config.get('attach_files', 'SMTP', get=bool))
            elif option in ["test", "t", "r", "p"]:
                attachments = sorted(list(Attachment.get_all()), key=lambda x: x.mail.lower())
                if option == "p":
                    with NamedTemporaryFile(mode="w+") as f:
                        try:
                            print(f"The messages are being temporarily generated to the file (stop by Ctrl+C): {f.name}")
                            for attachment in attachments:
                                print(".", end="")
                                sys.stdout.flush()
                                f.write(str(attachment.get_envelope()))
                            f.file.flush()
                            print("Done!")
                        except KeyboardInterrupt:
                            print("Interrupted!")
                        finally:
                            edit(Path(f.name), blocking=True)
                elif option == "test":
                    choices = [o for o in attachments if o.mail == test_attachment]
                    if len(choices) != 1:
                        print(f"Invalid testing attachment {test_attachment}")
                    else:
                        print(choices[0].get_envelope().preview())
                    return
                elif option == "t":
                    # Choose an attachment
                    choices = [(o.mail, "") for o in attachments]
                    try:
                        attachment = attachments[pick_option(choices, f"What attachment should serve as a test?")]
                    except Cancelled:
                        continue
                    clear()

                    # Display generated attachment
                    print(attachment.get_envelope().preview())

                    # Define testing e-mail
                    t = Config.get("testing_mail")
                    t = f" – type in or hit Enter to use {t}" if t else ""
                    try:
                        t = ask(Fore.YELLOW + f"Testing e-mail address to be sent to{t} (Ctrl+C to go back): " + Fore.RESET).strip()
                    except KeyboardInterrupt:
                        continue
                    if not t:
                        t = Config.get("testing_mail")
                    if not t:
                        input("No address written. Hit Enter...")
                        continue

                    # Send testing e-mail
                    old_testing, old_sent, attachment.sent = Config.get('testing'), attachment.sent, None
                    Config.set('testing', True)
                    Config.set('testing_mail', t)
                    sender.send_list([attachment])
                    Config.set('testing', old_testing)
                    input("\n\nTesting completed. Press Enter to continue...")
                    attachment.sent = old_sent
                elif option == "r":
                    # choose recipient list
                    choices = [(o.mail, o.get_draft_name() + ("" if validate_email(o.mail) else " (invalid)"), not o.sent)
                               for o in attachments]
                    code, tags = Dialog(autowidgetsize=True).checklist("Toggle e-mails to be send", choices=choices)
                    if code != 'ok':
                        continue
                    for attachment in attachments:
                        # XX if the same address is going to receive both local and abroad template e-mail,
                        #   this will change the status of its both e-mails.
                        #   In the future, we'd like to have another checklist engine where item references can be passed directly.
                        attachment.sent = attachment.mail not in tags
                    print("Changed!")
            elif option == "x":
                return

    def process(self):
        self.parser.run_analysis()
        self.wrapper.save()

    def config_menu(self):
        def start_debugger():
            self.start_debugger = True

        menu = Menu(title="Config menu")
        menu.add("Edit configuration", lambda: edit("config", 3, restart_when_done=True, blocking=True))
        menu.add("Edit default e-mail template", lambda: edit("template", blocking=True))
        menu.add("Edit default abroad e-mail template", lambda: edit("template_abroad", blocking=True))
        menu.add("Edit uwsgi configuration", lambda: edit("uwsgi"))
        menu.add("Fetch whois for an IP", self.debug_ip)
        menu.add("Start debugger", start_debugger)
        menu.sout()

    def debug_ip(self):
        ip = input("Debugging whois – get IP: ")
        if ip:
            from .whois import Whois
            self.parser.reset_whois(assure_init=True)
            whois = Whois(ip.strip())
            print(whois.analyze())
            print(whois.whois_response)
        input()

    def choose_settings(self):
        """ Remove some of the processing settings """
        actions = []  # description
        discard = []  # lambda to remove the setting
        st = self.parser.settings
        fields = self.parser.fields

        def add_list(labels):
            actions.extend(labels)
            discard.extend((st[type_].pop, i) for i, _ in enumerate(items))

        # Build processing settings list
        for type_, items in st.items():
            if not items and items is not 0:
                continue
            if type_ == "split":
                actions.append(f"split by {fields[items]}")
                discard.append((st.pop, "split"))
            elif type_ == "add":
                add_list(f"add {f} (from {str(f.source_field)})" for f in items)
            elif type_ == "filter":
                add_list(f"filter {fields[f].name} {'' if include else '!'}= {val}" for include, f, val in items)
            elif type_ == "unique":
                add_list(f"unique {fields[f].name}" for f in items)
            elif type_ == "aggregate":
                actions.extend(f"{fn.__name__}({fields[col].name})" for fn, col in items[1])
                discard.extend((st[type_][1].pop, i) for i, _ in enumerate(items[1]))
                self.parser.aggregation.clear()  # remove possible aggregation results

        if not actions:
            input("No processing settings found. Hit Enter...")
            return

        # Build dialog
        choices = [(str(i + 1), v, False) for i, v in enumerate(actions)]
        ret, values = Dialog(autowidgetsize=True).checklist("What processing settings should be discarded?", choices=choices)
        if ret == "ok":
            # these processing settings should be removed
            for v in values[::-1]:  # we reverse the list, we need to pop bigger indices first without shifting lower indices
                fn, v = discard[int(v) - 1]
                fn(v)
            if st["aggregate"] and not st["aggregate"][1]:
                # when removing an aggregation settings, we check if it was the last one to get rid of the setting altogether
                del st["aggregate"]

    def redo_menu(self):
        menu = Menu(title="What should be reprocessed?", fullscreen=True)
        menu.add("Delete some processing settings", self.choose_settings)
        menu.add("Delete all processing settings", self.parser.reset_settings)
        menu.add("Delete whois cache", self.parser.reset_whois)
        # XX note that aggregation generators were deleted (jsonpickling) → aggregation count will reset when re-resolving
        # See comment in the Aggregation class, concerning generator serialization.
        menu.add("Resolve unknown abuse-mails", self.parser.resolve_unknown)
        menu.add("Resolve invalid lines", self.parser.resolve_invalid)
        menu.add("Resolve queued lines", self.parser.resolve_queued)
        menu.add("Rework whole file again", self.wrapper.clear)
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
            try:
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
                            module = get_module_from_path(path)
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
            except Cancelled:
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

    def select_col(self, dialog_title="", only_computables=False, add=None, prepended_field=None):
        """ Starts dialog where user has to choose a column.
            If cancelled, we return to main menu automatically.
            :type prepended_field: tuple (field_name, description) If present, this field is prepended. If chosen, you receive -1.
            :rtype: int Column
        """
        # add existing fields
        fields = [] if only_computables else self.parser.get_fields_autodetection()

        # add computable field types
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

        # add special prepended field
        if prepended_field:
            fields.insert(0, prepended_field)

        # launch dialog
        col_i = pick_option(fields, dialog_title)

        # convert returned int col_i to match an existing or new column
        if prepended_field:
            col_i -= 1
            if col_i == -1:
                return col_i
        if only_computables or col_i >= len(self.parser.fields):
            target_type_i = col_i if only_computables else col_i - len(self.parser.fields)
            col_i = len(self.parser.fields)
            self.source_new_column(Types.get_computable_types()[target_type_i], add=add)
        return col_i

    def add_filter(self):
        menu = Menu(title="Choose a filter")
        menu.add("Unique filter", self.add_uniquing)
        menu.add("Include filter", self.add_filtering)
        menu.add("Exclude filter", lambda: self.add_filtering(False))
        menu.sout()

    def add_filtering(self, include=True, col_i=None, val=None):
        if col_i is None:
            col_i = self.select_col("filter")
        if val is None:
            s = "" if include else "not "
            val = ask(f"What value must {s}the field have to keep the line?")
        self.parser.settings["filter"].append((include, col_i, val))
        self.parser.is_processable = True

    def add_splitting(self):
        self.parser.settings["split"] = self.select_col("splitting")
        self.parser.is_processable = True

    def add_aggregation(self):
        # choose what column we want

        menu = Menu("Choose aggregate function", callbacks=False, fullscreen=True)
        for f in aggregate_functions:
            menu.add(f)
        option = menu.sout()
        if not option:
            return
        fn = getattr(Aggregate, aggregate_functions[int(option) - 1])
        col_i = self.select_col("aggregation")

        if self.parser.settings["aggregate"]:
            group, fns = self.parser.settings["aggregate"]
        else:
            group, fns = None, []

        if group is None:
            if fn == Aggregate.count:
                group = col_i
            else:
                group = self.select_col("group by", prepended_field=("no grouping", "aggregate whole column"))
                if group == -1:
                    group = None
        fns.append([fn, col_i])
        self.parser.settings["aggregate"] = group, fns
        self.parser.is_processable = True

    def add_dialect(self):
        # XX not ideal and mostly copies Parser.__init__
        # XX There might be a table with all the csv.dialect properties or so.
        dialect = self.parser.settings["dialect"]
        while True:
            s = "What is delimiter " + (f"(default '{dialect.delimiter}')" if dialect.delimiter else "") + ": "
            dialect.delimiter = input(s) or dialect.delimiter
            if len(dialect.delimiter) != 1:
                print("Delimiter must be a 1-character string. Invent one (like ',').")
                continue
            s = "What is quoting char " + (f"(default '{dialect.quotechar}')" if dialect.quotechar else "") + ": "
            dialect.quotechar = input(s) or dialect.quotechar
            break
        dialect.quoting = csv.QUOTE_NONE if not dialect.quotechar else csv.QUOTE_MINIMAL

        if self.parser.has_header:
            if self.parser.settings['header'] is False:
                s = f"Should we remove header? "
            else:
                s = f"Should we include header? "
            if not is_yes(s):
                self.parser.settings["header"] = not self.parser.settings["header"]

        self.parser.is_processable = True

    def add_column(self):
        self.select_col("New column", only_computables=True, add=True)
        self.parser.is_processable = True

    def add_uniquing(self, col_i=None):
        if col_i is None:
            col_i = self.select_col("unique")
        self.parser.settings["unique"].append(col_i)
        self.parser.is_processable = True

    def close(self):
        self.wrapper.save(last_chance=True)  # re-save cache file
        if not Config.get("yes"):
            if not Config.is_quiet():
                # Build processing settings list
                l = []
                st = self.parser.settings
                fields = self.parser.fields

                for type_, items in st.items():
                    # XXX code does not return its custom part
                    if not items and items is not 0:
                        continue
                    if type_ == "split":
                        l.append(f"--split {fields[items]}")
                    elif type_ == "add":
                        l.extend(f"--field {f},{str(f.source_field)}" for f in items)
                    elif type_ == "filter":
                        l.extend(f"--{'include' if include else 'exclude'}-filter {fields[f].name},{val}"
                                 for include, f, val in items)
                    elif type_ == "unique":
                        l.extend(f"--unique {fields[f].name}" for f in items)
                    elif type_ == "aggregate":
                        # XXX does not work well - at least, they are printed out opposite way
                        l.append(f"--aggregate {items[0]}," + ",".join(f"{fn.__name__},{fields[col].name}" for fn, col in items[1]))
                if l:
                    print(f" Settings cached:\n convey {self.parser.source_file} " + " ".join(l) + "\n")

            print("Finished.")
        exit(0)

    def get_autocompletion(self, parser):
        actions = []
        for action in parser._actions:
            actions.extend(action.option_strings)

        a = ["#!/usr/bin/env bash",
             "# bash completion for convey",
             ""
             '_convey()',
             '{',
             '  local cur',
             '  local cmd',
             '',
             '  cur=${COMP_WORDS[$COMP_CWORD]}',
             '  prev="${COMP_WORDS[COMP_CWORD-1]}";',
             '  cmd=( ${COMP_WORDS[@]} )',
             '',
             '  if [[ "$prev" == -f ]] || [[ "$prev" == --field ]] ||' +
             '  [[ "$prev" == -fe ]] || [[ "$prev" == --field-excluded ]]; then',
             f'        COMPREPLY=( $( compgen -W "{" ".join(t.name for t in Types.get_computable_types())}"  -- "$cur" ) )',
             '        return 0',
             '    fi',
             '',
             '  if [[ "$prev" == -a ]] || [[ "$prev" == --aggregate ]]; then',
             '    param=(${cur//,/ })',
             f'        COMPREPLY=( $( compgen -W "{" ".join("${param[0]}," + s for s in aggregate_functions)}"  -- "$cur" ) )',
             '        return 0',
             '    fi',
             '',
             '  if [[ "$cur" == -* ]]; then',
             f'    COMPREPLY=( $( compgen -W "{" ".join(actions)}" -- $cur ) )',
             '    return 0',
             '  fi',
             '}',
             '',
             'complete -F _convey -o default convey']
        return "\n".join(a)
