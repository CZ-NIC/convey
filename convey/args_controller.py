import argparse
from typing import Any, List, Tuple
from sys import exit

from .aggregate import aggregate_functions_str
from .types import Types
from . import __version__

otrs_flags = [("otrs_id", "Ticket id"), ("otrs_num", "Ticket num"), ("otrs_cookie", "OTRSAgentInterface cookie"),
              ("otrs_token", "OTRS challenge token")]

new_fields: List[Tuple[bool, Any]] = []
"User has requested to compute these. Defined by tuples: add (whether to include the column in the result), field definition"


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


class ArgsController:
    def parse_args(self):
        epilog = "To launch a web service see README.md."
        column_help = "COLUMN is ID of the column (1, 2, 3...), position from the right (-1, ...)," \
                      " the exact column name, field type name or its usual name."
        parser = argparse.ArgumentParser(description="Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`. Convenable way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.", formatter_class=SmartFormatter,
                                         epilog=epilog)

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
                                                   " and just print out possible types of the input.", action="store_true")
        group.add_argument('-C', '--csv-processing', help="Consider the input as a CSV, not a single.",
                           action="store_true")

        group = parser.add_argument_group("CLI experience")
        group.add_argument('--debug', help="Development only: increases verbosity and gets the prompt in the case of an exception.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--crash-post-mortem', help="Get prompt if program crashes",
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
        group.add_argument('--version', help=f"Show the version number (which is currently {__version__}).",
                           action="store_true")

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
        group.add_argument('--delimiter-output', help="Output delimiter. For tab use either \\t or tab.",
                           metavar="DELIMITER")
        group.add_argument('--quote-char-output', help="Output quoting char", metavar="QUOTE_CHAR")
        group.add_argument('--header-output', help="If false, header is omitted when processing..",
                           action=BlankTrue, nargs="?", metavar="blank/false")

        group = parser.add_argument_group("Actions")
        group.add_argument('-d', '--delete',
                           help="Delete a column. You may comma separate multiple columns."
                           "\n " + column_help, metavar="COLUMN,[COLUMN]")
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
                                "\n\nComputable fields: " + "".join(
                                    "\n* " + t.doc() for t in Types.get_computable_types()) +
                           "\n\nThis flag May be used multiple times.",
                           action=FieldVisibleAppend, metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]")
        group.add_argument('-fe', '--field-excluded',
                           help="The same as field but its column will not be added to the output.",
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
        group.add_argument('--merge', help="R|Merge another file here. "
                           "\n " + column_help,
                           metavar="[REMOTE_PATH],[REMOTE_COLUMN],[LOCAL_COLUMN]")

        group = parser.add_argument_group("Enabling modules")
        group.add_argument('--whois',
                           help="R|Allowing Whois module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--nmap',
                           help="R|Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--dig',
                           help="R|Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--web', help="R|Allowing Web module: Leave blank for True or put true/on/1 or false/off/0."
                                         "\nWhen single value input contains a web page, we could fetch it and add"
                                         " status (HTTP code) and text fields. Text is just mere text, no tags, style,"
                                         " script, or head. ",
                           action=BlankTrue, nargs="?", metavar="blank/false")

        group = parser.add_argument_group("Field computing options")
        group.add_argument('--disable-external',
                           help="R|Disable external function registered in config.ini to be imported.",
                           action="store_true", default=False)
        group.add_argument('--json', help="When checking single value, prefer JSON output rather than text.",
                           action="store_true")
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
        group.add_argument('--whois-reprocessable-unknown',
                           help="Make unknown lines reprocessable while single file processing,"
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
        group.add_argument('--attach-paths-from-path-column', help="Files from a column of the Path type are added as e-mail attachments."
                           " Note for security reasons, files must not be symlinks, be readable for others `chmod o+r`, and be in the same directory."
                           " So that a crafted CSV would not pull up ~/.ssh or /etc/ files.",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--testing', help="Do not be afraid, e-mail messages will not be sent."
                                             " They will get forwarded to the testing e-mail"
                                             " (and e-mails in Cc will not be sent at all)",
                           action=BlankTrue, nargs="?", metavar="blank/false")
        group.add_argument('--subject',
                           help="E-mail subject."
                                " May be in BASE64 if started with \"data:text/plain;base64,\"", metavar="SUBJECT")
        group.add_argument('--body',
                           help="E-mail body text (or HTML)."
                                " May be in BASE64 if started with \"data:text/plain;base64,\"", metavar="TEXT")
        group.add_argument('--references',
                           help="E-mail references header (to send message within a thread)."
                                " If used, Bcc header with the `email_from_name` is added to the e-mail template.",
                           metavar="MESSAGE_ID")

        group = parser.add_argument_group("OTRS")
        for flag in otrs_flags:
            group.add_argument('--' + flag[0], help=flag[1])
        return parser
