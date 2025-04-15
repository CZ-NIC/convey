from pathlib import Path
from typing import Annotated
import argparse
from dataclasses import dataclass
from dataclasses import field as field_orig
from typing import Annotated, Any, List, Optional, Tuple

from mininterface import run
from mininterface.interfaces import TextInterface
from mininterface.tag.flag import BlankTrue, Blank
from tyro.conf import (FlagConversionOff, OmitArgPrefixes, Positional,
                       UseAppendAction, arg)
from tyro.extras import get_parser as get_tyro_parser

from . import __version__
from .types import Types

otrs_flags = [("otrs_id", "Ticket id"), ("otrs_cookie", "OTRSAgentInterface cookie"),
              ("otrs_token", "OTRS challenge token")]

# NOTE config INI file should be converted into mininterface config. As now default CLI
# As we must have CLI > config > default. As argparse had no defaults, now with mininterface, we have
# CLI + default (if not set to None) > config. This might be confusing in the future.

new_fields: List[Tuple[bool, Any]] = []
"User has requested to compute these. Defined by tuples: add (whether to include the column in the result), field definition"


column_help = "COLUMN is ID of the column (1, 2, 3...), position from the right (-1, ...),"\
    " the exact column name, field type name or its usual name."


@dataclass
class IO:
    """Input/Output"""
    file_or_input: Positional[Optional[str | Path]] = None
    """File name to be parsed or input text. In nothing is given, user will input data through stdin."""

    file: Optional[str] = None
    """Parse file. (Instead of <file_or_input> parameter.)"""

    input: Annotated[Optional[str], arg(aliases=["-i"])] = ""
    """Parse input text. (Instead of <file_or_input> parameter.)"""

    output: Annotated[Blank[str], arg(metavar="blank|FILENAME")] = None
    """Save output to this file.
    If left blank, pass output to STDOUT.
    If omitted, a filename will be produced automatically.
    May be combined with --headless.
    """

    single_query: Annotated[BlankTrue, arg(aliases=["-S"])] = None
    """Consider the input as a single value, not a CSV."""

    single_detect: BlankTrue = None
    """Consider the input as a single value, not a CSV, and just print out possible types of the input."""

    csv_processing: Annotated[BlankTrue, arg(aliases=["-C"])] = None
    """Consider the input as a CSV, not a single."""


@dataclass
class CLI:
    """CLI experience"""

    debug: BlankTrue = None
    """Development only: increases verbosity and gets the prompt in the case of an exception."""

    crash_post_mortem: BlankTrue = None
    """Get prompt if program crashes"""

    verbose: Annotated[BlankTrue, arg(aliases=["-v"])] = None
    """Sets the verbosity to see DEBUG messages."""

    quiet: Annotated[BlankTrue, arg(aliases=["-q"])] = None
    """Sets the verbosity to see WARNINGs and ERRORs only.
    Prints out the least information possible.
    (Ex: if checking single value outputs a single word, prints out just that.)"""

    yes: Annotated[BlankTrue, arg(aliases=["-y"])] = None
    """Assume non-interactive mode and the default answer to questions.
    Will not send e-mails unless --send is on too."""

    headless: Annotated[BlankTrue, arg(aliases=["-H"])] = None
    """Launch program in a headless mode which imposes --yes and --quiet. No menu is shown."""

    compute_preview: BlankTrue = None
    """When adding new columns, show few first computed values."""


@dataclass
class Environment:
    """ Environment """
    config: Annotated[list[str], arg(metavar=("FILE", "MODE"))] = field_orig(default_factory=list)
    """Open a config file and exit.
    File: config (default)/uwsgi/template/template_abroad
    Mode: 1 terminal / 2 GUI / 3 try both (default)"""

    show_uml: Blank[int] = None
    """Show UML of fields and methods and exit.
    Methods that are currently disabled via flags or config file are grayed out.
     * FLAGs:
        * +1 to gray out disabled fields/methods
        * +2 to include usual field names"""

    get_autocompletion: BlankTrue = None
    """Get bash autocompletion."""

    version: Annotated[BlankTrue, arg(help=f"""Show the version number (which is currently {
        __version__}).""")] = None


@dataclass
class Processing:
    """ Processing """
    threads: Annotated[Blank[str], arg(metavar="blank/False/auto/INT")] = None
    """Set the thread processing number."""

    fresh: Annotated[BlankTrue, arg(aliases=["-F"])] = None
    """Do not attempt to load any previous settings / results.
    Do not load convey's global WHOIS cache.
    (But merge WHOIS results in there afterwards.)"""

    reprocess: Annotated[BlankTrue, arg(aliases=["-R"])] = None
    """Do not attempt to load any previous settings / results.
    But load convey's global WHOIS cache."""

    server: BlankTrue = None
    """Launches simple web server."""

    daemon: Annotated[Blank[str], arg(metavar="start/restart/stop/status/server")] = None
    """Run a UNIX socket daemon to speed up single query requests.
      * True – allow using the daemon
      * False – do not use the daemon
      * start – start the daemon and exit
      * stop – stop the daemon and exit
      * status – print out the status of the daemon
      * restart – restart the daemon and continue
      * server – run the server in current process (I.E. for debugging)"""


@dataclass
class CSVDialect:
    """ CSV dialect """

    delimiter: str = ""
    """Treat file as having this delimiter. For tab use either \\t or tab."""

    quote_char: str = ""
    """Treat file as having this quoting character."""

    header: BlankTrue = None
    """Treat file as having header."""

    delimiter_output: str = ""
    """Output delimiter. For tab use either \\t or tab."""

    quote_char_output: str = ""
    """Output quoting char."""

    header_output: BlankTrue = None
    """If false, header is omitted when processing."""


@dataclass
class Actions:
    """ Actions """
    delete: Annotated[str, arg(aliases=["-d"], metavar="COLUMN,[COLUMN]",
                               help="Delete a column. You may comma separate multiple columns. " + column_help)] = ""

    field: Annotated[UseAppendAction[list[str]], arg(aliases=["-f"],
                                                     metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]",
                                                     help="Compute field."
                                                     "\n* FIELD is a field type (see below) that may be appended with a [CUSTOM] in square brackets."
                                                     "\n* " + column_help +
                                                     "\n* SOURCE_TYPE is either field type or usual field type. "
                                                     "That way, you may specify processing method."
                                                     "\n* CUSTOM is any string dependent on the new FIELD type (if not provided, will be asked it for)."
                                                     "\nEx: --field tld[gTLD]  # would add TLD from probably a hostname, filtered by CUSTOM=gTLD"
                                                     "\nEx: --field netname,ip  # would add netname column from any IP column"
                                                     "\n    (Note the comma without space behind 'netname'.)"
                                                     "\n\nComputable fields: " + "".join(
        "\n* " + t.doc() for t in Types.get_computable_types()) + "\n\nThis flag May be used multiple times.")] = field_orig(default_factory=list)

    field_excluded: Annotated[UseAppendAction[list[str]], arg(aliases=["-fe"],
                                                              metavar="FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]")] = field_orig(default_factory=list)
    """The same as field but its column will not be added to the output."""

    type: Annotated[str, arg(aliases=["-t"], metavar="[TYPE],...")] = ""
    """Determine column type(s)."""

    split: Annotated[str, arg(metavar="COLUMN")] = ""
    """Split by this COLUMN."""

    sort: Annotated[str, arg(aliases=["-s"], metavar="COLUMN,...")] = ""
    """List of columns."""

    unique: Annotated[str, arg(aliases=["-u"], metavar="COLUMN,VALUE")] = ""
    """Cast unique filter on this COLUMN."""

    exclude_filter: Annotated[str, arg(aliases=["-ef"], metavar="COLUMN,VALUE")] = ""
    """Filter include this COLUMN by a VALUE."""

    include_filter: Annotated[str, arg(aliases=["-if"], metavar="COLUMN,VALUE")] = ""
    """Filter include this COLUMN by a VALUE."""

    aggregate: Annotated[str, arg(aliases=["-a"],
                                  metavar="[COLUMN, FUNCTION], ..., [group-by-COLUMN]")] = ""
    """Aggregate"""

    merge: Annotated[str, arg(metavar="[REMOTE_PATH],[REMOTE_COLUMN],[LOCAL_COLUMN]",
                              help="""Merge another file here. """ + column_help)] = ""


@dataclass
class EnablingModules:
    """ Enabling modules """
    whois: BlankTrue = None
    """Allowing Whois module: Leave blank for True or put true/on/1 or false/off/0."""

    nmap: BlankTrue = None
    """Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0."""

    dig: BlankTrue = None
    """Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0."""

    web: BlankTrue = None
    """Allowing Web module: Leave blank for True or put true/on/1 or false/off/0.
    When single value input contains a web page, we could fetch it and add status (HTTP code) and text fields.
    Text is just mere text, no tags, style, script, or head."""


@dataclass
class FieldComputingOptions:
    """ Field computing options """
    disable_external: BlankTrue = None
    """Disable external function registered in config.ini to be imported."""

    json: BlankTrue = None
    """When checking single value, prefer JSON output rather than text."""

    user_agent: str = ""
    """Change user agent to be used when scraping a URL."""

    multiple_hostname_ip: BlankTrue = None
    """Hostname can be resolved into multiple IP addresses. Duplicate row for each."""

    multiple_cidr_ip: BlankTrue = None
    """CIDR can be resolved into multiple IP addresses. Duplicate row for each."""

    web_timeout: Annotated[int, arg(metavar="SECONDS")] = 30
    """Timeout used when scraping a URL."""


@dataclass
class WhoisModule:
    """ WHOIS module options """
    whois_ttl: Annotated[int, arg(metavar="SECONDS")] = 86400
    """How many seconds will a WHOIS answer cache will be considered fresh."""

    whois_delete: BlankTrue = None
    """Delete convey's global WHOIS cache."""

    whois_delete_unknown: BlankTrue = None
    """Delete unknown prefixes from convey's global WHOIS cache."""

    whois_reprocessable_unknown: BlankTrue = None
    """Make unknown lines reprocessable while single file processing, do not leave unknown cells empty."""

    whois_cache: BlankTrue = None
    """Use whois cache."""


@dataclass
class SendingOptions:
    """ Sending options """
    send: Annotated[Blank[str], arg(metavar="blank/smtp/otrs")] = ""
    """Automatically send e-mails when split."""

    send_test: Optional[Annotated[tuple[str, str], arg(metavar=("E-MAIL", "TEMPLATE_FILE"))]] = None
    """Display e-mail message that would be generated for given e-mail."""

    jinja: BlankTrue = None
    """Process e-mail messages with jinja2 templating system."""

    attach_files: BlankTrue = None
    """Split files are added as e-mail attachments."""

    attach_paths_from_path_column: BlankTrue = None
    """Files from a column of the Path type are added as e-mail attachments."""

    testing: BlankTrue = None
    """Do not be afraid, e-mail messages will not be sent. They will get forwarded to the testing e-mail."""

    subject: str = ""
    """E-mail subject. May be in BASE64 if started with "data:text/plain;base64,"."""

    body: str = ""
    """E-mail body text (or HTML). May be in BASE64 if started with "data:text/plain;base64,"."""

    references: Annotated[str, arg(metavar="MESSAGE_ID")] = ""
    """E-mail references header (to send message within a thread)."""


@dataclass
class OTRS:
    """ OTRS specific options. We may send all the e-mails by it. """

    enabled: bool = False

    id: str = ""
    """Ticket id"""
    cookie: str = ""
    """OTRSAgentInterface cookie"""
    token: str = ""
    """OTRS challenge token"""

    host: str = "localhost"
    baseuri: str = "/otrs/index.pl"
    signkeyid: str = "PGP::Sign::-"


@dataclass
class Env:
    io: IO
    cli: CLI
    env: Environment
    process: Processing
    csv: CSVDialect
    action: Actions
    mod: EnablingModules
    comp: FieldComputingOptions
    whois: WhoisModule
    sending: SendingOptions
    otrs: OTRS


def get_parser():
    return get_tyro_parser(OmitArgPrefixes[FlagConversionOff[Env]])


def parse_args(args=None):
    m = run(OmitArgPrefixes[FlagConversionOff[Env]],
            args=args,
            interface="tui",  # NOTE – we migrate to mininterface step by step
            add_verbosity=False,
            description="Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`. Convenable way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.\n\nSee full docs at https://github.com/CZ-NIC/convey (ex. to launch a web service)."
            )
    [new_fields.append((True, values)) for values in m.env.action.field]
    [new_fields.append((False, values)) for values in m.env.action.field_excluded]
    return m
