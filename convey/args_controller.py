from typing import TYPE_CHECKING, Annotated, Any
from dataclasses import dataclass
from email.policy import default
from pathlib import Path
from typing import Annotated, Literal
import argparse
from dataclasses import dataclass, field
from dataclasses import field as field_orig
from typing import Annotated, Any, List, Optional, Tuple

from mininterface import run
from mininterface.tag.flag import BlankTrue, Blank
from tyro.conf import (FlagConversionOff, OmitArgPrefixes, Positional, Suppress,
                       UseAppendAction, arg)
from tyro.extras import get_parser as get_tyro_parser

from . import __version__
from .types import Types
from .config import config_dir, Config

otrs_flags = [("otrs_id", "Ticket id"), ("otrs_cookie", "OTRSAgentInterface cookie"),
              ("otrs_token", "OTRS challenge token")]

column_help = "COLUMN is ID of the column (1, 2, 3...), position from the right (-1, ...),"\
    " the exact column name, field type name or its usual name."


@dataclass
class IO:
    """Input/Output"""
    file_or_input: Positional[Optional[str | Path]] = None
    """File name to be parsed or input text. If nothing is given, user will input data through stdin."""

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

    default_action: int = 1
    """In the command line we specify a file name or input text (if file does not exist).
    If this parameter is omitted what should convey do?
    0 or empty ~ ask what to do
    1 ~ input from stdin
    2 ~ choose file name
    3 ~ input from stdin, then choose file name
    4 ~ choose file name, then input from stdin
    5 ~ allow only input text (unless flag --file present), even if parameter omitted
    6 ~ allow only file name (unless flag --input present), even if parameter omitted"""

    save_stdin_output: int = 1
    """
    When processing input text (not a file on disk), should we save the output to a file at program exit?
    4 or True ~ always save
    3 ~ if processed, save, otherwise do not save
    2 ~ always ask
    1 ~ if processed, ask, otherwise do not save
    0 or empty ~ do not save, just display
    This value gets overwritten if --output flag is used to specify the destination file.
    Note: We do not save single value input but only CSV STDIN input unless --output flag specified.
    Ex: $ convey example.com # single value input - no output unless --output flag
    Ex: $ convey < file.csv # CSV STDIN input - output savable"""

    # internal
    stdout: Suppress[bool | None] = None


@dataclass
class CLI:
    """CLI experience"""

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

    github_crash_submit: bool = True
    """ Submit crashes to GitHub """

    debug: BlankTrue = None
    """Development only: increases verbosity and gets the prompt in the case of an exception."""

    crash_post_mortem: BlankTrue = None
    """Get prompt if program crashes"""

    autoopen_editor: bool = False
    """ Open GUI editor with mail templates when analysis starts if splitting by a column """

    write_statistics: bool = False
    """ True if you want to write "statistics.txt" file next to the analyzed file, containing whois info, like:
     "Totally 17 of unique IPs; information for 5 countries (16 unique IPs), no contact for 1 countries without national/government CSIRT (1 unique IPs)"
     """


@dataclass
class Environment:
    """ Environment """

    # NOTE this works bad. In the past, it was possible to specify the mode too
    # but `Annotated[Blank[str|tuple[str,int]]]` does not work
    # Old:
    #    Mode: 1 terminal / 2 GUI / 3 try both (default)
    #    metavar=("FILE", "MODE")
    config: Annotated[Blank[str], arg(metavar="FILE")] = None
    """Open a config file and exit.
    File: config (default)/uwsgi/template/template_abroad
    """

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
    threads: Annotated[Blank[int] | Literal["auto"], arg(metavar="bool/auto/INT")] = "auto"
    """Set the thread processing number.

    Processing threads
    If set to threads = auto, threads will be used if convey think it is reasonable.
    If True, threads will be always used when processing.
    If number, that number of threads will be created.
    If False, 0, no thread used.
    """

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

    daemonize: bool = True
    """
    To start up convey could take around 0.75 s notably because of the external libraries (pint (0.2 s), bs4, requests).
    When doing a single query or a headless processing (no menu involved), we may reduce this time significantly (to cca 0.03 s) with a daemon that would parse our CLI arguments and if everything went ok print out the results.
    True ~ start the daemon at the end of the first convey call
    False ~ do not start the daemon automatically, just wait for `convey --daemon start` call.
    """


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

    nmap: BlankTrue = False
    """Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0."""

    dig: BlankTrue = None
    """Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0."""

    web: BlankTrue = None
    """Allowing Web module: Leave blank for True or put true/on/1 or false/off/0.
    When single value input contains a web page, we could fetch it and add status (HTTP code) and text fields.
    Text is just mere text, no tags, style, script, or head."""


@dataclass
class Web:
    # Fields 'code' and 'external' are considered unsafe, an attacker might take possession of your server.
    # With 'code', you can launch an arbitrary code on the machine.
    # With 'external', you can load any file from your machine and launch it.
    # These unsafe fields are not available via the web service.
    # You may specifically allow them here, ex: webservice_allow_unsafe_fields = code, external
    # Leave this field empty if you are not sure what are you doing!
    webservice_allow_unsafe_fields: list | None = None

    # Change user agent to be used when scraping a URL
    user_agent: str = ""

    # timeout used when scraping a URL
    timeout: int = 3


@dataclass
class FieldComputingOptions:
    """ Field computing options """

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

    multiple_nmap_ports: bool = False
    """ NMAP may generate a single string with ports and their services, ex:
            53/tcp  open  domain
            443/tcp open  https
    or may generate a list of open ports as integers, ex: [53, 443]
    False ~ take single string
    True ~ take all of them and duplicate whole row"""

    single_query_ignored_fields: list[str] = field(default_factory=lambda: ["html"])
    """ These fields shall not be computed when using single value check """

    compute_preview: BlankTrue = True
    """When adding new columns, show few first computed values."""

    external_fields: list = field(default_factory=list)
    """ You may define custom fields. Providing paths to the entrypoint Python files.
    Methods in these files will be taken as the names for the custom fields.

    Ex: `--external-fields /tmp/myfile.py /tmp/anotherfile.py`

    /tmp/myfile.py may have the contents: `def hello_world(val): return "hello world"`

    If you do not want to register all methods from the file, delimit the chosen method by a colon
    list chosen methods as new parameters while delimiting the method names by a colon.
    Ex: `--external-fields /tmp/myfile.py:hello_world`
    """

    # internal
    adding_new_fields: Suppress[bool] = False


@dataclass
class WhoisModule:
    """ WHOIS module options """
    ttl: Annotated[int, arg(metavar="SECONDS")] = 86400
    """How many seconds will a WHOIS answer cache will be considered fresh."""

    delete: BlankTrue = None
    """Delete convey's global WHOIS cache."""

    delete_unknown: BlankTrue = None
    """Delete unknown prefixes from convey's global WHOIS cache."""

    reprocessable_unknown: BlankTrue = None
    """Make unknown lines reprocessable while single file processing, do not leave unknown cells empty."""

    cache: BlankTrue = True
    """Use whois cache."""

    mirror: Optional[str] = None

    local_country: str = ""
    """ whois country code abbreviation (or their list) for local country(countries),
    other countries will be treated as "abroad" if listed in contacts_abroad
    This is important for incident-contact field; when generating e-mail messages, "abroad" e-mails use another template.
    * local country record uses whois abuse e-mail and template.eml
    * abroad (non-local) record try to get the csirtmail from contacts_abroad and uses template_abroad.csv
    * if the csirtmail is not available, it uses whois abuse e-mail and template_abroad.csv
    Ex: cz """

    lacnic_quota_skip_lines: bool = True
    """ LACNIC has rate limits that lets the script wait for 5 minutes.
     False ~ wait 5 minutes
     True ~ skip lines and try to resolve them afterwards
     """

    lacnic_quota_resolve_immediately: bool = True
    """
    True ~ resolve after processing other lines
    False ~ left skipped unprocessed (user have to launch reprocessing from menu)
    empty ~ ask
    """


@dataclass
class SendingOptions:
    """ Sending options """
    send: Annotated[Blank[str], arg(metavar="blank/smtp/otrs")] = ""
    """Automatically send e-mails when split."""

    send_test: Optional[Annotated[tuple[str, str], arg(metavar=("E-MAIL", "TEMPLATE_FILE"))]] = None
    """Display e-mail message that would be generated for given e-mail."""

    jinja: BlankTrue = True
    """Process e-mail messages with jinja2 templating system."""

    attach_files: BlankTrue = True
    """Split files are added as e-mail attachments."""

    attach_paths_from_path_column: BlankTrue = None
    """Files from a column of the Path type are added as e-mail attachments."""

    testing: BlankTrue = None
    """Do not be afraid, e-mail messages will not be sent. They will get forwarded to the testing e-mail."""

    testing_mail: str = "example@example.com"
    """ If testing is True, all e-mails will be forwarded to this testing e-mail. """

    subject: str = ""
    """E-mail subject. May be in BASE64 if started with "data:text/plain;base64,"."""

    body: str = ""
    """E-mail body text (or HTML). May be in BASE64 if started with "data:text/plain;base64,"."""

    references: Annotated[str, arg(metavar="MESSAGE_ID")] = ""
    """E-mail references header (to send message within a thread)."""

    mail_template: str = "template.eml"
    """ Template for basic e-mails. """

    mail_template_abroad: str = "template_abroad.eml"
    """ Template for abroad e-mails. """

    smtp_host: str = "localhost"
    email_from_name: str = '"My cool mail" <example@example.com>'

    contacts_cc: str = "contacts_cc.csv"
    # Filepath to local country team contacts. CSV file is in the format: domain,cc. (Mails can be delimited by semicolon.)

    contacts_abroad: str = "contacts_abroad.csv"
    # Filepath to foreign countries contacts. CSV file is in the format: country,email

    verify_ssl: bool = True
    """ Verify SSL host when sending e-mails. """


@dataclass
class OTRS:
    """ OTRS specific options. We may send all the e-mails by it. """

    enabled: bool = True

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
    io: OmitArgPrefixes[IO]
    cli: OmitArgPrefixes[CLI]
    env: OmitArgPrefixes[Environment]
    process: OmitArgPrefixes[Processing]
    csv: OmitArgPrefixes[CSVDialect]
    action: OmitArgPrefixes[Actions]
    mod: OmitArgPrefixes[EnablingModules]
    comp: OmitArgPrefixes[FieldComputingOptions]
    whois: WhoisModule
    sending: OmitArgPrefixes[SendingOptions]
    otrs: OTRS
    web: Web


def get_parser():
    return get_tyro_parser(FlagConversionOff[Env])


def parse_args(args=None):
    cd = Path(config_dir)
    config_file = cd / "convey.yaml"
    if not config_file.exists():
        config_file = False
    Config.config_file = config_file

    old_conf = cd / "config.ini"
    backup_conf = cd / "config.ini.old"
    if old_conf.exists() and not backup_conf.exists():
        if run().confirm(f"The config.ini is deprecated. Can I rename it to {old_conf}.old?"):
            old_conf.rename(backup_conf)
            print("Renamed. Run `convey --config` to modify the program defaults now (you may possibly want to migrate some options that you have previously set to config.ini).")
            quit()

    m = run(FlagConversionOff[Env],
            args=args,
            interface="tui",  # NOTE – we migrate to mininterface step by step
            add_verbose=False,
            description="Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`. Convenable way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.\n\nSee full docs at https://github.com/CZ-NIC/convey (ex. to launch a web service).",
            config_file=config_file
            )
    return m
