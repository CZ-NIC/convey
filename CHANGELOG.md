# CHANGELOG

## 1.2 (unreleased)
- web service
- flags:
    - CHANGED: flag --file does not have anymore shortcut '-f'
    - both INI and CLI flags
        - delimiter flag
        - quote_char flag
        - new header / no-header flags
        - new output CLI flag
        - web, whois, nmap
        - new flag single_value_ignored_fields
        - flag --verbose, --quiet and config `verbosity`
        - flag compute_preview
        - user-agent
        - headless
    - CLI only flags
        - flag --yes for skipping dialogues
        - new CLI flag --config to open configuration
        - new CLI flag --show-fields to get UML overview
        - new flag --json
        - flags --field, --delete
        - flags --single-processing, --csv-processing
    - INI only flags
        - github_crash_submit
- fixes:
    - fix: new installation should now correctly place contacts files in .config
    - fix: refresh partner contact list e-mails when restart even if the file has been processed before
    - PyPi installer requirements fix
- Whois module 
    - won't throw error if host can't be resolved
    - huge refactoring (may lead to the behaviour when Country is taken from ARIN and Netname from AfriNIC if AfriNIC points us to ARIN that doesn't state Netname)
    - thousands of unique prefixes tried, many uses cases handled
    - naive database of country names, so that country may be guessed from non-standardised "address" field
    - some well known erroneous LIR responses are re-requested by their respective RIR
    - CIDR with host bits set ( = invalid network) translates to IP when asking whois (RIR would return 'invalid search key')
    - CIDR translated to an IP before asking whois
    - number of discovered prefixes should during processing displayed, as well as real whois server URLs
    - socket.gethostbyname non-existing domain exception caught
- processing:
    - logs in format "time IP src port > IP dst port" can be automatically transformed to CSV before processing
    - multiline base64 strings (seen in e-mails) may be input → automatically decoded
- internal
    - os replaced by pathlib
    - Config.getboolean merged to Config.get
    - Identifier (former CSVGuesses) is now object oriented, no more spaghetti
    - huge refactoring
    - fix: log files
- dialogs
    - able to automatically add/remove config file flags at program upgrade if allowed by user
    - when no known method is known to process a field, an example is given
    - when more than 9 options, you can use letters as shortcuts
    - main screen shows colorized result, preferable in the form of table if the terminal is wide enough
    - new 'code' field type for writing arbitrary code
    - when not in debug mode, a GitHub issue is filled out automatically at crash 
    - autoopen_editor opens when analysis starts but now only if splitting by a column
    - Config file startup integrity check: missing items and sections may be inserted automatically after an upgrade
    - column sorting/picking in the main menu
- types
    - reg type and its reg_m and reg_s


## 1.1 (2019-05-13)
- fix: do not reprocess file if moved to another location
- fix: empty file check
- fix: dialect ignored when generating a sample, whois inconsistency toughness
- fix: when config file is a symlink and is broken, do not confuse user with creating a new set of config file I.E. in .local/bin. Instead, demand mounting the symlink (or exit or recreate files).
- fix: whois fetching asn + netname again
- '/' is forbidden char in linux file names, when splitting by IP prefix, the char is replaced with a dash
- reading from stdin instead of a file
- when stdin input is a single value, auto-detect it, compute all possible results and quit (use case: inputting a base64 string will decode it, IP will produce all whois information table)
- new file_or_input config flag
- new save_stdin_output config flag
- Config file startup integrity check (you might have missing items since last upgrades)
- dropped default_dir and default_file config items & functionality. I doubt anyone has ever used that. These were to store the incidents directory for the case we did not provide an exact filename to treat when launching convey.
- Adding a column: if there is a single column we can source from, skip the dialog
- Since delimited, quote char and header guesses are mostly right, I stripped two dialog questions to a single one
- Main menu uses "←←←←←" symbol for hinting default value that is triggered when user hits Enter. When you select a processing action you don't have to write "p" for "process" anymore.
- CIDR type
- varying number of columns exception check
- when analyzing, show number of file descriptors currently being written
- unmaintained library lepl replaced by validate_email
- Wrong URL type

## 1.0.1 (2018-10-26)
- dropped Python 3.5 support
- python3.6 annotations
- it worked somehow but my colleague faced a strange issue in Whois module. Match object couldn't be called as a dictionary. I stepped out the change to see that Python3.5 support was dropped since 18.8., 51d7a90 , just after the first mature 1.0.0 release.
- logging while processing invalid rows write whole traceback
- file sizes in "show all details"
- csirtmail field fix, creating Config files: wrong path might be reported  …
- superfluous code removed
- better logging of invalid rows
- invalid lines fix, config menu, depickling error fix
- ARIN redirected whois support
- direct results from whois linux command
- fixed invalid line when different length #29
- invalid lines bugfixes


## 1.0.0 (2018-08-10)
- mature version
- Every important feature working as expected.


