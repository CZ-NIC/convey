# CHANGELOG

## 1.5.0 (2025-05-30)
* CHANGED:
    * config.ini file retired
        * Migrate all custom options to YAML. Just run `convey --config` and put there only CLI flags that need to be changed.
    * `file-or-input` must be the first argument, or specified by `--file PATH` or `--input STR`.
    * CLI bool flags must be either `blank|True|False`. No more support for `on/off`, `1/0`, or case insensitivity.
    * CLI flags:
        * renamed (grouped by sections), check `--help`
            * removed `--no-header` in favour to `--header False`;
        * Config file options ported to the same-named CLI flags. (With the exception of `file-or-input` renamed to `default_action` due to the name clash.)
    * removed `--disable-externals` in favour of `--external-fields (blank)`
    * nmap is off by default (turn on with `--nmap`)
* Brand new CLI / UI by [mininterface](https://github.com/CZ-NIC/mininterface)
* removed the dialog dependency

## 1.4.7 (2025-01-21)
* drop Python3.9 support
* fix: Setting field type by `--type` suppresses the auto-detection.
* fix: split by CIDR
* fix: single value regex preview wizzard
* registrar_abusemail field

## 1.4.4 (2023-05-26)
* fix: OTRS sending with no attachment forwarded

## 1.4.3 (2023-05-05)
* fix: OTRS sending removes the attachment we have been split from (avoid duplicity)

## 1.4.2 (2023-01-19)
* files merging
* fix: OTRS multiple files sending
* fix: piping into program while specifiying fields works
* fix: single-query processing
* fix: support for XLSX files
* testing directly through module import possible
* drop Python3.6 support

## 1.4.1 (2023-01-06)
* types
    * path
* flags
    * --attach_paths_from_path_column
    * --crash-post-mortem

## 1.4 (2023-01-05)
* CHANGED:
    * --delete-whois-cache renamed to --whois-delete
    * template function `{{ print_attachment() }}` renamed to `{{ attachment() }}`
    * aggregated results will provide valid CSV, not fancy but hardly parsable table
    * sending works with SMTP or OTRS6 (OTRS3 is deprecated now)
    * removed --csirt-incident macro (easily replaced by other CLI flags)
* webservice
    * uwsgi file (HTTPS support)
    * clear=web parameter
* able to parse pandoc simple table format (headers underlined with ---------) and a lot of spaces between columns
* local_country is empty by default (you do not have to be a national CSIRT to use this program)
* program help flags grouped
* types
    * csirt_contact now may be derived from tld
    * web module now ignores invalid HTTPS certificates
    * form_names prints out more information about tags without `name` attribute
    * base64 no more limited to UTF-8, better detection
    * phone formats not confused with dates
    * ip -> url conversion generates a proper PTR hostname
    * wrong_url protocol case insensitive (accepts "hXXp")
    * Unix time is reasonably recognized as a timestamp
    * cc_contact converts abusemail to value given by contacts_cc.csv
* dialog
    * edit default e-mail templates from config submenu
    * delimiter now may contain tab character, input by "\t" or "tab"
    * show current SMTP server in the send submenu
    * --config now can edit any config file, not only config.ini
    * print out settings so that it can be reprocessed via bash command (currently experimental, on file exit)
    * displays what is happening if WHOIS cache is being loaded/saved longer than 1 s
    * atomic thread safe information printing – no more blinking and shuffled info; few records stay on the screen when information refresh
    * statistics info reworded
    * reset menu renamed to redo
    * sending menu – testing is the default option (you do not want to send all by mistake too early) and attachments are sorted alphabetically
    * positional vs keyword arguments order resilience
* flags
    * --whois-delete-unknown
    * --whois-reprocessable-unknown
    * --whois-cache
    * --web-timeout
    * --subject, --body (even with BASE64), --references
      * when using --body flag, combine the text with the template
    * selecting column by negative numbers to match the last added column (`--field tld,-1`)
    * while splitting --output left blank prints out the file contents to the STDOUT after the processing
    * fix: possible to split by a mere type (exact column ID/name not needed)
* internal
    * OTRS no more appends ".txt" to the attachment name
    * web scraping bug of suspicious form-tag without name attribute present
    * fix: print all attachments flush
    * fix: cache empty whois prefix (ex: of a wrongly formatted IP)
    * whois cache saved only when changed (useful when having a huge cache)
    * mitigation for another type of a wrong WHOIS response
    * fix: reprocessing while changing dialect
    * fix: catch preview exception
    * fix: threading atomic write
    * applying filter before line processing if possible (spares a lot of time, ex: skip lines before WHOIS processing)
    * fix Python3.6: disabled logging messages from daemon (threw errors)
    * fix: processing velocity info (lines / s) showed garbage since threads implemented
    * fix: aggregate via Alt+a from main menu + any after-processing dialog (like resolve unknowns) caused the terminal to freeze (cannot use input() while another prompt toolkit session is active)
    * CLI better source_type determining
    * web module boosts and fixes
    * fix: when reprocessing (ex: invalid lines) after loading, file will get cleared no more
    * fix: CIDR when WHOIS returns directly CIDR instead of prefix. Currently, we do not guarantee prefix will be in the form "... - ...", it may has directly CIDR form if WHOIS tells us so
    * fix 1.3.6: file name duplicate when reprocessing
    * fix: aggregation can be disabled even if processed before
    * NTFS compatible abroad attachment names. Instead of a colon we use double at-sign to delimit country code from the chosen e-mail when splitting by an incident-contact field.
    * fix: PickBase used from CLI through --external
    * fix: empty `convey.log` is no more created in the directory when writing `python3 -m [LETTER].[TAB]` into terminal
    * unmaintained library validate_email replaced by py3-validate-email
    * working with current prompt_toolkit and ipython
    * resolve Python3.8 warnings

## 1.3.1 (2020-01-31)
* thread processing
* automatically converts XLSX and ODS spreadsheet file formats too
* internal
    * external field missing method name exception
    * loading dialect from a cached file bug
    * jsonpickle whois caching bug mitigated: now we are doing the serialization part ourselves
    * dependency of lxml of ezodf (which was not installed with ezodf I do not know why) added to requirements
    * submitting to github strips URL to 2000 chars (which is a reasonable maximum that server accepts)

## 1.3 (2020-01-28)
* CHANGED:
    * config.ini renamed to
        * contacts_local → contacts_cc
        * contacts_foreign → contacts_abroad
        * mail_template_basic → mail_template
        * mail_template_partner → mail_template_abroad
    * incident-contact field
        * for non-local countries produces now the file whose name is in the form "abroad:abusemail@example.com"
        * when non-local country is missing from contacts_abroad, it will be sent to its abusemail contact (but preserving mail_template_abroad)
    * attachment name no more prepended with prefix "part-"
    * by default, produced file CSV dialect is set to standard: comma, double quotes. (This may be changed in the config.ini by letting the relevant fields in CSV section blank to let the output file have the same dialect as the input.)
* flags
    * --aggregate – count grouped by a column, sum, etc.
    * --daemon, daemonize – since it takes around 0.75 s to start the program, notably because of the external libraries (pint, bs4, requests), when doing a single query or a headless processing (no menu involved) we may reduce this time at least ten times with a daemon)
    * --type – specify type of the given column(s), useful when treating a column that cannot be easily detected (as country_name)
    * --output left BLANK causes output be piped to STDOUT instead of to a file.
    * --reprocess
    * --testing
    * --send, --send-test [e-mail] [template]
    * --jinja
    * --attach-files
    * --delimiter-output, --quote-char-output, --header-output (may be set to `false`) to change output file syntax
* LICENSE included
* emergency input mode – when piping into the program (instead of giving the input as an argument), convey tries to gain a reduced STDIN from the terminal process #38
* bash completion
* webservice accepts `field` and `type` arguments (same as CLI flags)
* fix
    - adding external modules at runtime via menu
    - Ctrl+C works when interrupting wizzard as expected #39
    - detect multiline quoted_printable
    - better phone format recognition
    - multiple STDIN processing in a single session
    - CSV flags (like --header) when processing in --yes mode
    - web relative redirect working
    - max number of redirects is 10
* type: form_names
* interface
    - nicer output when processing from STDIN
    - aggregation more human readable
    - exclude filter + filter menu (composed from unique, exclude and include filter)
    - remove some of the processing settings
* internal
    - daemon pipes stderr as well
    - got rid of python-Levenshtein package and did not use psutil package so installing whole gcc is not needed anymore
    - after resetting settings fields keep their auto-detection information
    - tests
* sending: huge improvement of the interface
    - SMTP sending uses the envelope library
    - jinja templates, including helper instruments: print_attachment, amount, row, joined, first_row

## 1.2 (2019-11-13)
* web service
* flags:
    - CHANGED:
        - flag `--file` does not have anymore shortcut '-f'.
        - `custom_field_modules` renamed to `external_fields`
    - both INI and CLI flags
        - delimiter flag
        - quote_char flag
        - new header / no-header flags
        - new output CLI flag
        - web, whois, nmap
        - new flag single_query_ignored_fields
        - flag --verbose, --quiet and config `verbosity`
        - flag compute_preview
        - user-agent
        - headless
        - multiple-hostname-ip #32
        - whois_ttl #34
    - CLI only flags
        - --yes for skipping dialogues
        - --config to open configuration
        - --show-uml to get UML overview
        - --json
        - --field, --field-excluded, --delete, --split, --sort
        - --single-query, --csv-processing
        - --version
        - --disable-external, --whois-delete
    - INI only flags
        - github_crash_submit
* fixes:
    - fix: new installation should now correctly place contacts files in .config
    - fix: refresh abroad contact list e-mails when restart even if the file has been processed before
    - PyPi installer requirements fix
* Whois module
    - won't throw error if host can't be resolved
    - huge refactoring (may lead to the behaviour when Country is taken from ARIN and Netname from AfriNIC if AfriNIC points us to ARIN that doesn't state Netname)
    - thousands of unique prefixes tried, many uses cases handled
    - naive database of country names, so that country may be guessed from non-standardised "address" field
    - some well known erroneous LIR responses are re-requested by their respective RIR
    - CIDR with host bits set ( = invalid network) translates to IP when asking whois (RIR would return 'invalid search key')
    - CIDR translated to an IP before asking whois
    - number of discovered prefixes should during processing displayed, as well as real whois server URLs
    - socket.gethostbyname non-existing domain exception caught
    - Whois cache common for all convey files
    - every cache record has TTL
    - LACNIC quota exceeded marks the rows to be re-queued
    - sets internal process locale to en_US so that we can grep the same result at environments using different language
* processing:
    - logs in format "time IP src port > IP dst port" can be automatically transformed to CSV before processing
    - multiline base64 and quoted_printable strings (seen in e-mails) may be input → automatically decoded
    - methods may return a list (the row will be duplicated)
    - implicitly convert to plaintext if possible when adding new column (ex: base64 will be implicitly decoded before its value being passed to a new reg column)
    - decorator PickMethod, PickInput to allow the user choose the way generating will work
* internal
    - os replaced by pathlib
    - Config.getboolean merged to Config.get
    - Identifier (former CSVGuesses) is now object oriented, no more spaghetti
    - huge refactoring
    - fix: log files
    - Processor handles Whois statistics no more, so Identifier Whois methods do not return tuple anymore (standardised)
    - advanced header detection
* interface
    - able to automatically add/remove config file flags at program upgrade if allowed by user
    - when no known method is known to process a field, an example is given
    - when more than 9 options, you can use letters as shortcuts
    - main screen shows colorized result, preferable in the form of table if the terminal is wide enough
    - new 'code' field type for writing arbitrary code
    - when not in debug mode, a GitHub issue is filled out automatically at crash
    - autoopen_editor opens when analysis starts but now only if splitting by a column
    - Config file startup integrity check: missing items and sections may be inserted automatically after an upgrade
    - column sorting/picking in the main menu
    - much more options to handle STDIN saving
* types
    - reg type and its reg_m and reg_s
    - dns types (a, aaaa, mx, spf, ns, dmarc, txt)
    - tld
    - web: text, http_status, html, redirects, x_frame_options, csp
    - port, ports
    - urlencode, quoted_printable
    - charset, bytes
    - timestamp, isotimestamp, time, date, formatted_time
    - phone, unit

## 1.1 (2019-05-13)
* fix: do not reprocess file if moved to another location
* fix: empty file check
* fix: dialect ignored when generating a sample, whois inconsistency toughness
* fix: when config file is a symlink and is broken, do not confuse user with creating a new set of config file I.E. in .local/bin. Instead, demand mounting the symlink (or exit or recreate files).
* fix: whois fetching asn + netname again
* '/' is forbidden char in linux file names, when splitting by IP prefix, the char is replaced with a dash
* reading from stdin instead of a file
* when stdin input is a single value, auto-detect it, compute all possible results and quit (use case: inputting a base64 string will decode it, IP will produce all whois information table)
* new file_or_input config flag
* new save_stdin_output config flag
* Config file startup integrity check (you might have missing items since last upgrades)
* dropped default_dir and default_file config items & functionality. I doubt anyone has ever used that. These were to store the incidents directory for the case we did not provide an exact filename to treat when launching convey.
* Adding a column: if there is a single column we can source from, skip the dialog
* Since delimited, quote char and header guesses are mostly right, I stripped two dialog questions to a single one
* Main menu uses "←←←←←" symbol for hinting default value that is triggered when user hits Enter. When you select a processing action you don't have to write "p" for "process" anymore.
* CIDR type
* varying number of columns exception check
* when analyzing, show number of file descriptors currently being written
* unmaintained library lepl replaced by validate_email
* Wrong URL type

## 1.0.1 (2018-10-26)
* dropped Python 3.5 support
* python3.6 annotations
* it worked somehow but my colleague faced a strange issue in Whois module. Match object couldn't be called as a dictionary. I stepped out the change to see that Python3.5 support was dropped since 18.8., 51d7a90 , just after the first mature 1.0.0 release.
* logging while processing invalid rows write whole traceback
* file sizes in "show all details"
* csirtmail field fix, creating Config files: wrong path might be reported  …
* superfluous code removed
* better logging of invalid rows
* invalid lines fix, config menu, depickling error fix
* ARIN redirected whois support
* direct results from whois linux command
* fixed invalid line when different length #29
* invalid lines bugfixes


## 1.0.0 (2018-08-10)
* mature version
* Every important feature working as expected.


