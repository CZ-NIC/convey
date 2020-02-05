# CHANGELOG

## 1.3.2 (unreleased)
* webservice uwsgi file (HTTPS support)
* types
    * csirt_contact now may be derived from tld
* dialog
    * edit default e-mail templates from config submenu
    * delimiter now may contain tab character, input by "\t" or "tab"
    * show current SMTP server in the send submenu
    * --config now can edit any config file, not only config.ini 
* internal
    * OTRS no more appends ".txt" to the attachment name
    * web scraping bug of suspicious form-tag without name attribute present
    * fix: print all attachments flush

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
        - --disable-external, --delete-whois-cache
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


