This is the output of the `--help` command.
```
usage: convey [-h] [OPTIONS] [{None}|STR|PATH]

Swiss knife for mutual conversion of the web related data types, like `base64`
or outputs of the programs `whois`, `dig`, `curl`. Convenable way to quickly 
gather all meaningful information or to process large files that might freeze 
your spreadsheet processor.

See full docs at https://github.com/CZ-NIC/convey (ex. to launch a web 
service).

╭─ positional arguments ─────────────────────────────────────────────────────╮
│ [{None}|STR|PATH]                                                          │
│     File name to be parsed or input text. In nothing is given, user will   │
│     input data through stdin. (default: None)                              │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ options ──────────────────────────────────────────────────────────────────╮
│ -h, --help                                                                 │
│     show this help message and exit                                        │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ io options ───────────────────────────────────────────────────────────────╮
│ Input/Output                                                               │
│ ────────────────────────────────────────────────────────────────────────── │
│ --file {None}|STR                                                          │
│     Parse file. (Instead of <file_or_input> parameter.) (default: None)    │
│ -i {None}|STR, --input {None}|STR                                          │
│     Parse input text. (Instead of <file_or_input> parameter.) (default:    │
│     '')                                                                    │
│ --output blank|FILENAME                                                    │
│     Save output to this file.                                              │
│     If left blank, pass output to STDOUT.                                  │
│     If omitted, a filename will be produced automatically.                 │
│     May be combined with --headless. (default: None)                       │
│ -S blank=True|BOOL, --single-query blank=True|BOOL                         │
│     Consider the input as a single value, not a CSV. (default: None)       │
│ --single-detect blank=True|BOOL                                            │
│     Consider the input as a single value, not a CSV, and just print out    │
│     possible types of the input. (default: None)                           │
│ -C blank=True|BOOL, --csv-processing blank=True|BOOL                       │
│     Consider the input as a CSV, not a single. (default: None)             │
│ --default-action INT                                                       │
│     In the command line we specify a file name or input text (if file does │
│     not exist).                                                            │
│     If this parameter is omitted what should convey do?                    │
│     0 or empty ~ ask what to do                                            │
│     1 ~ input from stdin                                                   │
│     2 ~ choose file name                                                   │
│     3 ~ input from stdin, then choose file name                            │
│     4 ~ choose file name, then input from stdin                            │
│     5 ~ allow only input text (unless flag --file present), even if        │
│     parameter omitted                                                      │
│     6 ~ allow only file name (unless flag --input present), even if        │
│     parameter omitted (default: 1)                                         │
│ --save-stdin-output INT                                                    │
│     When processing input text (not a file on disk), should we save the    │
│     output to a file at program exit?                                      │
│     4 or True ~ always save                                                │
│     3 ~ if processed, save, otherwise do not save                          │
│     2 ~ always ask                                                         │
│     1 ~ if processed, ask, otherwise do not save                           │
│     0 or empty ~ do not save, just display                                 │
│     This value gets overwritten if --output flag is used to specify the    │
│     destination file.                                                      │
│     Note: We do not save single value input but only CSV STDIN input       │
│     unless --output flag specified.                                        │
│     Ex: $ convey example.com # single value input - no output unless       │
│     --output flag                                                          │
│     Ex: $ convey < file.csv # CSV STDIN input - output savable (default:   │
│     1)                                                                     │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ cli options ──────────────────────────────────────────────────────────────╮
│ CLI experience                                                             │
│ ────────────────────────────────────────────────────────────────────────── │
│ -v blank=True|BOOL, --verbose blank=True|BOOL                              │
│     Sets the verbosity to see DEBUG messages. (default: None)              │
│ -q blank=True|BOOL, --quiet blank=True|BOOL                                │
│     Sets the verbosity to see WARNINGs and ERRORs only.                    │
│     Prints out the least information possible.                             │
│     (Ex: if checking single value outputs a single word, prints out just   │
│     that.) (default: None)                                                 │
│ -y blank=True|BOOL, --yes blank=True|BOOL                                  │
│     Assume non-interactive mode and the default answer to questions.       │
│     Will not send e-mails unless --send is on too. (default: None)         │
│ -H blank=True|BOOL, --headless blank=True|BOOL                             │
│     Launch program in a headless mode which imposes --yes and --quiet. No  │
│     menu is shown. (default: None)                                         │
│ --github-crash-submit {True,False}                                         │
│     Submit crashes to GitHub (default: True)                               │
│ --debug blank=True|BOOL                                                    │
│     Development only: increases verbosity and gets the prompt in the case  │
│     of an exception. (default: None)                                       │
│ --crash-post-mortem blank=True|BOOL                                        │
│     Get prompt if program crashes (default: None)                          │
│ --autoopen-editor {True,False}                                             │
│     Open GUI editor with mail templates when analysis starts if splitting  │
│     by a column (default: False)                                           │
│ --write-statistics {True,False}                                            │
│     True if you want to write "statistics.txt" file next to the analyzed   │
│     file, containing whois info, like:                                     │
│         "Totally 17 of unique IPs; information for 5 countries (16 unique  │
│     IPs), no contact for 1 countries without national/government CSIRT (1  │
│     unique IPs)" (default: False)                                          │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ env options ──────────────────────────────────────────────────────────────╮
│ Environment                                                                │
│ ────────────────────────────────────────────────────────────────────────── │
│ --config FILE                                                              │
│     Open a config file and exit.                                           │
│     File: config (default)/uwsgi/template/template_abroad (default: None)  │
│ --show-uml blank=True|BOOL|INT                                             │
│     Show UML of fields and methods and exit.                               │
│     Methods that are currently disabled via flags or config file are       │
│     grayed out.                                                            │
│      * FLAGs:                                                              │
│         * +1 to gray out disabled fields/methods                           │
│         * +2 to include usual field names (default: None)                  │
│ --get-autocompletion blank=True|BOOL                                       │
│     Get bash autocompletion. (default: None)                               │
│ --version blank=True|BOOL                                                  │
│     Show the version number (which is currently 1.5.0-beta1). (default:    │
│     None)                                                                  │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ process options ──────────────────────────────────────────────────────────╮
│ Processing                                                                 │
│ ────────────────────────────────────────────────────────────────────────── │
│ --threads bool/auto/INT                                                    │
│     Set the thread processing number.                                      │
│                                                                            │
│                                                                            │
│     Processing threads                                                     │
│     If set to threads = auto, threads will be used if convey think it is   │
│     reasonable.                                                            │
│     If True, threads will be always used when processing.                  │
│     If number, that number of threads will be created.                     │
│     If False, 0, no thread used. (default: auto)                           │
│ -F blank=True|BOOL, --fresh blank=True|BOOL                                │
│     Do not attempt to load any previous settings / results.                │
│     Do not load convey's global WHOIS cache.                               │
│     (But merge WHOIS results in there afterwards.) (default: None)         │
│ -R blank=True|BOOL, --reprocess blank=True|BOOL                            │
│     Do not attempt to load any previous settings / results.                │
│     But load convey's global WHOIS cache. (default: None)                  │
│ --server blank=True|BOOL                                                   │
│     Launches simple web server. (default: None)                            │
│ --daemon start/restart/stop/status/server                                  │
│     Run a UNIX socket daemon to speed up single query requests.            │
│     * True – allow using the daemon                                        │
│     * False – do not use the daemon                                        │
│     * start – start the daemon and exit                                    │
│     * stop – stop the daemon and exit                                      │
│     * status – print out the status of the daemon                          │
│     * restart – restart the daemon and continue                            │
│     * server – run the server in current process (I.E. for debugging)      │
│     (default: None)                                                        │
│ --daemonize {True,False}                                                   │
│     To start up convey could take around 0.75 s notably because of the     │
│     external libraries (pint (0.2 s), bs4, requests).                      │
│     When doing a single query or a headless processing (no menu involved), │
│     we may reduce this time significantly (to cca 0.03 s) with a daemon    │
│     that would parse our CLI arguments and if everything went ok print out │
│     the results.                                                           │
│     True ~ start the daemon at the end of the first convey call            │
│     False ~ do not start the daemon automatically, just wait for `convey   │
│     --daemon start` call. (default: True)                                  │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ csv options ──────────────────────────────────────────────────────────────╮
│ CSV dialect                                                                │
│ ────────────────────────────────────────────────────────────────────────── │
│ --delimiter STR                                                            │
│     Treat file as having this delimiter. For tab use either \t or tab.     │
│     (default: '')                                                          │
│ --quote-char STR                                                           │
│     Treat file as having this quoting character. (default: '')             │
│ --header blank=True|BOOL                                                   │
│     Treat file as having header. (default: None)                           │
│ --delimiter-output STR                                                     │
│     Output delimiter. For tab use either \t or tab. (default: '')          │
│ --quote-char-output STR                                                    │
│     Output quoting char. (default: '')                                     │
│ --header-output blank=True|BOOL                                            │
│     If false, header is omitted when processing. (default: None)           │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ action options ───────────────────────────────────────────────────────────╮
│ Actions                                                                    │
│ ────────────────────────────────────────────────────────────────────────── │
│ -d COLUMN,[COLUMN], --delete COLUMN,[COLUMN]                               │
│     Delete a column. You may comma separate multiple columns. COLUMN is ID │
│     of the column (1, 2, 3...), position from the right (-1, ...), the     │
│     exact column name, field type name or its usual name. (default: '')    │
│ -f FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM], --field                 │
│ FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]                             │
│     Compute field.                                                         │
│     * FIELD is a field type (see below) that may be appended with a        │
│     [CUSTOM] in square brackets.                                           │
│     * COLUMN is ID of the column (1, 2, 3...), position from the right     │
│     (-1, ...), the exact column name, field type name or its usual name.   │
│     * SOURCE_TYPE is either field type or usual field type. That way, you  │
│     may specify processing method.                                         │
│     * CUSTOM is any string dependent on the new FIELD type (if not         │
│     provided, will be asked it for).                                       │
│     Ex: --field tld[gTLD]  # would add TLD from probably a hostname,       │
│     filtered by CUSTOM=gTLD                                                │
│     Ex: --field netname,ip  # would add netname column from any IP column  │
│         (Note the comma without space behind 'netname'.)                   │
│                                                                            │
│     Computable fields:                                                     │
│                                                                            │
│     This flag May be used multiple times. (repeatable)                     │
│ -fe FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM], --field-excluded       │
│ FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]                             │
│     The same as field but its column will not be added to the output.      │
│     (repeatable)                                                           │
│ -t [TYPE],..., --type [TYPE],...                                           │
│     Determine column type(s). (default: '')                                │
│ --split COLUMN                                                             │
│     Split by this COLUMN. (default: '')                                    │
│ -s COLUMN,..., --sort COLUMN,...                                           │
│     List of columns. (default: '')                                         │
│ -u COLUMN,VALUE, --unique COLUMN,VALUE                                     │
│     Cast unique filter on this COLUMN. (default: '')                       │
│ -ef COLUMN,VALUE, --exclude-filter COLUMN,VALUE                            │
│     Filter include this COLUMN by a VALUE. (default: '')                   │
│ -if COLUMN,VALUE, --include-filter COLUMN,VALUE                            │
│     Filter include this COLUMN by a VALUE. (default: '')                   │
│ -a [COLUMN, FUNCTION], ..., [group-by-COLUMN], --aggregate [COLUMN,        │
│ FUNCTION], ..., [group-by-COLUMN]                                          │
│     Aggregate (default: '')                                                │
│ --merge [REMOTE_PATH],[REMOTE_COLUMN],[LOCAL_COLUMN]                       │
│     Merge another file here. COLUMN is ID of the column (1, 2, 3...),      │
│     position from the right (-1, ...), the exact column name, field type   │
│     name or its usual name. (default: '')                                  │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ mod options ──────────────────────────────────────────────────────────────╮
│ Enabling modules                                                           │
│ ────────────────────────────────────────────────────────────────────────── │
│ --whois blank=True|BOOL                                                    │
│     Allowing Whois module: Leave blank for True or put true/on/1 or        │
│     false/off/0. (default: None)                                           │
│ --nmap blank=True|BOOL                                                     │
│     Allowing NMAP module: Leave blank for True or put true/on/1 or         │
│     false/off/0. (default: False)                                          │
│ --dig blank=True|BOOL                                                      │
│     Allowing DNS DIG module: Leave blank for True or put true/on/1 or      │
│     false/off/0. (default: None)                                           │
│ --web blank=True|BOOL                                                      │
│     Allowing Web module: Leave blank for True or put true/on/1 or          │
│     false/off/0.                                                           │
│     When single value input contains a web page, we could fetch it and add │
│     status (HTTP code) and text fields.                                    │
│     Text is just mere text, no tags, style, script, or head. (default:     │
│     None)                                                                  │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ comp options ─────────────────────────────────────────────────────────────╮
│ Field computing options                                                    │
│ ────────────────────────────────────────────────────────────────────────── │
│ --json blank=True|BOOL                                                     │
│     When checking single value, prefer JSON output rather than text.       │
│     (default: None)                                                        │
│ --user-agent STR                                                           │
│     Change user agent to be used when scraping a URL. (default: '')        │
│ --multiple-hostname-ip blank=True|BOOL                                     │
│     Hostname can be resolved into multiple IP addresses. Duplicate row for │
│     each. (default: None)                                                  │
│ --multiple-cidr-ip blank=True|BOOL                                         │
│     CIDR can be resolved into multiple IP addresses. Duplicate row for     │
│     each. (default: None)                                                  │
│ --web-timeout SECONDS                                                      │
│     Timeout used when scraping a URL. (default: 30)                        │
│ --multiple-nmap-ports {True,False}                                         │
│     NMAP may generate a single string with ports and their services, ex:   │
│                53/tcp  open  domain                                        │
│                443/tcp open  https                                         │
│        or may generate a list of open ports as integers, ex: [53, 443]     │
│        False ~ take single string                                          │
│        True ~ take all of them and duplicate whole row (default: False)    │
│ --single-query-ignored-fields [STR [STR ...]]                              │
│     These fields shall not be computed when using single value check       │
│     (default: html)                                                        │
│ --compute-preview blank=True|BOOL                                          │
│     When adding new columns, show few first computed values. (default:     │
│     True)                                                                  │
│ --external-fields [STR [STR ...]]                                          │
│     You may define custom fields. Providing paths to the entrypoint Python │
│     files.                                                                 │
│        Methods in these files will be taken as the names for the custom    │
│     fields.                                                                │
│                                                                            │
│                                                                            │
│        Ex: `--external-fields /tmp/myfile.py /tmp/anotherfile.py`          │
│                                                                            │
│                                                                            │
│        /tmp/myfile.py may have the contents: `def hello_world(val): return │
│     "hello world"`                                                         │
│                                                                            │
│                                                                            │
│        If you do not want to register all methods from the file, delimit   │
│     the chosen method by a colon                                           │
│        list chosen methods as new parameters while delimiting the method   │
│     names by a colon.                                                      │
│        Ex: `--external-fields /tmp/myfile.py:hello_world` (default: )      │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ whois options ────────────────────────────────────────────────────────────╮
│ WHOIS module options                                                       │
│ ────────────────────────────────────────────────────────────────────────── │
│ --whois.ttl SECONDS                                                        │
│     How many seconds will a WHOIS answer cache will be considered fresh.   │
│     (default: 86400)                                                       │
│ --whois.delete blank=True|BOOL                                             │
│     Delete convey's global WHOIS cache. (default: None)                    │
│ --whois.delete-unknown blank=True|BOOL                                     │
│     Delete unknown prefixes from convey's global WHOIS cache. (default:    │
│     None)                                                                  │
│ --whois.reprocessable-unknown blank=True|BOOL                              │
│     Make unknown lines reprocessable while single file processing, do not  │
│     leave unknown cells empty. (default: None)                             │
│ --whois.cache blank=True|BOOL                                              │
│     Use whois cache. (default: None)                                       │
│ --whois.mirror {None}|STR                                                  │
│     (default: None)                                                        │
│ --whois.local-country STR                                                  │
│     whois country code abbreviation (or their list) for local              │
│     country(countries),                                                    │
│        other countries will be treated as "abroad" if listed in            │
│     contacts_abroad                                                        │
│        This is important for incident-contact field; when generating       │
│     e-mail messages, "abroad" e-mails use another template.                │
│        * local country record uses whois abuse e-mail and template.eml     │
│        * abroad (non-local) record try to get the csirtmail from           │
│     contacts_abroad and uses template_abroad.csv                           │
│        * if the csirtmail is not available, it uses whois abuse e-mail and │
│     template_abroad.csv                                                    │
│        Ex: cz (default: '')                                                │
│ --whois.lacnic-quota-skip-lines {True,False}                               │
│     LACNIC has rate limits that lets the script wait for 5 minutes.        │
│         False ~ wait 5 minutes                                             │
│         True ~ skip lines and try to resolve them afterwards (default:     │
│     True)                                                                  │
│ --whois.lacnic-quota-resolve-immediately {True,False}                      │
│     True ~ resolve after processing other lines                            │
│     False ~ left skipped unprocessed (user have to launch reprocessing     │
│     from menu)                                                             │
│     empty ~ ask (default: True)                                            │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ sending options ──────────────────────────────────────────────────────────╮
│ Sending options                                                            │
│ ────────────────────────────────────────────────────────────────────────── │
│ --send blank/smtp/otrs                                                     │
│     Automatically send e-mails when split. (default: '')                   │
│ --send-test {None}|{STR STR}                                               │
│     Display e-mail message that would be generated for given e-mail.       │
│     (default: None)                                                        │
│ --jinja blank=True|BOOL                                                    │
│     Process e-mail messages with jinja2 templating system. (default: True) │
│ --attach-files blank=True|BOOL                                             │
│     Split files are added as e-mail attachments. (default: True)           │
│ --attach-paths-from-path-column blank=True|BOOL                            │
│     Files from a column of the Path type are added as e-mail attachments.  │
│     (default: None)                                                        │
│ --testing blank=True|BOOL                                                  │
│     Do not be afraid, e-mail messages will not be sent. They will get      │
│     forwarded to the testing e-mail. (default: None)                       │
│ --testing-mail STR                                                         │
│     If testing is True, all e-mails will be forwarded to this testing      │
│     e-mail. (default: example@example.com)                                 │
│ --subject STR                                                              │
│     E-mail subject. May be in BASE64 if started with                       │
│     "data:text/plain;base64,". (default: '')                               │
│ --body STR                                                                 │
│     E-mail body text (or HTML). May be in BASE64 if started with           │
│     "data:text/plain;base64,". (default: '')                               │
│ --references MESSAGE_ID                                                    │
│     E-mail references header (to send message within a thread). (default:  │
│     '')                                                                    │
│ --mail-template STR                                                        │
│     Template for basic e-mails. (default: template.eml)                    │
│ --mail-template-abroad STR                                                 │
│     Template for abroad e-mails. (default: template_abroad.eml)            │
│ --smtp-host STR                                                            │
│     (default: localhost)                                                   │
│ --email-from-name STR                                                      │
│     (default: '"My cool mail" <example@example.com>')                      │
│ --contacts-cc STR                                                          │
│     (default: contacts_cc.csv)                                             │
│ --contacts-abroad STR                                                      │
│     (default: contacts_abroad.csv)                                         │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ otrs options ─────────────────────────────────────────────────────────────╮
│ OTRS specific options. We may send all the e-mails by it.                  │
│ ────────────────────────────────────────────────────────────────────────── │
│ --otrs.enabled {True,False}                                                │
│     (default: True)                                                        │
│ --otrs.id STR                                                              │
│     Ticket id (default: '')                                                │
│ --otrs.cookie STR                                                          │
│     OTRSAgentInterface cookie (default: '')                                │
│ --otrs.token STR                                                           │
│     OTRS challenge token (default: '')                                     │
│ --otrs.host STR                                                            │
│     (default: localhost)                                                   │
│ --otrs.baseuri STR                                                         │
│     (default: /otrs/index.pl)                                              │
│ --otrs.signkeyid STR                                                       │
│     (default: PGP::Sign::-)                                                │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ web options ──────────────────────────────────────────────────────────────╮
│ --web.webservice-allow-unsafe-fields {None}|{[STR [STR ...]]}              │
│     Fields 'code' and 'external' are considered unsafe, an attacker might  │
│     take possession of your server. With 'code', you can launch an         │
│     arbitrary code on the machine. With 'external', you can load any file  │
│     from your machine and launch it. These unsafe fields are not available │
│     via the web service. You may specifically allow them here, ex:         │
│     webservice_allow_unsafe_fields = code, external Leave this field empty │
│     if you are not sure what are you doing! (default: None)                │
│ --web.user-agent STR                                                       │
│     Change user agent to be used when scraping a URL (default: '')         │
│ --web.timeout INT                                                          │
│     timeout used when scraping a URL (default: 3)                          │
╰────────────────────────────────────────────────────────────────────────────╯
```
