This is the output of the `--help` command.
```
usage: convey [-h] [--file] [-i] [-o [blank/FILENAME]] [-S] [--single-detect]
              [-C] [--debug [blank/false]] [-v] [-q] [-y] [-H]
              [--compute-preview [blank/false]] [--csirt-incident]
              [--config [FILE [MODE ...]]] [--show-uml [SHOW_UML]]
              [--get-autocompletion] [--version]
              [--threads [blank/false/auto/INT]] [-F] [-R] [--server]
              [--daemon [start/restart/stop/status/server]]
              [--delimiter DELIMITER] [--quote-char QUOTE_CHAR] [--header]
              [--no-header] [--delimiter-output DELIMITER]
              [--quote-char-output QUOTE_CHAR] [--header-output [blank/false]]
              [-d COLUMN,[COLUMN]]
              [-f FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]]
              [-fe FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]]
              [-t [TYPE],...] [--split COLUMN] [-s COLUMN,...]
              [-u COLUMN,VALUE] [-ef COLUMN,VALUE] [-if COLUMN,VALUE]
              [-a [COLUMN, FUNCTION], ..., [group-by-COLUMN]]
              [--whois [blank/false]] [--nmap [blank/false]]
              [--dig [blank/false]] [--web [blank/false]] [--disable-external]
              [--json] [--user-agent USER_AGENT]
              [--multiple-hostname-ip [blank/false]]
              [--multiple-cidr-ip [blank/false]] [--web-timeout SECONDS]
              [--whois-ttl SECONDS] [--whois-delete] [--whois-delete-unknown]
              [--whois-reprocessable-unknown] [--whois-cache [blank/false]]
              [--send [blank/smtp/otrs]] [--send-test E-MAIL TEMPLATE_FILE]
              [--jinja [blank/false]] [--attach-files [blank/false]]
              [--testing [blank/false]] [--otrs_id OTRS_ID]
              [--otrs_num OTRS_NUM] [--otrs_cookie OTRS_COOKIE]
              [--otrs_token OTRS_TOKEN]
              [file_or_input]

Data conversion swiss knife

optional arguments:
  -h, --help            show this help message and exit
  --csirt-incident      Macro that lets you split CSV by fetched incident-
                        contact (whois abuse mail for local country or csirt
                        contact for foreign countries) and send everything by
                        OTRS. You set local countries in config.ini, currently
                        set to 'cz'
  --server              Launches simple web server
  --daemon [start/restart/stop/status/server]
                        Run a UNIX socket daemon to speed up single query requests.
                          * 1/true/on – allow using the daemon
                          * 0/false/off – do not use the daemon
                          * start – start the daemon and exit
                          * stop – stop the daemon and exit
                          * status – print out the status of the daemon
                          * restart – restart the daemon and continue
                          * server – run the server in current process (I.E. for debugging)

Input/Output:
  file_or_input         File name to be parsed or input text. In nothing is
                        given, user will input data through stdin.
  --file                Treat <file_or_input> parameter as a file, never as an
                        input
  -i, --input           Treat <file_or_input> parameter as an input text, not
                        a file name
  -o [blank/FILENAME], --output [blank/FILENAME]
                        Save output to this file. If left blank, pass output
                        to STDOUT. If omitted, a filename will be produced
                        automatically. May be combined with --headless.
  -S, --single-query    Consider the input as a single value, not a CSV.
  --single-detect       Consider the input as a single value, not a CSV, and
                        just print out possible types of the input.
  -C, --csv-processing  Consider the input as a CSV, not a single.

CLI experience:
  --debug [blank/false]
                        On error, enter a pdb session
  -v, --verbose         Sets the verbosity to see DEBUG messages.
  -q, --quiet           Sets the verbosity to see WARNINGs and ERRORs only. Prints out the least information possible.
                        (Ex: if checking single value outputs a single word, prints out just that.)
  -y, --yes             Assume non-interactive mode and the default answer to
                        questions. Will not send e-mails unless --send is on
                        too.
  -H, --headless        Launch program in a headless mode which imposes --yes
                        and --quiet. No menu is shown.
  --compute-preview [blank/false]
                        When adding new columns, show few first computed
                        values.

Environment:
  --config [FILE [MODE ...]]
                        Open a config file and exit.
                         File: config (default)/uwsgi/template/template_abroad
                         Mode: 1 terminal / 2 GUI / 3 try both (default)
  --show-uml [SHOW_UML]
                        Show UML of fields and methods and exit. Methods that are currently disabled via flags or config file are grayed out.
                         * FLAGs:
                            * +1 to gray out disabled fields/methods
                            * +2 to include usual field names
  --get-autocompletion  Get bash autocompletion.
  --version             Show the version number (which is currently 1.2).

Processing:
  --threads [blank/false/auto/INT]
                        Set the thread processing number.
  -F, --fresh           Do not attempt to load any previous settings /
                        results. Do not load convey's global WHOIS cache. (But
                        merge WHOIS results in there afterwards.)
  -R, --reprocess       Do not attempt to load any previous settings /
                        results. But load convey's global WHOIS cache.

CSV dialect:
  --delimiter DELIMITER
                        Treat file as having this delimiter. For tab use
                        either \t or tab.
  --quote-char QUOTE_CHAR
                        Treat file as having this quoting character
  --header              Treat file as having header
  --no-header           Treat file as not having header
  --delimiter-output DELIMITER
                        Output delimiter. For tab use either \t or tab.
  --quote-char-output QUOTE_CHAR
                        Output quoting char
  --header-output [blank/false]
                        If false, header is omitted when processing..

Actions:
  -d COLUMN,[COLUMN], --delete COLUMN,[COLUMN]
                        Delete a column. You may comma separate multiple
                        columns.COLUMN is ID of the column (1, 2, 3...), the
                        exact column name, field type name or its usual name.
  -f FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM], --field FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]
                        Compute field.
                        * FIELD is a field type (see below) that may be appended with a [CUSTOM] in square brackets.
                        * COLUMN is ID of the column (1, 2, 3...), the exact column name, field type name or its usual name.
                        * SOURCE_TYPE is either field type or usual field type. That way, you may specify processing method.
                        * CUSTOM is any string dependent on the new FIELD type (if not provided, will be asked it for).
                        Ex: --field tld[gTLD]  # would add TLD from probably a hostname, filtered by CUSTOM=gTLD
                        Ex: --field netname,ip  # would add netname column from any IP column
                            (Note the comma without space behind 'netname'.)
                        
                        Computable fields: 
                        * HostnameTldExternal (hostname example text)
                        * base64 (Text encoded with Base64) usual names: base64
                        * charset
                        * cidr (CIDR 127.0.0.1/32) usual names: cidr
                        * country_name
                        * date
                        * email (E-mail address) usual names: mail
                        * first_method ( hoho )
                        * formatted_time
                        * hostname (2nd or 3rd domain name) usual names: fqdn, hostname, domain
                        * ip (valid IP address) usual names: ip, ipaddress
                        * isotimestamp
                        * plaintext (Plain text) usual names: plaintext, text
                        * port (port) usual names: port, prt
                        * quoted_printable (Text encoded as quotedprintable)
                        * second_method (Hello boys!)
                        * time
                        * tld
                        * unit (any physical quantity)
                        * url (URL starting with http/https) usual names: url, uri, location
                        * urlencode (Text encoded with urlencode) usual names: urlencode
                        * code
                        * external
                        * reg
                        * reg_m
                        * reg_s
                        * abusemail (Abuse e-mail contact from whois)
                        * asn (Autonomous system number) usual names: as, asn, asnumber
                        * country
                        * csirt_contact (E-mail address corresponding with country code, taken from your personal contacts_abroad CSV in the format `country,abusemail`. See config.ini/contacts_abroad)
                        * incident_contact
                        * netname
                        * prefix
                        * a
                        * aaaa
                        * dmarc
                        * mx
                        * ns
                        * spf
                        * txt
                        * ports (Open ports given by nmap)
                        * csp
                        * form_names
                        * html
                        * http_status (HTTP response status. If 0 or negative, request failed.)
                        * redirects
                        * text
                        * x_frame_options
                        
                        This flag May be used multiple times.
  -fe FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM], --field-excluded FIELD,[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]
                        The same as field but its column will not be added to
                        the output.
  -t [TYPE],..., --type [TYPE],...
                        Determine column type(s).
                        Ex: --type country,,phone # 1st column is country, 2nd unspecified, 3rd is phone
  --split COLUMN        Split by this COLUMN.
  -s COLUMN,..., --sort COLUMN,...
                        List of columns.
  -u COLUMN,VALUE, --unique COLUMN,VALUE
                        Cast unique filter on this COLUMN.
  -ef COLUMN,VALUE, --exclude-filter COLUMN,VALUE
                        Filter include this COLUMN by a VALUE.
  -if COLUMN,VALUE, --include-filter COLUMN,VALUE
                        Filter include this COLUMN by a VALUE.
  -a [COLUMN, FUNCTION], ..., [group-by-COLUMN], --aggregate [COLUMN, FUNCTION], ..., [group-by-COLUMN]
                        Aggregate
                        Ex: --aggregate 2,sum # will sum the second column
                        Ex: --aggregate 2,sum,3,avg # will sum the second column and average the third
                        Ex: --aggregate 2,sum,1 # will sum the second column grouped by the first
                        Ex: --aggregate 1,count # will count the grouped items in the 1st column (count will automatically set grouping column to the same)
                        
                        Available functions: 
                        * avg
                        * sum
                        * count
                        * min
                        * max
                        * list
                        * set

Enabling modules:
  --whois [blank/false]
                        Allowing Whois module: Leave blank for True or put true/on/1 or false/off/0.
  --nmap [blank/false]  Allowing NMAP module: Leave blank for True or put true/on/1 or false/off/0.
  --dig [blank/false]   Allowing DNS DIG module: Leave blank for True or put true/on/1 or false/off/0.
  --web [blank/false]   Allowing Web module: Leave blank for True or put true/on/1 or false/off/0.
                        When single value input contains a web page, we could fetch it and add status (HTTP code) and text fields. Text is just mere text, no tags, style, script, or head. 

Field computing options:
  --disable-external    Disable external function registered in config.ini to be imported.
  --json                When checking single value, prefer JSON output rather
                        than text.
  --user-agent USER_AGENT
                        Change user agent to be used when scraping a URL
  --multiple-hostname-ip [blank/false]
                        Hostname can be resolved into multiple IP addresses.
                        Duplicate row for each.
  --multiple-cidr-ip [blank/false]
                        CIDR can be resolved into multiple IP addresses.
                        Duplicate row for each.
  --web-timeout SECONDS
                        Timeout used when scraping a URL

WHOIS module options:
  --whois-ttl SECONDS   How many seconds will a WHOIS answer cache will be
                        considered fresh.
  --whois-delete        Delete convey's global WHOIS cache.
  --whois-delete-unknown
                        Delete convey's global WHOIS cache.
  --whois-reprocessable-unknown
                        Make unknown lines reprocessable while single file
                        processing, do not leave unknown cells empty.
  --whois-cache [blank/false]
                        Use whois cache.

Sending options:
  --send [blank/smtp/otrs]
                        Automatically send e-mails when split.
  --send-test E-MAIL TEMPLATE_FILE
                        Display e-mail message that would be generated for
                        given e-mail.
  --jinja [blank/false]
                        Process e-mail messages with jinja2 templating system
  --attach-files [blank/false]
                        Split files are added as e-mail attachments
  --testing [blank/false]
                        Do not be afraid, e-mail messages will not be sent.
                        They will get forwarded to the testing e-mail (and
                        e-mails in Cc will not be sent at all)

OTRS:
  --otrs_id OTRS_ID     Ticket id
  --otrs_num OTRS_NUM   Ticket num
  --otrs_cookie OTRS_COOKIE
                        OTRS cookie
  --otrs_token OTRS_TOKEN
                        OTRS token

To launch a web service see README.md.
```
