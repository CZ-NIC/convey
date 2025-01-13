# Convey

[![Build Status](https://github.com/CZ-NIC/convey/actions/workflows/run-unittest.yml/badge.svg)](https://github.com/CZ-NIC/convey/actions) 
[![Downloads](https://static.pepy.tech/badge/convey)](https://pepy.tech/project/convey)

Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`.
A convenient way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.

Any input is accepted:
* if a **single value** input is detected, all **meaningful information** is fetched
* multiline **base64**/**quoted_printable** string gets decoded
* **log/XLS/XLSX/ODS file** converted to CSV
* **CSV file** (any delimiter, header or [pandoc](https://pandoc.org/MANUAL.html#tables) table format) performs one or more actions
    1) **Pick, delete or sort columns** (if only some columns are needed)
    2) **Add a column** (computes one field from another – see below)
    3) **Filter** (keep/discard rows with specific values, no duplicates)
    4) **Split by a column** (produce separate files instead of single file; these can then be sent by generic SMTP or through OTRS)
    5) **Change CSV dialect** (change delimiter or quoting character, remove header)
    6) **Aggregate** (count grouped by a column, sum...)
    7) **Merge** (join other file)

Python3.10+ required (older releases support up to 3.6).

# Table of contents
* [Usage](#usage)
  + [Usage 1 – Single query](#usage-1--single-query)
  + [Usage 2 – CSV processor program](#usage-2--csv-processor-program)
  + [Usage 3 – Web service](#usage-3--web-service)
* [Installation and first run](#installation-and-first-run)
  + [Prerequisities](#prerequisities)
  + [Launch as a package](#launch-as-a-package)
  + [OR launch from a directory](#or-launch-from-a-directory)
  + [Bash completion](#bash-completion)
  + [Customisation](#customisation)
* [Computing fields](#computing-fields)
  + [Computable fields](#computable-fields)
    - [Whois module](#whois-module)
  + [Detectable fields](#detectable-fields)
  + [Overview of all methods](#overview-of-all-methods)
  + [External field how-to](#external-field-how-to)
    - [Simple custom method](#simple-custom-method)
      * [Launch an external method](#launch-an-external-method)
      * [Register an external method](#register-an-external-method)
    - [List of results possible](#list-of-results-possible)
    - [PickMethod decorator](#pickmethod-decorator)
    - [PickInput decorator](#pickinput-decorator)
* [Web service](#web-service)
* [Sending files](#sending-files)
  + [Arbitrary e-mail headers, "From" header, GPG signing](#arbitrary-e-mail-headers-from-header-gpg-signing)
  + [Dynamic templates](#dynamic-templates)
* [Examples](#examples)
  + [URL parsing](#url-parsing)
    - [Output formats](#output-formats)
    - [Computing TLD from another column](#computing-tld-from-another-column)
    - [CSV processing](#csv-processing)
    - [File splitting](#file-splitting)
    - [CSIRT Usecase](#csirt-usecase)
  + [Custom code field](#custom-code-field)
  + [Base64 and Regular expressions](#base64-and-regular-expressions)
  + [Converting units](#converting-units)
  + [Aggregate](#aggregate)
  + [Merge](#merge)
  + [Sending images to different recipients](#sending-images-to-different-recipients)
* [Credits](#credits)


## Usage

### Usage 1 – Single query
Check what happens if an IP is provided, it returns table with WHOIS-related information and scraped HTTP content.
```bash
$ convey 1.1.1.1 # single query input
Input value detected: ip

1.1.1.1 ...au

field             value
----------------  -----------------
prefix            1.1.1.0-1.1.1.255
asn               as13335
abusemail         abuse@apnic.net
country           au
netname           apnic-labs
csirt-contact     -
incident-contact  au
status            200
text              DNSThe free app that makes your (much longer text...)
```

### Usage 2 – CSV processor program
Parses CSV file.
```bash
$ convey my-file-with-ips.csv # will trigger file parsing
Source file: /tmp/my-file.csv
Log lines: 200

Sample:
...

Delimiter character found: ','
Quoting character: '"'
Header is present: not used

Could you confirm this? [y]/n
...
...
```

### Usage 3 – Web service
Again, let's provide an IP to the [web service](#web-service), it returns JSON with WHOIS-related information and scraped HTTP content.
```bash
$ convey --server  # start a UWSGI session
```
Access in the browser: http://localhost:26683/?q=example.com
```json
{"ip": "93.184.216.34", "prefix": "93.184.216.0-93.184.216.255", "asn": "", "abusemail": "abuse@verizondigitalmedia.com", "country": "unknown", "netname": "edgecast-netblk-03", "csirt-contact": "-", "incident-contact": "unknown", "status": 200, "text": "DNSThe free app that makes your (much longer text...)"}
```

## Installation and first run

### Prerequisites
* You'll be asked to install `dialog` library at the first run if not already present in the system.
* If something is missing on your system, you may find help yourself with this command:
`sudo apt install python3-pip python3-dev python3-tk git xdg-utils dialog whois dnsutils nmap curl build-essential libssl-dev libpcre3 libpcre3-dev && pip3 install setuptools wheel uwsgi && pip3 install --upgrade ipython`
    * `build-essential` is needed to build `uwsgi` and `envelope`
    * `libpcre3 libpcre3-dev` needed to suppress uWSGI warning `!!! no internal routing support, rebuild with pcre support !!!`
    * `libssl-dev` needed to be present before building `uwsgi` if you will need to use `--https`

### Launch as a package:

```bash
# (optional) setup virtual environment
python3 -m venv venv
. venv/bin/activate
(venv) $ ... # continue below

# install from PyPi
pip3 install convey  # without root use may want to use --user

# (optional) alternatively, you may want to install current master from GitHub
pip3 install git+https://github.com/CZ-NIC/convey.git

# launch
convey [filename or input text] # or try `python3 -m convey` if you're not having `.local/bin` in your executable path
```

Parameter `[filename or input text]` may be the path of the CSV source file or any text that should be parsed. Note that if the text consist of a single value, program prints out all the computable information and exits; I.E. inputting a base64 string will decode it.

### OR launch from a directory

```bash
# download from GitHub
git clone git@github.com:CZ-NIC/convey.git
cd convey
pip3 install -r requirements.txt  --user

# launch
./convey.py
```

### Bash completion
1. Run: `apt-get install bash-completion jq`
2. Copy: [extra/convey-autocompletion.bash](./extra/convey-autocompletion.bash) to `/etc/bash_completion.d/`
3. Restart terminal

### Customisation
* Launch convey with [`--help`](docs/convey-help-cmd-output.md) flag to see [further options](docs/convey-help-cmd-output.md).
* A file [`config.ini`](convey/defaults/config.ini) is automatically created in [user config folder](convey/defaults/config.ini). This file may be edited for further customisation. Access it with `convey --config`.
> * Convey tries to open the file in the default GUI editor or in the terminal editor if GUI is not an option.
> * If `config.ini` is present at working directory, that one is used over the one in the user config folder.
> * Configuration is updated automatically on upgrade.

## Computing fields

### Computable fields

Some field types are directly computable:

* **abusemail** – got abuse e-mail contact from whois
* **asn** – got from whois
* **base64** – encode/decode
* **cc_contact** – e-mail address corresponding with the abusemail, taken from your personal contacts_cc CSV in the format `domain,cc;cc` (mails delimited by a semicolon). Path to this file has to be specified in `config.ini » contacts_cc`.
* **country** – country code from whois
* **~~csirt_contact~~** – e-mail address corresponding with country code, taken from your personal contacts_abroad CSV in the format `country,abusemail`. Path to this file has to be specified in `config.ini » contacts_abroad`
* **external** – you specify method in a custom .py file that receives the field and generates the value for you, see below
* **hostname** – domain from url
* **incident_contact** – if the IP comes from local country (specified in `config.ini » local_country`) the field gets *abusemail*, otherwise we get *country@@mail* where *mail* is either *abusemail* or abroad country e-mail. When splitting by this field, convey is subsequently able to send the split files to local abuse and foreign csirt contacts.
* **ip** – translated from url
* **netname** – got from whois
* **prefix** – got from whois

#### Whois module

When obtaining a WHOIS record
* We are internally calling `whois` program, detecting what servers were asked.
* Sometimes you encounter a funny formatted *whois* response. We try to mitigate such cases and **re-ask another registry** in well known cases.
* Since IP addresses in the same prefix share the same information we cache it to gain **maximal speed** while reducing *whois* queries.
* Sometimes you encounter an IP that gives no information but asserts its prefix includes a large portion of the address space. All IP addresses in that portion ends labeled as unknowns. At the end of the processing you are **asked to redo unknowns** one by one to complete missing information, flushing misleading superset from the cache.
* You may easily hit **LACNIC query rate** quota. In that case, we re-queue such lines to be queried after the quota is over if possible. At the end of the processing, you will get asked whether you wish to carefully and slowly reprocess the lines awaiting the quota lift.

### Detectable fields

Some of the field types are possible to be auto-detected:

* **ip** – standard IPv4 / IPv6 addresses
* **cidr** – CIDR notation, ex: 127.0.0.1/32
* **port_ip** – IPv4 in the form 1.2.3.4.port
* **any_ip** – IPv4 garbled in the form `any text 1.2.3.4 any text`
* **hostname** – or FQDN; 2nd or 3rd domain name
* **url** – URL starting with http/https
* **asn** – AS Number
* **base64** – text encoded with base64
* **wrong_url** – URL that has been deactivated by replacing certain chars, ex: "hxxp://example[.]com"

### Overview of all methods

Current field computing capacity can be get from `--show-uml` flag. Generate yours by ex: `convey --show-uml | dot -Tsvg -o /tmp/convey-methods.svg`

* Dashed node: field type is auto-detectable
* Dashed edge: field types are identical
* Edge label: generating options asked at runtime
* Rectangle: field category border

![Methods overview](./docs/convey-methods.svg?sanitize=True)



### External field how-to
#### Simple custom method
If you wish to compute an **external** field, prepare a file whose contents can be as simple as this:

```python3
def any_method(value):
    # do something
    return "modified :)"
```

##### Launch an external method
* When CSV processing, hit *'Add column'* and choose *'new external... from a method in your. py file'*
* Or in the terminal append `--field external` to your `convey` command. A dialog for a path of the Python file and desired method will appear.
```bash
$ convey [string_or_filepath] --field external
```
* You may as well directly specify the path and the callable. Since the `--field` has following syntax:
> *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*

You may omit both *COLUMN* and *SOURCE_TYPE* writing it this way:

> *FIELD,~~COLUMN,SOURCE_TYPE~~,CUSTOM,CUSTOM*
> external,/tmp/myfile.py,any_method
```bash
$ convey [string_or_filepath] --field external,/tmp/myfile.py,any_method
Input value seems to be plaintext.
field     value
--------  -----------------------
external  modified :)
```

##### Register an external method
* You may as well hard code custom fields in the [`config.ini`](convey/config.ini.default) by providing paths to the entry point Python files delimited by a comma: `external_fields = /tmp/myfile.py, /tmp/anotherfile.py`. All the public methods in the defined files will become custom fields!
```editorconfig
[EXTERNAL]
external_fields = /tmp/myfile.py
```
* If this is not needed, you may register one by one by adding new items to the `EXTERNAL` section. Delimit the method name by a colon.
```editorconfig
[EXTERNAL]
any_method = /tmp/myfile.py:any_method
```

#### List of results possible
If you need a single call to generate multiple rows, return list, the row accepting a list will be duplicated.

```python3
def any_method(value):
    # do something
    return ["foo", "bar"]
```

When convey receives multiple lists, it generates a row for each combination. Ex: If a method returns 2 items and another 3 items, you will receive 6 similar rows.

#### PickMethod decorator
Should there be multiple ways of using your generator, place them as methods of a class decorated with `PickMethod` and let the user decide at the runtime. `PickMethod` has optional `default:str` parameter that specifies the default method.

```python3
from convey import PickMethod

@PickMethod("all")
class any_method(PickMethod):
    def all(x):
        ''' All of them.  '''
        return x

    def filtered(cls, x):
        ''' Filter some of them '''
        if x in country_code_set:
            return x
```

```bash
$ convey file.csv --field any_method  # user will be asked whether to use `all` or `filtered`
$ convey file.csv --field any_method[filtered]  # `filtered` sub-method will be used
$ convey file.csv --field any_method --yes  # the default `all` sub-method will be used
```

#### PickInput decorator
If you need a direct user entry before each processing, import `PickInput` and make your method accept *two* parameters. The latter will be set by the user and may have a default value.

```python3
from convey import PickInput
import dateutil

@PickInput
def time_format(val, format="%H:%M"):
    ''' This text will be displayed to the user.
        If running in headless mode, the default format will be "%H:%M" (hours:minutes).   '''
    return dateutil.parser.parse(val).strftime(format)
```

```bash
$ convey file.csv --field time_format  # user will be asked for a format parameter
$ convey file.csv --field time_format[%M]  # `format` will have the value `M%`
$ convey file.csv --field time_time --yes  # the default `format` `%H:%M` will be used
```

## Web service
When launched as a web service, several parameters are available:
* `q` – search query
* `type` – same as `--type` CLI flag
* `field` – same as `--field` CLI flag.
    * Note that unsafe field types `code` and `external` are disabled in web service by default. You may re-allow them in `webservice_allow_unsafe_fields` config option
    * full syntax of CLI flag is supported
    > *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*

    Ex: `reg_s,l,L` performs regular substitution of *'l'* by *'L'*
* `clear=web` – clears web scrapping module cache

Quick deployment may be realized by a single command:
```bash
$ convey --server
```

* Note that convey must be installed via `pip`
* Note that LACNIC may freeze for 300 s, hence the timeout recommendation.
* Note that you may find your convey installation path by launching `pip3 show convey`
* If you received or [generated](https://uwsgi-docs.readthedocs.io/en/latest/HTTPS.html#https-support-from-1-3) key and certificate, you may turn on HTTPS in `uwsgi.ini` accesible by: `convey --config uwsgi`
* Internally, flag `--server` launches `wsgi.py` with a UWSGI session.
    ```bash
    $ uwsgi --http :26683 --http-timeout 310 --wsgi-file /home/$USER/.local/lib/python3.../site-packages/convey/wsgi.py
    ```


Access: `curl http://localhost:26683/?q=example.com`
```json
{"ip": "93.184.216.34", "prefix": "93.184.216.0-93.184.216.255", "asn": "", "abusemail": "abuse@verizondigitalmedia.com", "country": "unknown", "netname": "edgecast-netblk-03", "csirt-contact": "-", "incident-contact": "unknown", "status": 200, "text": "DNSThe free app that makes your (much longer text...)"}
```

Access: `curl http://localhost:26683/?q=example.com&field=ip`
```json
{"ip": "93.184.216.34"}
```

Access: `curl http://localhost:26683?q=hello&type=country&field=reg_s,l,L`
```json
{"reg_s": "heLLo"}
```

## Sending files

When you split the CSV file into chunks by an e-mail, generated files may be sent to these addresses. Look at the example of an unlocked "send" menu below. You see the list of the recipients, followed by a conditional list of recipients that have been already sent to. Next, an exact e-mail message is printed out, including headers.

In the menu, you may either:
 * **Send** the e-mails
 * **Limit** the messages that are being send at once; if you are not 100 % sure you want to send the the whole message bucket at once.
 * **Edit** the template. The message file will open either in the default GUI or terminal editor. The first line of the template should be `Subject: ...`, followed by a free line. Note that you may include any e-mail headers, such as `Reply-To: ...`, `Cc: ...`, etc. The e-mail will reflect all of them. You may write the message either in plain text or in the HTML.
 * **Choose** which recipients in a checkbox list will receive the message.
 * **Test** sending a message to your own address. You'll be prompted which of the messages should be delivered to you. The e-mail contents possibly modified by a dynamic template is shown just before sending.
 * **Print all e-mails** to a file to have the more granulated control over what is going to be sent.
 * **Toggle file attaching** on and off. A portion of the source file related to this e-mail address might be attached. There are use cases when you do not want the files to be sent with as the body text suits fine.
 * **Toggle paths from the path column attaching** on and off. Files mentioned in a path column and related to this e-amil address might be attached.

```bash
  *** E-mail template ***
Recipient list (1/3): alice@example.com
Already sent (2/3): bob@example.com, cilia@example.com
Attachment: split CSV file attached

Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit
MIME-Version: 1.0
Subject: My subject
From: me@example.com
Date: Fri, 17 Jan 2020 01:36:28 +0100

Hello,

this is my testing message.

Keen regards

**************************************************
1) Send all e-mails via localhost (1) ←←←←←
l) Limit sending amount to...
e) Edit template...
r) Choose recipients...
t) Send test e-mail...
p) Print e-mails to a file...
a) Attach files (toggle): True
i) Attach paths from path column (toggle): False
x) Go back...
?
```

### Arbitrary e-mail headers, "From" header, GPG signing
In the template, you may specify any e-mail header, such as `Reply-To`, `Cc` or `From`. If `From` is not found, we take `SMTP/email_from_name` config value. If `gnupg` home is found on the default user path, we check if there is a secret key matching the `From` header and if found, e-mail will be GPG-signed. If it is going to be signed, you would see something like `Content-Type: multipart/signed; protocol="application/pgp-signature";` header in the e-mail template preview.

### Dynamic templates
Message is processed with [Jinja2](https://jinja.palletsprojects.com/en/2.10.x/) templating system by default.

Few instruments are included to treat the attachment contents:
* **attachment()** – Prints the attachment contents and prevent it to be attached.
    ```jinja2
    You will find our findings below.

    {{ attachment() }}
    ```
* **row()** – Generate attachment contents fields row by row. Header skipped.
* **amount(count=2)** – Check if the attachment has at least `count` number of lines. Header is not counted. Useful when deciding whether the are single row in the result or multiple.
* **joined(column: int, delimiter=", ")** – Return a column joined by delimiter
* **first_row** – Access first line fields

    Example:
    ```jinja2
    {% if amount() %}
        Here is the complete list of the elements.
        {{ joined(1,"\n") }}
    {% else %}
        Here is the element you had problems with: {{ first_row[1] }}
    {% endif %}
    ```

## Examples

In the examples, we will use these parameters to add a field and to shorten the result.
```bash
# -f, --field adding field syntax: FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]
# -H, --headless: just quietly print out single value, no dialog
```

### URL parsing

#### Output formats
Put any IP or URL as the argument.

```bash
$ convey example.com
Input value detected: hostname

Whois 93.184.216.34... abuse@verizondigitalmedia.com
Scrapping http://example.com...
field             value
----------------  ------------------------------------------------------------------------------
cidr              93.184.216.0/24
ip                93.184.216.34
tld               com
url               http://example.com
abusemail         abuse@verizondigitalmedia.com
csirt_contact     -
incident_contact  abuse@verizondigitalmedia.com
netname           edgecast-netblk-03
prefix            93.184.216.0-93.184.216.255
a                 93.184.216.34
aaaa              2606:2800:220:1:248:1893:25c8:1946
mx                0 .
ns                ['a.iana-servers.net.', 'b.iana-servers.net.']
spf               v=spf1 -all
http_status       200
text              Example Domain
                  This domain is for use in illustrative examples in documents. You may use this
                   domain in literature without prior coordination or asking for permission.
                  More informatio
                  n...
```

Should you need just the country the domain/IP is hosted in, use `--field, -f` argument

```bash
$ convey wikipedia.com -f country
Input value detected: hostname

Whois 208.80.154.232... us
field    value
-------  -------
country  us
```

Use `--headless, -H` or `--quiet, -q` flag to shorten the output (and cut down all dialogues).
```bash
$ convey wikipedia.com -f country -H
us
```

Flag `--json` modifies the output.

```bash
$ convey wikipedia.com -f country -H --json
{"country": "us"}
```

#### Computing TLD from another column
To compute a TLD from the abusemail that is being used for the IP domain is hosted in, add a field `abusemail` and then another field `tld`. Specifically say that the latter should source from the second column (which is `abusemail`) – either type '2' or 'abusemail'.

```bash
$ convey example.com -f abusemail -f tld,2
$ convey example.com -f abusemail -f tld,abusemail
Input value detected: hostname

Whois 93.184.216.34... abuse@verizondigitalmedia.com
field      value
---------  -----------------------------
abusemail  abuse@verizondigitalmedia.com
tld        com

```

To prevent `abusemail` from being output, use `--field-excluded, -fe` instead of `--field, -f`:
```bash
$ convey example.com -fe abusemail -f tld,2 -H
Input value detected: hostname

Whois 93.184.216.34... abuse@verizondigitalmedia.com
field    value
-------  -------
tld      com
```

We did not say earlier, user is asked each time whether they wish to get any `tld`, `gTLD` (ex: *com*) or `ccTLD` (ex: *cz*). You may specify it from CLI by one of those equivalent commands.
```bash
$ convey test.csv --fresh --field tld[gTLD]
$ convey test.csv --fresh --field tld,,,gTLD

# flag --yes or --headless will choose the default option which is *all*
$ convey test.csv --fresh --field tld --yes
```

#### CSV processing
Should you have a list of the object that you want to enrich of a CIDR they are hosted at, load the file `test.csv` they are located in.

```csv
# file text.csv
domain list
wikipedia.com
example.com
```

And see the menu just by adding `--field cidr` argument.

```bash
$ convey test.csv -f cidr
Source file: /tmp/ram/test.csv
Identified columns:
Log lines: 3

Sample:
domain list
wikipedia.com
example.com

Delimiter character found: ','
Quoting character: '"'
Header is present: yes

Could you confirm this? [y]/n: (HIT ENTER)

Source file: /tmp/ram/test.csv, delimiter: ',', quoting: '"', header: used
Identified columns: domain list (hostname)
Computed columns: cidr (from domain list)
Log lines: 3

Sample:
domain list
wikipedia.com
example.com

Whois 208.80.154.232... us
Whois 93.184.216.34... abuse@verizondigitalmedia.com
Preview:
domain list      cidr from:
   (hostname)    domain list
---------------  ---------------
wikipedia.com    208.80.152.0/22
example.com      93.184.216.0/24

Main menu - how the file should be processed?
1) Pick or delete columns
2) Add a column
3) Filter
4) Split by a column
5) Change CSV dialect
6) Aggregate
7) Merge
p) process ←←←←←
~) send (split first)
~) show all details (process first)
r) redo...
c) config...
x) exit
?
```

#### File splitting
We will create an ASN field and split the file.csv by this field, without adding it into the output.

```csv
# file.csv
wikipedia.com,443,2016-02-09T01:12:26-05:00,16019,US
seznam.cz,25,2016-02-27T22:20:21-05:00,16019,CZ
google.com,25,2016-02-28T02:27:21-05:00,16019,US
```

```bash
$ convey file.csv --field-excluded asn --split asn
(...)
** Processing completed: 3 result files in /tmp/ram/file.csv_convey1573236314
(...)
```

```csv
# file as14907
wikipedia.com,443,2016-02-09T01:12:26-05:00,16019,US
```

```csv
# file as43037
seznam.cz,25,2016-02-27T22:20:21-05:00,16019,CZ
```

```csv
# file as15169
google.com,25,2016-02-28T02:27:21-05:00,16019,US
```

#### CSIRT Usecase
A CSIRT may use the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then sent by through OTRS from within the tool.
A most of the work is done by this command.
```bash
convey --field-excluded incident_contact,source_ip --split incident_contact --yes [FILENAME]
```

### Custom code field

Adding a column from custom Python code:
```bash
$ convey example.com -f code,"x=x[1:5]"
xamp
```

### Base64 and Regular expressions
Code there and back:
```bash
$ convey hello -f base64  -H  # --headless conversion to base64
aGVsbG8=
$ convey aGVsbG8= -H  # automatically identifies input as base64 and produces plaintext
hello
```

Use a `reg` column for regular expressions.
```bash
# start adding a new reg column wizzard that will take decoded "hello" as input
$ convey aGVsbG8= -f reg
$ convey aGVsbG8= -f reg_s,"ll","LL" -H   # substitute 'll' with 'LL'
heLLo
```

Specify source
```bash
# start adding a new reg column wizzard that will take plaintext from auto-detected base64 "aGVsbG8=" as input
$ convey aGVsbG8= -f reg,plaintext
# specifying plaintext as a source type (and not as a column) will prevent implicit conversion from base64
# Note the 1 that specifies the (first and only) column.
$ convey aGVsbG8= -f reg_s,1,plaintext,"[A-Z]","!" -H  # substitute uppercase letters with '!'
a!!sb!8=
```

### Converting units

We are connected to the [pint](https://pint.readthedocs.io/en/0.9/) unit converter!
```bash
$ convey "3 kg"
Input value detected: unit

field      value
---------  --------------------------------------------------------------------------------------------
plaintext  ['1.806642538265029e+27 atomic_mass_unit', '105.82188584874123 ounce', '96.45223970588393 ap
           othecary_ounce', '0.0703602964419822 bag', '0.05905239165666364 long_hunderweight', '0.06613
           867865546327 US_hundredweight', '0.002952619582833182 UK_ton', '0.002952619582833182 long_to
           n', '1929.0447941176785 pennyweight', '46297.07505882429 grain', '1.7935913792661326e+27 pro
           ton_mass', '771.6179176470714 apothecary_dram', '3000.0 gram', ...]


$ convey "3 kg" -f unit # launches wizzard that let's you decide what unit to convert to
$ convey "3 kg" -f unit[g] -H
3000.0 gram

$ convey "kg" -f unit --csv-processing --headless
kg|6.022141794216764e+26 atomic_mass_unit
kg|0.001 metric_ton
kg|0.0009842065276110606 UK_ton
kg|771.6179176470714 scruple
kg|257.2059725490238 apothecary_dram
kg|1000.0 gram


# You may try to specify the units with no space and quotation.
# In the following example, convey expand all time-units it is able to compute
# – time units will be printed out and each is base64 encoded.
$ convey 3hours
Input value detected: timestamp, unit

field                value
-------------------  ------------------------------------------------------------------
(...)
base64               ['MC4wMDQxMDY4NjM4OTc0NTAwNzcgbW9udGg=', 'MTA4MDAuMCBzZWNvbmQ=', 'MC4wMTc4NTcxNDI4NTcxNDI4NSB3ZWVr']
plaintext            ['0.004106863897450077 month', '10800.0 second', '0.01785714285714285 week', (...)]
time                 03:00:00
(...)

# What if
$ convey 3hours -f urlencode
Input value detected: timestamp, unit

Input unit_expand variable unit: *you type here sec or seconds to see the wizzard*
Preview
| original   | result         |
|------------|----------------|
| 3hours     | 10800.0 second |

field      value
---------  ----------------
urlencode  10800.0%20second

# What if we wanted to urlencode text "3hours" without converting it to unit first?
# Just specify the SOURCE_TYPE to be plaintext:
$ convey "3hours" -f urlencode,plaintext
Input value detected: timestamp, unit

field      value
---------  -------
urlencode  3hours

```

### Country names
When specifying country code, you get country name.
```bash
$ convey --type country sc
Seychelles
```
Lots of countries can be recognized.
```
bash
$ convey --type country_name Futuna
wf
```
You may get the country code from various telephone number formats.
```bash
$ convey +2481234567
Seychelles

$ convey "1-541-754-3010"
['ca', 'us']

$ convey
```

### Aggregate

Syntax is `[COLUMN, FUNCTION], ..., [group-by-COLUMN]`.
Possible functions are:
* avg
* sum
* count
* min
* max
* list
* set


Let's have a file.
```csv
# file.csv
category,price,consumption
bulb,100,30
bulb,150,10
kettle,250,70
kettle,352,80
bulb,120,15
```

Sum the `price` column.
```bash
$ convey file.csv --aggregate price,sum
  sum(price)
------------
         972
```

Group the `price` sum by `category`.
```bash
$ convey file.csv --aggregate price,sum,category
category     sum(price)
---------  ------------
total               972
bulb                370
kettle              602
```

Group the `price` sum and the `consumption` average value by `category`.

```bash
$ convey file.csv --aggregate price,sum,consumption,avg,category
category      sum(price)    avg(consumption)
----------  ------------  ------------------
total                972               41
bulb                 370               18.33
kettle               602               75
```

Group the `price` sum by `category` and list its values.

```bash
$ convey file.csv --aggregate price,sum,price,list,category
category      sum(price)  list(price)
----------  ------------  ---------------------
total                972  (all)
bulb                 370  ['100', '150', '120']
kettle               602  ['250', '352']
```

You can even split while aggregating. Each file will count its own results.

```bash
$ convey file.csv --agg price,sum --split category

Split location: bulb
  sum(price)
------------
         370

Split location: kettle
  sum(price)
------------
         602
```

### Merge

You can merge two file based on a common column.

Imagine a XLS file `person.xls`, containing following rows:

```
john@example.com,foo,male
mary@example.com,foo,female
hyacint@example.com,bar,male
```

And a file `sheet.csv`
```
foo,red,second.example.com
foo,green,first.example.com
bar,blue,wikipedia.org
bar,yellow,example.com
foo,orange,wikipedia.com
```

Get them merged with a single command. We specify the merged file will be `person.xls`, while the common column (`foo/bar`) is the second in the remote and the first in the local `sheet.csv` file.

```bash
$ convey --output --headless --file sheet.csv --merge person.xls,2,1
foo,red,second.example.com,mary@example.com,female
foo,red,second.example.com,john@example.com,male
foo,green,first.example.com,mary@example.com,female
foo,green,first.example.com,john@example.com,male
bar,blue,wikipedia.org,hyacint@example.com,male
bar,yellow,example.com,hyacint@example.com,male
foo,orange,wikipedia.com,mary@example.com,female
foo,orange,wikipedia.com,john@example.com,male
```

* When a pivot key (local column value)
  * is missing from the remote file, the fields on the line stays blank.
  * is found twice, the row gets duplicated.
* Performance note: Working with really huge files? Whereas the local file that you merge to can be of an arbitrary size, the remote file being merged should not be excessively big, it should fit to the RAM.

### Sending images to different recipients
Imagine you have a directory full of PNG files, containg info for respective domain administrators.

```
example.com.png
example.com-2.png
wikipedia.org.png
csirt.cz.png
```

We want to send two images to the admin of `example.com` and single one for `wikipedia.org` and `csirt.cz`. First, create a CSV having first column the domain name and second the respective image. To do so, we use the [pz](https://github.com/CZ-NIC/pz) library.

```
pip3 install pz  # install `pz` if needed
ls *.png | pz 're.sub("-\d+$", "", Path(s).stem),s' > domains_images.csv
```

CSV domains_images.csv now looks like this:

```
example.com	example.com-2.png
example.com	example.com.png
wikipedia.com	wikipedia.com.png
csirt.cz	csirt.cz.png
```

The following command will tell `convey` to add an e-mail column derived from the hostname and when sending files, attach all our images from the path column.

```
convey domains_images.csv  -t hostname,path -f abusemail --split abusemail --attach-files False  --attach-paths-from-path-column True
```

Wizzard will lead you to sending the test mail to you own address. This is the sending a testing e-mail dialog for the `wikipedia.org` domain.

```
Attachment wikipedia.com.png (image/png): PNG...
MIME-Version: 1.0
Subject: PNG that might interest you
To: abuse@wikimedia.org
Date: Fri, 06 Jan 2023 20:04:31 +0100

Body text message
Testing e-mail address to be sent to – type in or hit Enter to use your-testing-mail@example.com (Ctrl+C to go back):
```

## Credits

Brought by [CSIRT.cz](https://csirt.cz).
