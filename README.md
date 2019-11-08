# Convey

Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`.
Convenable way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.

Any input is accepted: 
* if a **single value** input is detected, all **meaningful information** is fetched
* multiline **base64**/**quoted_printable** string gets decoded
* **log file** is converted to CSV 
* **CSV file** (any delimiter, header or whatever) performs one or more actions
    1) **Pick or delete columns** (if only some columns are needed)
    2) **Add a column** (computes one field from another – see below)
    3) **Unique filter** (no value duplicates)
    4) **Value filter** (only rows with a specific values are preserved)
    5) **Split by a column** (produce separate files instead of single file; these can then be sent by generic SMTP or through OTRS)
    6) **Change CSV dialect** (change delimiter or quoting character)


Python3.6+ required.

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
Again, let's provide an IP to the web service, it returns JSON with WHOIS-related information and scraped HTTP content.
```bash
check
$ pip3 check_if_typeconvey
Location: /home/$USER/.local/lib/python3.7/site-packages
# launch __main__.py with uwsgi (note that LACNIC may freeze for 300 s, hence the timeout recommendation)
$ uwsgi --http :26683 --http-timeout 310 --wsgi-file /home/$USER/.local/lib/python3.7/site-packages/convey/__main__.py

# Access: http://localhost:26683/?q=example.com
# {'ip': '93.184.216.34', 'prefix': '93.184.216.0-93.184.216.255', 'asn': '', 'abusemail': 'abuse@verizondigitalmedia.com', 'country': 'unknown', 'netname': 'edgecast-netblk-03', 'csirt-contact': '-', 'incident-contact': 'unknown', 'status': 200, 'text': 'DNSThe free app that makes your (much longer text...)'}

```

## Installation and first run


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

### Dependencies and troubleshooting
* You'll be asked to install `dialog` library at the first run if not already present in the system.
* If something is missing on your system, maybe you may find help in this command: `sudo apt install python3-pip git python3-tk dialog whois dig nmap curl && pip3 install setuptools && pip3 install --upgrade ipython`

### Customisation
* Launch convey with [`--help`](docs/convey-help-cmd-output.md) flag to see [further options](docs/convey-help-cmd-output.md).
* A file `config.ini` is automatically created in user config folder. This file may be edited for further customisation. Access it with `convey --config`.
> * Convey tries to open the file in the default GUI editor or in the terminal editor if GUI is not an option.
> * If `config.ini` is present at working directory, that one is used over the one in the user config folder.
> * Configuration updates automatically on upgrade. 

## Computable fields

We are able to compute these value types:

* **abusemail** – got abuse e-mail contact from whois
* **asn** – got from whois
* **base64** – encode/decode
* **country** – country code from whois
* **csirt-contact** – e-mail address corresponding with country code, taken from your personal contacts_foreign CSV in the format `country,abusemail`. Path to this file has to be specified in `config.ini » contacts_foreign`
* **external** – you specify method in a custom .py file that receives the field and generates the value for you, see below
* **hostname** – domain from url
* **incident-contact** – if the IP comes from local country (specified in `config.ini » local_country`) the field gets *abusemail*, otherwise we get *country*. When splitting by this field, convey is subsequently able to send the splitted files to local abuse and foreign csirt contacts 
* **ip** – translated from url
* **netname** – got from whois
* **prefix** – got from whois

### Overview of all methods:

![Methods overview](./docs/convey-methods.svg?sanitize=True)

### Detectable fields

We are able to auto-detect these columns: 

* **ip** – standard IPv4 / IPv6 addresses
* **cidr** – CIDR notation, ex: 127.0.0.1/32
* **portIP** – IPv4 in the form 1.2.3.4.port
* **anyIP** – IPv4 garbled in the form `any text 1.2.3.4 any text`
* **hostname** – or FQDN; 2nd or 3rd domain name
* **url** – URL starting with http/https
* **asn** – AS Number
* **base64** – text encoded with base64
* **wrongURL** – URL that has been deactivated by replacing certain chars, ex: "hxxp://example[.]com"
           

### External field example
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
* You may as well directly specify the path and the callable. Since the `--field` has following syntax: *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*, you may omit both *COLUMN* and *SOURCE_TYPE* writing it this way: *FIELD,~~COLUMN,SOURCE_TYPE~~,CUSTOM,CUSTOM*
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
Should there be multiple ways of using your generator, you may decorate with `PickMethod` and let the user decide at the runtime. `PickMethod` has optional `default:str` parameter that specifies default method.

```python3
from convey import PickMethod
PickMethod("all")
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
$ convey file.csv --field any_method[filtered]  # filtered sub-method will be used
```

#### PickInput decorator
If you need a direct user entry before each processing, import `PickInput` and make your method accept *two* parameters. The latter will be set by the user and may have a default value.

```python3
from convey import PickInput
@PickInput
def time_format(val, format="%H:%M"):
    ''' This text will be displayed to the user.
        If running in headless mode, the default format will be "%H:%M" (hours:minutes).   '''
    return dateutil.parser.parse(val).strftime(format)
```

## Examples

### Base64 and Regular expressions
```bash
# -f, --field adding field syntax: FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]
# -H, --headless: just quietly print out single value, no dialog

$ convey hello -f base64  -H  # --headless conversion to base64
aGVsbG8=
$ convey aGVsbG8= -H  # automatically identifies input as base64 and produces plaintext
hello

$ convey aGVsbG8= -f reg  # start adding a new reg column wizzard that will take decoded "hello" as input 
$ convey aGVsbG8= -f reg_s,"ll","LL" -H   # substitute 'll' with 'LL'
heLLo

$ convey aGVsbG8= -f reg,plaintext # start adding a new reg column wizzard that will take plaintext "aGVsbG8=" as input 
# specifying plaintext as a source type will prevent implicit convertion from base64
$ convey aGVsbG8= -f reg_s,plaintext,"[A-Z]","!" -H  # substitute uppercase letters with '!'
a!!sb!8=


# We will create an ASN field and split the file.csv by this field, without adding it into the output.
#
# file.csv
# 1.2.3.4,25,2016-02-28T02:27:21-05:00,16019,CZ
# 5.6.7.8,443,2016-02-09T01:12:26-05:00,16019,CZ
# 9.10.11.12,25,2016-02-27T22:20:21-05:00,16019,CZ
$ convey file.csv --field-excluded asn --split asn

These are equivalent. If "gTLD" is not provided, user will be asked for.
$ convey test.csv --fresh -field tld[gTLD]
$ convey test.csv --fresh -field tld,,,gTLD

We are connected to the pint unit convertor!

$ convey "3 kg" 
Input value detected: unit

field      value
---------  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
plaintext  ['105.82188584874123 ounce', '1693.1501735798597 drachm', '1.806642538265029e+27 atomic_mass_unit', '3.2933076034236e+30 electron_mass', '0.0703602964419822 bag', '6.613867865546327 pound', '4
           6297.07505882429 grain', '8.037686642156995 apothecary_pound', '15000.0 carat', '8.037686642156993 troy_pound', '1929.0447941176785 pennyweight', '3000.0 gram', '0.06613867865546327 short_hund
           erdweight', '0.05905239165666364 long_hunderweight', '771.6179176470714 apothecary_dram', '0.47241913325330914 stone', '1.7935913792661326e+27 proton_mass', '0.06613867865546327 US_hundredweig
           ht', '0.059052391656663636 UK_hundredweight', '0.003306933932773164 US_ton', '0.016872111901903894 quarter', '1.7911224616452038e+27 neutron_mass', '96.45223970588394 troy_ounce', '96.45223970
           588393 apothecary_ounce', '0.003 metric_ton', '2314.853752941214 scruple', '0.003306933932773164 short_ton', '0.002952619582833182 UK_ton', '0.002952619582833182 long_ton']


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


# You may try to specify the units with no space and quotation. In the following example, convey expand all time-units it is able to compute – time units will be printed out and each is base64 encoded. 
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

# What if we wanted to urlencode text "3hours" without converting it to unit first? Just specify the SOURCE_TYPE to be plaintext:
$ convey "3hours" -f urlencode,plaintext
Input value detected: timestamp, unit

field      value
---------  -------
urlencode  3hours

```

## CSIRT Usecase
We are using the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then sent by through OTRS from within the tool.

## Credits

Brought by [CSIRT.cz](https://csirt.cz).
