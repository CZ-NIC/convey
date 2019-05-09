# Convey

A tool for information conveying – CSV swiss knife brought by [CSIRT.cz](https://csirt.cz). Convenable way to process large files that might freeze your spreadsheet processor.

It takes any CSV or text input (any delimiter, header or whatever) and perform one or more actions:

1) **Pick or delete columns** (if only some columns are needed)
2) **Add a column** (computes one field from another – see below)
3) **Unique filter** (no value duplicates)
4) **Value filter** (only rows with a specific values are preserved)
5) **Split by a column** (produce separate files instead of single file; these can then be sent by generic SMTP or through OTRS)
6) **Change CSV dialect** (change delimiter or quoting character)

Python3.6+ required.

## Examples

```bash
$ convey my-file.csv # will trigger file parsing
$ convey 1.1.1.1 # single value input
Config file loaded from: /home/edvard/.config/convey/config.ini
We think the inputted value can be: ip

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

$ convey 
Do you want to input text (otherwise you'll be asked to choose a file name)? [y/n]
...
```  


## Installation and first run


### Launch as a package:

```bash
# (optional) setup virtual environment
python3 -m venv venv
. venv/bin/activate
(venv) $ ... # continue below

# download from GitHub
pip3 install git+https://github.com/CZ-NIC/convey.git  # without root use may want to use --user

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
* If something is missing on your system, maybe you may find help in this command: `sudo apt install python3-pip git python3-tk && pip3 install setuptools`

### Customisation
* A file `config.ini` is automatically created in user config folder. This file may be edited for further customisation.
* If `config.ini` is present at working directory, that one is used over the one in the user config folder.
* Launch convey with `--help` flag to see further options.

## Computable fields

We are able to compute these value types:

* **abusemail** – got abuse e-mail contact from whois
* **ans** – got from whois
* **base64** – encode/decode
* **country** – country code from whois
* **csirt-contact** – e-mail addres corresponding with country code, taken from your personal contacts_foreign CSV in the format `country,abusemail`. Path to this file has to be specified in `config.ini » contacts_foreign`
* **custom** – you specify method in a custom .py file that receives the field and generates the value for you, see below
* **hostname** – domain from url
* **incident-contact** – if the IP comes from local country (specified in `config.ini » local_country`) the field gets *abusemail*, otherwise we get *country*. When splitting by this field, convey is subsequently able to send the splitted files to local abuse and foreign csirt contacts 
* **ip** – translated from url
* **netname** – got from whois
* **prefix** – got from whois

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
           

### Custom field example
If you wish to compute a **custom** field, you'll be dialogued for a path of a python file and desired method that should be used. The contents of the file can be as simple as this:

```python3
def any_method(value):
    # do something
    return "modified :)"
```

You may as well hard code custom fields in the [`config.ini`](convey/config.ini.default) by providing paths to the entrypoint Python files delimited by a comma: `custom_fields_modules = /tmp/myfile.py, /tmp/anotherfile.py`. All the public methods in the defined files will become custom fields!

Handsome feature if you're willing to use the Shodan API as our partner or to do anything else.

## CSIRT Usecase
We are using the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then sent by through OTRS from within the tool.
