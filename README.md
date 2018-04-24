# Convey

A tool for information conveying – CSV swiss knife brought by [CSIRT.cz](https://csirt.cz). Convenable way to process large files that might freeze your spreadsheet processor.

It takes any CSV (any delimiter, header or whatever) and perform one or more actions:

1) **Pick or delete columns** (if only some columns are needed)
2) **Add a column** (computes one field from another – see below)
3) **Unique filter** (no value duplicates)
4) **Value filter** (only rows with a specific values are preserved)
5) **Split by a column** (produce separate files instead of single file; these can then be sent by generic SMTP or through OTRS)
6) **Change CSV dialect** (change delimiter or quoting character)

## Installation and first run

On the first run we may want to run installation script to assure dependencies are present. Then, we run convey normally. Parameter [filename] is path to source log file in CSV format.
 If [filename] not present, script asks for it.


```bash
git clone git@github.com:CZ-NIC/convey.git && cd convey && install.sh # on first run we assure some dependencies
convey.py [filename] # program start
convey.py --help # see some flags that help you further automating
``` 

## Computable fields

* **abusemail** – got abuse e-mail contact from whois
* **ans** – got from whois
* **base64** – encode/decode
* **country** – country code from whois
* **csirt-contact** – e-mail addres corresponding with country code, taken from your personal contacts_foreign CSV in the format `country,abusemail`. Path to this file has to be specified in `config.ini » contacts_foreign`
* **hostname** – domain from url
* **incident-contact** – if the IP comes from local country (specified in `config.ini » local_country`) the field gets *abusemail*, otherwise we get *country*. When splitting by this field, convey is subsequently able to send the splitted files to local abuse and foreign csirt contacts 
* **ip** – translated from url
* **netname** – got from whois
* **prefix** – got from whois

## Usecase
We are using the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then sent by our OTRS via HTTP from within the tool.
 
It is able to parse Apache log format files as well.  
It can bear ##.##.##.##.port format for ip address.  
If there is invalid lines, they will come to dedicated file to be reprocessed again.   
It connects to all whois servers I know.

I've tried a file with 3,6* 10^6 lines (300 MB). First 600 000 took around 6 minutes to analyze, the rest around two minutes. It asked 369× arin server and 709× ripe server. There were only 960 of unique IPs in 702 different IP prefixes.
