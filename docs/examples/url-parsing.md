# URL parsing & CSV

In the examples, we will use these parameters to add a field and to shorten the result.
```bash
# -f, --field adding field syntax: FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]
# -H, --headless: just quietly print out single value, no dialog
```

## URL parsing

### Output formats
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

### Computing TLD from another column
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

### CSV processing
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

### File splitting
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

### CSIRT Usecase
A CSIRT may use the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then sent by through OTRS from within the tool.
A most of the work is done by this command.
```bash
convey --field-excluded incident_contact,source_ip --split incident_contact --yes [FILENAME]
```

