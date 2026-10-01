# Usage

## Usage 1 – Single query
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

## Usage 2 – CSV processor program
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

## Usage 3 – Web service
Again, let's provide an IP to the [web service](web-service.md), it returns JSON with WHOIS-related information and scraped HTTP content.
```bash
$ convey --server  # start a UWSGI session
```
Access in the browser: http://localhost:26683/?q=example.com
```json
{"ip": "93.184.216.34", "prefix": "93.184.216.0-93.184.216.255", "asn": "", "abusemail": "abuse@verizondigitalmedia.com", "country": "unknown", "netname": "edgecast-netblk-03", "csirt-contact": "-", "incident-contact": "unknown", "status": 200, "text": "DNSThe free app that makes your (much longer text...)"}
```

