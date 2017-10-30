# Convey

Input: Any CSV that has column with IP addresses or URLs.
Output: Set of CSV grouped by country AND/OR abusemail related to IPs.
These CSVs can be automatically send by your OTRS.

## Translator for OTRS.
 Syntax:
    ./convey.py [--id <OTRS ticket id>] [--num <OTRS ticket number>] [--cookie <OTRS cookie>] [--token <OTRS token>] [<filename>]
 Parameter [filename] is path to source log file in CSV format.
 If [filename] not present, script asks for it.
 Script tries to parse and determine IP and ASN columns.

 Instead of IP column we may use URL column. In that case, script takes the URL domain, translates it to IP and adds a column 'HOST_IP' to CSV. If it finds more IP, it duplicates URL row.

 Dependencies needed are installed by install.sh script.
 -h, --help Show help.


##
Notes:
It is able to parse Apache log format files.
It can bear ##.##.##.##.port format for ip address.
If there is invalid lines, they will come to dedicated file to be reprocessed again.
It connects to all whois servers I know.

I've tried a file with 3,6* 10^6 lines (300 MB). First 600 000 took around 6 minutes to analyze, the rest around two minutes. It asked 369× arin server and 709× ripe server. There were only 960 of unique IPs in 702 different IP prefixes.