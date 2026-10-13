# CSV processing

Give convey a file and it becomes a CSV processor. Any delimiter, quoting, header or a [pandoc](https://pandoc.org/MANUAL.html#tables) table is detected; log, XLS, XLSX and ODS files are converted to CSV first.

Every action may be chosen either in the interactive menu or by a CLI flag – the flags are just a way to skip the menu.

## Interactive menu

Let's have a list of domains we want to enrich with the CIDR they are hosted at.

```csv
# file test.csv
domain list
wikipedia.com
example.com
```

Load the file and add the `--field cidr` argument.

```bash
$ convey test.csv -f cidr
Source file: /tmp/test.csv
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

Source file: /tmp/test.csv, delimiter: ',', quoting: '"', header: used
Identified columns: domain list (hostname)
Computed columns: cidr (from domain list)
Log lines: 3

Sample:
domain list
wikipedia.com
example.com

Preview:
domain list      cidr from:
   (hostname)    domain list
---------------  ---------------
wikipedia.com    185.15.56.0/22
example.com      172.64.0.0/13

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

Hit `p` to process the file. The result is saved next to the source file, in a directory like `test.csv_convey1791910245/`.

## Non-interactive run

* `--yes, -y` – assume the default answer to every question, process the file and quit.
* `--headless, -H` – the same and also be quiet. Combine with `--output` to print the result.
* `--output` – blank to print the result to STDOUT, or a file name to save it there. If omitted, the file name is invented.

```bash
$ convey test.csv -f cidr -H --output
"domain list","cidr"
"wikipedia.com","185.15.56.0/22"
"example.com","104.16.0.0/12"

$ convey test.csv -f cidr -H --output result.csv   # saved to ./result.csv
```

!!! note
    `--headless` without `--output` prints nothing – the result goes silently to the invented file in the result directory.
    A headless run outputs only when there is something to process (a column added, a filter, a split…).

The output dialect follows the input. Here, the single-column file was detected as quoting all the values.

## Caching

Convey remembers what you did with a file: the detected dialect, the added columns, the processing settings. Next time you open the same file, you continue where you left off. The cache lives in the result directory next to the file. Besides, whois results are cached globally, so that the same prefix is not asked twice.

* `--fresh, -F` – do not load the previous settings nor the global whois cache, start from scratch.
* `--reprocess, -R` – do not load the previous settings, but use the global whois cache.

The examples below use the following file. Add `--fresh` when you play with them, so that the settings of the previous run do not stack.

```csv
# file shop.csv
category,price,consumption
bulb,100,30
bulb,150,10
kettle,250,70
kettle,352,80
bulb,120,15
```

## Column references

Wherever a COLUMN is expected (`--field`, `--delete`, `--split`, `--merge`, filters…), you may use:

* the column position: `1`, `2`, `3`… (counted from 1),
* the position from the right: `-1`, `-2`…,
* the exact column name (from the header): `price`,
* the field type or its usual name: `hostname`, `ip`…

## Pick, delete or sort columns

Delete a column by `--delete, -d`.

```bash
$ convey shop.csv --delete consumption -H --output
category,price
bulb,100
bulb,150
kettle,250
kettle,352
bulb,120
```

Pick and reorder columns by `--sort, -s`. The listed columns are output in the given order, the others are dropped.

```bash
$ convey shop.csv --sort 2,1 -H --output
price,category
100,bulb
150,bulb
250,kettle
352,kettle
120,bulb
```

!!! warning
    `--sort` accepts the column positions only, not their names.

## Add a column

Use `--field, -f` (or `--field-excluded, -fe` for a column you need only as a source, not in the output). The syntax is the same as in the [single value](single-value.md#picking-fields) mode, with the COLUMN part saying which column to compute from.

```bash
$ convey shop.csv -f base64,category -H --output
category,price,consumption,base64
bulb,100,30,YnVsYg==
bulb,150,10,YnVsYg==
kettle,250,70,a2V0dGxl
kettle,352,80,a2V0dGxl
bulb,120,15,YnVsYg==
```

See all the [computable fields](fields/computing-fields.md#field-reference) or write [your own](fields/external-fields.md).

## Filter

Keep the rows with the given value by `--include-filter, -if`, drop them by `--exclude-filter, -ef`.

```bash
$ convey shop.csv --include-filter category,bulb -H --output
category,price,consumption
bulb,100,30
bulb,150,10
bulb,120,15

$ convey shop.csv --exclude-filter category,bulb -H --output
category,price,consumption
kettle,250,70
kettle,352,80
```

Keep only the first row of each value by `--unique, -u`.

```bash
$ convey shop.csv --unique category -H --output
category,price,consumption
bulb,100,30
kettle,250,70
```

## Split by a column

Instead of a single file, produce a file for every value of a column. Each file may then be [sent](sending-files.md) by e-mail.

```bash
$ convey shop.csv --split category -H
$ ls shop.csv_convey*/
bulb  kettle  shop.csv.cache
$ cat shop.csv_convey*/bulb
category,price,consumption
bulb,100,30
bulb,150,10
bulb,120,15
```

Split by a computed column. Here, we create an ASN field and split by it, without adding it to the output.

```csv
# file domains.csv
wikipedia.com,443,2016-02-09T01:12:26-05:00,16019,US
seznam.cz,25,2016-02-27T22:20:21-05:00,16019,CZ
google.com,25,2016-02-28T02:27:21-05:00,16019,US
```

```bash
$ convey domains.csv --field-excluded asn --split asn --yes
(...)
** Processing completed: 3 result files in /tmp/domains.csv_convey1791910245
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

## Change CSV dialect

Override the detected input dialect by `--delimiter`, `--quote-char`, `--header`. Change the output by `--delimiter-output`, `--quote-char-output`, `--header-output`. For a tab, use `tab` or `\t`.

```bash
$ convey shop.csv --delimiter-output ";" -H --output
category;price;consumption
bulb;100;30
(...)

$ convey shop.csv --header-output False -f base64,1 -H --output
bulb,100,30,YnVsYg==
bulb,150,10,YnVsYg==
(...)
```

## Aggregate and merge

Count, sum or list the values grouped by a column, or join another file. See [Aggregate & merge](aggregate-merge.md).

## Input from STDIN

A multiline STDIN is processed as a CSV. Convey guesses whether the first line is a header; say it by `--header` if it guesses wrong.

```bash
$ printf 'wikipedia.org\nexample.com\n' | convey -f country -H --output --header False
"wikipedia.org","nl"
"example.com","us"
```

Use `--csv-processing, -C` to process a single value as a CSV (ex: to get every [unit conversion](single-value.md#units) on its own row).

## CSIRT use case

A CSIRT may use the tool to automate incident handling tasks. The input is any CSV we receive from partners; there is at least one column with IP addresses or URLs. We fetch whois information and produce a set of CSV grouped by country AND/OR abusemail related to IPs. These CSVs are then [sent](sending-files.md) through OTRS or SMTP from within the tool.

Most of the work is done by this command.

```bash
$ convey --field-excluded incident_contact --split incident_contact --yes [FILENAME]
```

The `incident_contact` field holds the abuse e-mail for the IPs from your country and the national CSIRT contact for the others, see [computing fields](fields/computing-fields.md#whois-module).
