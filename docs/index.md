# Convey

[![Build Status](https://github.com/CZ-NIC/convey/actions/workflows/run-unittest.yml/badge.svg)](https://github.com/CZ-NIC/convey/actions)
[![Downloads](https://static.pepy.tech/badge/convey)](https://pepy.tech/project/convey)

Swiss knife for mutual conversion of the web related data types, like `base64` or outputs of the programs `whois`, `dig`, `curl`.
A convenient way to quickly gather all meaningful information or to process large files that might freeze your spreadsheet processor.

```bash
pip3 install convey
```

Python 3.10+ required (older releases support up to 3.6). See [Installation](installation.md) for the system prerequisites.

## Three ways to use it

The same engine runs in three modes. Convey decides by the input: a single value is examined, a file (or a multi-line STDIN) is processed as a CSV.

| Mode | Example | What happens |
|------|---------|--------------|
| [Single value](single-value.md) | `convey example.com` | The value type is detected and every meaningful information is computed (whois, DNS, web, conversions…). |
| [CSV processing](csv-processing.md) | `convey file.csv` | An interactive menu (or CLI flags) to pick, add, filter, split, aggregate and merge columns. |
| [Web service](web-service.md) | `convey --server` | The single value mode exposed over HTTP, returning JSON. |

```bash
$ convey aGVsbG8= -H              # base64 is detected and decoded
hello
$ convey wikipedia.com -f country -H
nl
$ convey file.csv --field country --split country   # add a column, split the file by it
```

## What it does

Any input is accepted:

* if a **single value** input is detected, all **meaningful information** is fetched
* multiline **base64**/**quoted_printable** string gets decoded
* **log/XLS/XLSX/ODS file** converted to CSV
* **CSV file** (any delimiter, header or [pandoc](https://pandoc.org/MANUAL.html#tables) table format) performs one or more actions
    1. **Pick, delete or sort columns** (if only some columns are needed)
    2. **Add a column** (computes one field from another – see [computing fields](fields/computing-fields.md))
    3. **Filter** (keep/discard rows with specific values, no duplicates)
    4. **Split by a column** (produce separate files instead of single file; these can then be [sent](sending-files.md) by generic SMTP or through OTRS)
    5. **Change CSV dialect** (change delimiter or quoting character, remove header)
    6. **[Aggregate](aggregate-merge.md#aggregate)** (count grouped by a column, sum...)
    7. **[Merge](aggregate-merge.md#merge)** (join other file)

## Where to go next

* New here? Start with the [single value](single-value.md) mode, it shows the [field syntax](fields/computing-fields.md#field-syntax) used everywhere else.
* Processing files? See [CSV processing](csv-processing.md) and [Aggregate & merge](aggregate-merge.md).
* Missing a conversion? Write your own in Python: [external fields](fields/external-fields.md).
* Every flag is listed in [CLI options](convey-help-cmd-output.md), every option can be made permanent in the [configuration](configuration.md).

## Credits

Brought by [CSIRT.cz](https://csirt.cz).
