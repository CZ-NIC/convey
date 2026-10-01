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
    1. **Pick, delete or sort columns** (if only some columns are needed)
    2. **Add a column** (computes one field from another – see [computing fields](https://cz-nic.github.io/convey/fields/computing-fields/))
    3. **Filter** (keep/discard rows with specific values, no duplicates)
    4. **Split by a column** (produce separate files instead of single file; these can then be sent by generic SMTP or through OTRS)
    5. **Change CSV dialect** (change delimiter or quoting character, remove header)
    6. **Aggregate** (count grouped by a column, sum...)
    7. **Merge** (join other file)

Python3.10+ required (older releases support up to 3.6).

## Credits

Brought by [CSIRT.cz](https://csirt.cz).
