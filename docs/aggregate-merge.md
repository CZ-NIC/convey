# Aggregate & merge

## Aggregate

Syntax is `--aggregate, -a [COLUMN, FUNCTION], ..., [group-by-COLUMN]`.
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
category      sum(price)
----------  ------------
total                972
kettle               602
bulb                 370
```

Group the `price` sum and the `consumption` average value by `category`.

```bash
$ convey file.csv --aggregate price,sum,consumption,avg,category
category      sum(price)    avg(consumption)
----------  ------------  ------------------
total                972               41
kettle               602               75
bulb                 370               18.33
```

Group the `price` sum by `category` and list its values.

```bash
$ convey file.csv --aggregate price,sum,price,list,category
category      sum(price)  list(price)
----------  ------------  ---------------------
total                972  (all)
kettle               602  ['250', '352']
bulb                 370  ['100', '150', '120']
```

Count the rows in each group. The counted column must be the grouping one.

```bash
$ convey file.csv --aggregate category,count,category
category      count(category)
----------  -----------------
total                       5
bulb                        3
kettle                      2
```

Unique values of a column, no grouping.

```bash
$ convey file.csv --aggregate category,set
set(category)
------------------
{'bulb', 'kettle'}
```

The tables above are printed in the interactive mode (shown here without the menu). For a script, use `--headless --output` to get a CSV.

```bash
$ convey file.csv --aggregate price,sum,category -H --output
category,sum(price)
total,972.0
kettle,602.0
bulb,370.0
```

You can even split while aggregating. Each file counts its own results.

```bash
$ convey file.csv --aggregate price,sum --split category
Split location: bulb
  sum(price)
------------
         370

Split location: kettle
  sum(price)
------------
         602
```

The results are saved in the split files, `--headless --output` prints them as CSV.

```bash
$ convey file.csv --aggregate price,sum --split category -H --output
* Saved to bulb

sum(price)
370.0

* Saved to kettle

sum(price)
602.0
```

## Merge

You can merge two files based on a common column. Syntax is `--merge [REMOTE_PATH],[REMOTE_COLUMN],[LOCAL_COLUMN]`.

Imagine an XLS file `person.xls`, containing the following rows:

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
    * is missing from the remote file, the fields on the line stay blank.
    * is found twice, the row gets duplicated.
* The `--merge` flag may be used multiple times to merge more files.
* Performance note: Working with really huge files? Whereas the local file that you merge to can be of an arbitrary size, the remote file being merged should not be excessively big, it should fit to the RAM.
