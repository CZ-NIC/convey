# Aggregate & merge

## Aggregate

Syntax is `[COLUMN, FUNCTION], ..., [group-by-COLUMN]`.
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
category     sum(price)
---------  ------------
total               972
bulb                370
kettle              602
```

Group the `price` sum and the `consumption` average value by `category`.

```bash
$ convey file.csv --aggregate price,sum,consumption,avg,category
category      sum(price)    avg(consumption)
----------  ------------  ------------------
total                972               41
bulb                 370               18.33
kettle               602               75
```

Group the `price` sum by `category` and list its values.

```bash
$ convey file.csv --aggregate price,sum,price,list,category
category      sum(price)  list(price)
----------  ------------  ---------------------
total                972  (all)
bulb                 370  ['100', '150', '120']
kettle               602  ['250', '352']
```

You can even split while aggregating. Each file will count its own results.

```bash
$ convey file.csv --agg price,sum --split category

Split location: bulb
  sum(price)
------------
         370

Split location: kettle
  sum(price)
------------
         602
```

## Merge

You can merge two file based on a common column.

Imagine a XLS file `person.xls`, containing following rows:

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
    * is missing from the remote file, the fields on the line stays blank.
    * is found twice, the row gets duplicated.
* Performance note: Working with really huge files? Whereas the local file that you merge to can be of an arbitrary size, the remote file being merged should not be excessively big, it should fit to the RAM.

