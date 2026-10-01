# External field how-to
## Simple custom method
If you wish to compute an **external** field, prepare a file whose contents can be as simple as this:

```python3
def any_method(value):
    # do something
    return "modified :)"
```

### Launch an external method

* When CSV processing, hit *'Add column'* and choose *'new external... from a method in your. py file'*
* Or in the terminal append `--field external` to your `convey` command. A dialog for a path of the Python file and desired method will appear.
```bash
$ convey [string_or_filepath] --field external
```

* You may as well directly specify the path and the callable. Since the `--field` has following syntax:
> *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*

You may omit both *COLUMN* and *SOURCE_TYPE* writing it this way:

> *FIELD,~~COLUMN,SOURCE_TYPE~~,CUSTOM,CUSTOM*
> external,/tmp/myfile.py,any_method
```bash
$ convey [string_or_filepath] --field external,/tmp/myfile.py,any_method
Input value seems to be plaintext.
field     value
--------  -----------------------
external  modified :)
```

### Register an external method

* You may as well hard code custom fields in the [`config.ini`](https://github.com/CZ-NIC/convey/blob/main/convey/config.ini.default) by providing paths to the entry point Python files delimited by a comma: `external_fields = /tmp/myfile.py, /tmp/anotherfile.py`. All the public methods in the defined files will become custom fields!
```editorconfig
[EXTERNAL]
external_fields = /tmp/myfile.py
```

* If this is not needed, you may register one by one by adding new items to the `EXTERNAL` section. Delimit the method name by a colon.
```editorconfig
[EXTERNAL]
any_method = /tmp/myfile.py:any_method
```

## List of results possible
If you need a single call to generate multiple rows, return list, the row accepting a list will be duplicated.

```python3
def any_method(value):
    # do something
    return ["foo", "bar"]
```

When convey receives multiple lists, it generates a row for each combination. Ex: If a method returns 2 items and another 3 items, you will receive 6 similar rows.

## PickMethod decorator
Should there be multiple ways of using your generator, place them as methods of a class decorated with `PickMethod` and let the user decide at the runtime. `PickMethod` has optional `default:str` parameter that specifies the default method.

```python3
from convey import PickMethod

@PickMethod("all")
class any_method(PickMethod):
    def all(x):
        ''' All of them.  '''
        return x

    def filtered(cls, x):
        ''' Filter some of them '''
        if x in country_code_set:
            return x
```

```bash
$ convey file.csv --field any_method  # user will be asked whether to use `all` or `filtered`
$ convey file.csv --field any_method[filtered]  # `filtered` sub-method will be used
$ convey file.csv --field any_method --yes  # the default `all` sub-method will be used
```

## PickInput decorator
If you need a direct user entry before each processing, import `PickInput` and make your method accept *two* parameters. The latter will be set by the user and may have a default value.

```python3
from convey import PickInput
import dateutil

@PickInput
def time_format(val, format="%H:%M"):
    ''' This text will be displayed to the user.
        If running in headless mode, the default format will be "%H:%M" (hours:minutes).   '''
    return dateutil.parser.parse(val).strftime(format)
```

```bash
$ convey file.csv --field time_format  # user will be asked for a format parameter
$ convey file.csv --field time_format[%M]  # `format` will have the value `M%`
$ convey file.csv --field time_time --yes  # the default `format` `%H:%M` will be used
```

