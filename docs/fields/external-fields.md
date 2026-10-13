# External fields

When no built-in field fits, write a Python function and convey uses it as a new field.

## Simple custom method

Prepare a file whose contents can be as simple as this:

```python3
# /tmp/myfile.py
def any_method(value):
    # do something
    return "modified :)"
```

### Launch an external method

* When CSV processing, hit *'Add column'* and choose *'new external... from a method in your .py file'*.
* Or append `--field external` to your `convey` command. A dialog for a path of the Python file and desired method will appear.

```bash
$ convey [string_or_filepath] --field external
```

* You may as well directly specify the path and the callable. The `--field` [syntax](computing-fields.md#field-syntax) is *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*, so omit both *COLUMN* and *SOURCE_TYPE* and put the path and the method name as the CUSTOM parts: `external,/tmp/myfile.py,any_method`

```bash
$ convey hello --field external,/tmp/myfile.py,any_method
Input value seems to be plaintext.
field     value
--------  -----------
external  modified :)
```

### Register an external method

Register the file by `--external-fields` and its functions become fields with their own names.

```bash
$ convey hello --external-fields /tmp/myfile.py --field any_method -H
modified :)
```

All the public functions of the file become fields. To register a single one, delimit its name by a colon: `--external-fields /tmp/myfile.py:any_method`.

To have them always available, put them into the [configuration](../configuration.md) file:

```yaml
comp:
  external_fields:
    - /tmp/myfile.py
    - /tmp/anotherfile.py:any_method
```

## List of results possible

If you need a single call to generate multiple rows, return a list. The row accepting a list will be duplicated.

```python3
def two(value):
    return [value + "-foo", value + "-bar"]
```

```bash
$ printf 'a\nx\n' | convey --external-fields /tmp/myfile.py --field two --header False -H --output
"a","a-bar"
"a","a-foo"
"x","x-bar"
"x","x-foo"
```

When convey receives multiple lists, it generates a row for each combination. Ex: If a method returns 2 items and another 3 items, you will receive 6 similar rows.

## PickMethod decorator

Should there be multiple ways of using your generator, place them as methods of a class decorated with `PickMethod` and let the user decide at the runtime. `PickMethod` has an optional `default:str` parameter that specifies the default method. The docstrings are displayed to the user.

```python3
from convey import PickMethod

@PickMethod("all")
class any_method(PickMethod):
    @staticmethod
    def all(x):
        ''' All of them.  '''
        return x

    @classmethod
    def filtered(cls, x):
        ''' Filter some of them '''
        if x in ["a", "b", "c"]:
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
from dateutil import parser

@PickInput
def time_format(val, format="%H:%M"):
    ''' This text will be displayed to the user.
        If running in headless mode, the default format will be "%H:%M" (hours:minutes).   '''
    return parser.parse(val).strftime(format)
```

```bash
$ convey file.csv --field time_format  # user will be asked for a format parameter
$ convey file.csv --field time_format[%M]  # `format` will have the value `%M`
$ convey file.csv --field time_format --yes  # the default `format` `%H:%M` will be used
```

!!! note
    The `code` and `external` fields are disabled in the [web service](../web-service.md) by default.
