# Units & countries

## Converting units

We are connected to the [pint](https://pint.readthedocs.io/en/0.9/) unit converter!
```bash
$ convey "3 kg"
Input value detected: unit

field      value
---------  --------------------------------------------------------------------------------------------
plaintext  ['1.806642538265029e+27 atomic_mass_unit', '105.82188584874123 ounce', '96.45223970588393 ap
           othecary_ounce', '0.0703602964419822 bag', '0.05905239165666364 long_hunderweight', '0.06613
           867865546327 US_hundredweight', '0.002952619582833182 UK_ton', '0.002952619582833182 long_to
           n', '1929.0447941176785 pennyweight', '46297.07505882429 grain', '1.7935913792661326e+27 pro
           ton_mass', '771.6179176470714 apothecary_dram', '3000.0 gram', ...]


$ convey "3 kg" -f unit # launches wizzard that let's you decide what unit to convert to
$ convey "3 kg" -f unit[g] -H
3000.0 gram

$ convey "kg" -f unit --csv-processing --headless
kg|6.022141794216764e+26 atomic_mass_unit
kg|0.001 metric_ton
kg|0.0009842065276110606 UK_ton
kg|771.6179176470714 scruple
kg|257.2059725490238 apothecary_dram
kg|1000.0 gram


# You may try to specify the units with no space and quotation.
# In the following example, convey expand all time-units it is able to compute
# – time units will be printed out and each is base64 encoded.
$ convey 3hours
Input value detected: timestamp, unit

field                value
-------------------  ------------------------------------------------------------------
(...)
base64               ['MC4wMDQxMDY4NjM4OTc0NTAwNzcgbW9udGg=', 'MTA4MDAuMCBzZWNvbmQ=', 'MC4wMTc4NTcxNDI4NTcxNDI4NSB3ZWVr']
plaintext            ['0.004106863897450077 month', '10800.0 second', '0.01785714285714285 week', (...)]
time                 03:00:00
(...)

# What if
$ convey 3hours -f urlencode
Input value detected: timestamp, unit

Input unit_expand variable unit: *you type here sec or seconds to see the wizzard*
Preview
| original   | result         |
|------------|----------------|
| 3hours     | 10800.0 second |

field      value
---------  ----------------
urlencode  10800.0%20second

# What if we wanted to urlencode text "3hours" without converting it to unit first?
# Just specify the SOURCE_TYPE to be plaintext:
$ convey "3hours" -f urlencode,plaintext
Input value detected: timestamp, unit

field      value
---------  -------
urlencode  3hours

```

## Country names
When specifying country code, you get country name.
```bash
$ convey --type country sc
Seychelles
```
Lots of countries can be recognized.
```
bash
$ convey --type country_name Futuna
wf
```
You may get the country code from various telephone number formats.
```bash
$ convey +2481234567
Seychelles

$ convey "1-541-754-3010"
['ca', 'us']

$ convey
```

