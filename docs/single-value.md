# Single value

When the input is a single value, convey detects its type and computes every meaningful information it can reach from it – whois record, DNS, the web page, conversions.

!!! note
    Whois, DNS and web results below are real outputs at the time of writing. The records change in time, so yours might differ.

## Everything at once

Put any value as the argument.

```bash
$ convey example.com
Input value hostname

Whois 104.20.23.154... us@@soc@us-cert.gov
Whois example.com... no incident contact.
Scrapped http://example.com (577 bytes)
field             value
----------------  ------------------------------------------------------------------
cidr              104.16.0.0/12
country_name      United States of America
ip                104.20.23.154
tld               com
url               http://example.com
abusemail         abuse@cloudflare.com
asn               as13335
country           us
csirt_contact     soc@us-cert.gov
incident_contact  us@@soc@us-cert.gov
netname           cloudflarenet
prefix            104.16.0.0/12
http_status       200
text              This domain is for use in documentation examples without needing permission. (...)
```

An IP address works the same way. Here, the reverse DNS hostname is scraped too.

```bash
$ convey 1.1.1.1
Input value ip

Whois 1.1.1.1... au@@asd.assist@defence.gov.au;auscert@auscert.org.au
Whois one.one... abuse@one.com
Scrapped http://one.one.one.one (56517 bytes)
field                value
-------------------  ---------------------------------------------------
cidr                 1.1.1.0/24
country_name         Australia
hostname             one.one.one.one
abusemail            helpdesk@apnic.net
asn                  as13335
country              au
netname              apnic-labs
prefix               1.1.1.0/24
http_status          200
(...)
```

Just want to know what the value is? Use `--single-detect`.

```bash
$ convey example.com --single-detect -H
hostname
```

Convey guesses the input type. If the guess is wrong, or the value is ambiguous, state the type with `--type, -t`.

```bash
$ convey --type country sc
Input value country

field         value
------------  ----------
country_name  Seychelles
```

DNS fields (`a`, `aaaa`, `mx`, `ns`, `spf`, `txt`, `dmarc`) and `ports` (nmap) are disabled by default. Enable their module by `--dig` or `--nmap` (or permanently in the [configuration](configuration.md)).

```bash
$ convey example.com -f mx -H
Disabled path at hostname – mx. Launch --config to enable it.
$ convey example.com -f mx --dig -H
0 .
```

## Picking fields

Should you need just the country the domain/IP is hosted in, use `--field, -f`.

```bash
$ convey wikipedia.com -f country
Input value hostname

Whois 185.15.58.226... nl@@cert@ncsc.nl
field    value
-------  -------
country  nl
```

Use `--headless, -H` to shorten the output to the bare value (and cut down all dialogues).

```bash
$ convey wikipedia.com -f country -H
nl
```

Multiple fields? Repeat the flag. Add `--json` to get a machine-readable output.

```bash
$ convey example.com -f ip -f country -H
field    value
-------  --------------
ip       172.66.147.243
country  us

$ convey example.com -f ip -f country -H --json
{"ip": "172.66.147.243", "country": "us"}
```

The full `--field` syntax is `FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]`, see [field syntax](fields/computing-fields.md#field-syntax). Below are the most common uses.

### Computing a field from another field

To compute a TLD from the abusemail of the hosting, add a field `abusemail` and then another field `tld`. Specify that the latter should source from the second column (which is `abusemail`) – either by its position `2` or by its name.

```bash
$ convey example.com -f abusemail -f tld,2
$ convey example.com -f abusemail -f tld,abusemail
Input value hostname

field      value
---------  --------------------
abusemail  abuse@cloudflare.com
tld        com
```

To prevent `abusemail` from being output, use `--field-excluded, -fe` instead of `--field, -f`.

```bash
$ convey example.com -fe abusemail -f tld,2 -H
com
```

### Options asked at runtime

Some fields need an option. Ex: `tld` asks whether you want any TLD, a `gTLD` (ex: *com*) or a `ccTLD` (ex: *cz*). Pass the option in square brackets or as the CUSTOM part of the syntax:

```bash
$ convey example.com -f tld[gTLD] -H
com
$ convey example.com -f tld,,,gTLD -H
com

# flag --yes or --headless chooses the default option (here: all TLDs)
$ convey example.com -f tld --yes
```

### Source type

The SOURCE_TYPE part says what the input should be considered before the conversion. Ex: compute a `netname` from an IP (and not from a hostname or anything else):

```bash
$ convey 1.1.1.1 -f netname,ip -H
apnic-labs
```

## Encodings: base64, urlencode…

Code there and back. The input type is auto-detected, so decoding needs no flag.

```bash
$ convey hello -f base64 -H
aGVsbG8=
$ convey aGVsbG8= -H
hello

$ convey "hello world" -f urlencode -H
hello%20world
$ convey "hello%20world" -H
hello world
```

A multiline base64 or quoted-printable text (ex: pasted from an e-mail source) gets decoded as a whole.

## Regular expressions

Use a `reg_s` field to substitute, `reg_m` to match, or the `reg` field to get a wizard.

```bash
# start a new reg column wizard that takes decoded "hello" as the input
$ convey aGVsbG8= -f reg

# substitute 'll' with 'LL'
$ convey aGVsbG8= -f reg_s,"ll","LL" -H
heLLo
```

Specify the source to prevent the implicit conversion. Here, the base64 string is taken as a plain text and not decoded first. Note the `1` that specifies the (first and only) column.

```bash
# substitute uppercase letters with '!'
$ convey aGVsbG8= -f reg_s,1,plaintext,"[A-Z]","!" -H
a!!sb!8=
```

## Custom code

Compute a field with a Python expression. The variable `x` holds the value; whatever is in `x` at the end is the result.

```bash
$ convey example.com -f code,"x=x[1:5]" -H
xamp
```

Need more than a one-liner? Write a Python file, see [external fields](fields/external-fields.md).

## Units

We are connected to the [pint](https://pint.readthedocs.io/) unit converter!

```bash
$ convey "3 kg"
Input value unit

field      value
---------  ------------------------------------------------------------------------------
plaintext  ['3.29330731727329e+30 electron_mass', '3000000000.0 gamma_mass', '15000.0 carat',
           '0.003 metric_ton', '46297.07505882429 grain', '3000.0 gram', (...)]

$ convey "3 kg" -f unit           # launches a wizard that lets you choose the target unit
$ convey "3 kg" -f unit[g] -H
3000.0 gram
```

Want all the conversions, one per line? Process the value as a CSV with `--csv-processing, -C`.

```bash
$ convey kg -f unit -C -H --output
"kg","0.001 metric_ton"
"kg","5000.0 carat"
"kg","1000.0 gram"
"kg","15432.35835294143 grain"
(...)
```

A time expression may be detected as a time and a unit at once – you get all the time units it can be converted to.

```bash
$ convey 3hours
Input value timestamp

field             value
----------------  --------------------------------------------------------------------
isotimestamp      0000-00-00T03:00:00
plaintext         ['0.125 day', '180.0 minute', '10800 second', '0.01785714285714285 week', (...)]
time              03:00:00
(...)
```

What if we wanted to urlencode the text "3hours" without converting it to a unit first? Specify the SOURCE_TYPE to be `plaintext`.

```bash
$ convey 3hours -f urlencode,plaintext -H
3hours
```

## Countries and phone numbers

When specifying a country code, you get the country name and vice versa.

```bash
$ convey --type country sc -H
Seychelles

$ convey --type country_name Futuna -H
wf
```

You may get the country from various telephone number formats.

```bash
$ convey +2481234567
Input value phone

field         value
------------  ----------
country_name  Seychelles
country       sc

$ convey "1-541-754-3010"
Input value phone

field          value
-------------  ------------------------------------------------
country_name   ['Canada', 'United States of America']
country        ['ca', 'us']
csirt_contact  ['cyberincident@cyber.gc.ca', 'soc@us-cert.gov']
```

## Input from STDIN

The value may be piped or given by `--input, -i`. Use `--single-query, -S` to force the single value mode (ex: for a text containing a comma that would be taken as a CSV).

```bash
$ convey -i wikipedia.org -f country -H
nl
$ echo "hello, hello" | convey -S -f base64 -H
aGVsbG8sIGhlbGxv
```

A multiline STDIN is processed as a CSV, see [CSV processing](csv-processing.md#input-from-stdin).
