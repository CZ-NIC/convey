# Code, base64 & regex

## Custom code field

Adding a column from custom Python code:
```bash
$ convey example.com -f code,"x=x[1:5]"
xamp
```

## Base64 and Regular expressions
Code there and back:
```bash
$ convey hello -f base64  -H  # --headless conversion to base64
aGVsbG8=
$ convey aGVsbG8= -H  # automatically identifies input as base64 and produces plaintext
hello
```

Use a `reg` column for regular expressions.
```bash
# start adding a new reg column wizzard that will take decoded "hello" as input
$ convey aGVsbG8= -f reg
$ convey aGVsbG8= -f reg_s,"ll","LL" -H   # substitute 'll' with 'LL'
heLLo
```

Specify source
```bash
# start adding a new reg column wizzard that will take plaintext from auto-detected base64 "aGVsbG8=" as input
$ convey aGVsbG8= -f reg,plaintext
# specifying plaintext as a source type (and not as a column) will prevent implicit conversion from base64
# Note the 1 that specifies the (first and only) column.
$ convey aGVsbG8= -f reg_s,1,plaintext,"[A-Z]","!" -H  # substitute uppercase letters with '!'
a!!sb!8=
```

