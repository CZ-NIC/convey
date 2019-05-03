# CHANGELOG

## 1.1 (unreleased)
- fix: do not reprocess file if moved to another location
- fix: empty file check
- fix: dialect ignored when generating a sample, whois inconstitency toughness
- fix: when config file is a symlink and is broken, do not confuse user with creating a new set of config file I.E. in .local/bin. Instead, demand mounting the symlink (or exit or recreate files).
- fix: whois fetching asn + netname again
- '/' is forbidden char in linux file names, when splitting by IP prefix, the char is replaced with a dash
- reading from stdin instead of a file
- when stdin input is a single value, auto-detect it, compute all possible results and quit (use case: inputting a base64 string will decode it, IP will produce all whois information table)
- new file_or_input config flag
- new save_stdin_output config flag
- Config file startup integrity check (you might have missing items since last upgrades)
- dropped default_dir and default_file config items & functionality. I doubt anyone has ever used that. These were to store the incidents directory for the case we did not provide an exact filename to treat when launching convey.
- Adding a column: if there is a single column we can source from, skip the dialog
- Since delimited, quote char and header guesses are mostly right, I stripped two dialog questions to a single one
- Main menu uses "←←←←←" symbol for hinting default value that is triggered when user hits Enter. When you select a processing action you don't have to write "p" for "process" anymore.
- CIDR type
- varying number of columns exception check
- when analyzing, show number of file descriptors currently being written

## 1.0.1 (2018-10-26)
- dropped Python 3.5 support
- python3.6 annotations
- it worked somehow but my colleague faced a strange issue in Whois module. Match object couldn't be called as a dictionary. I stepped out the change to see that Python3.5 support was dropped since 18.8., 51d7a90 , just after the first mature 1.0.0 release.
- logging while processing invalid rows write whole traceback
- file sizes in "show all details"
- csirtmail field fix, creating Config files: wrong path might be reported  …
- superfluous code removed
- better logging of invalid rows
- invalid lines fix, config menu, depickling error fix
- ARIN redirected whois support
- direct results from whois linux command
- fixed invalid line when different length #29
- invalid lines bugfixes


## 1.0.0 (2018-08-10)
- mature version
- Every important feature working as expected.


