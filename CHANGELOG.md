# CHANGELOG

## 1.1 (unreleased)
- fix: do not reprocess file if moved to another location
- fix: empty file check
- fix: dialect ignored when generating a sample, whois inconstitency toughness
- fix: when config file is a symlink and is broken, do not confuse user with creating a new set of config file I.E. in .local/bin. Instead, demand mounting the symlink (or exit or recreate files).
- fix: whois fetching asn + netname again
- '/' is forbidden char in linux file names, when splitting by IP prefix, the char is replaced with a dash

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


