Launch convey.py and it's all. If a library is not found, you'll be asked to launch install.sh.

Translator for OTRS.
 Syntax:
    ./convey.py [--id <OTRS ticket id>] [--num <OTRS ticket number>] [--cookie <OTRS cookie>] [--token <OTRS token>] [<filename>]
 Parameter [filename] is path to source log file in CSV format.
 If [filename] not present, script asks for it.
 Script tries to parse and determine IP and ASN columns.

 Instead of IP column we may use URL column. In that case, script takes the URL domain, translates it to IP and adds a column 'HOST_IP' to CSV. If it finds more IP, it duplicates URL row.

 Dependencies needed are installed by install.sh script.
 -h, --help Show help.