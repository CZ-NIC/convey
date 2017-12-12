import re
from csv import Error, Sniffer
from lib.dialogue import Dialogue
from lib.whois import Whois
from lib.config import Config

reIpWithPort = re.compile("((\d{1,3}\.){4})(\d+)")
reAnyIp = re.compile("\"?((\d{1,3}\.){3}(\d{1,3}))")
reFqdn = re.compile("^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$")
reUrl = re.compile('[a-z]*://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

"""
     guesses - ways to identify a column
        name: ([usual names], method to identify)
"""
guesses = {"ip": (["ip", "sourceipaddress", "ipaddress", "source"], Whois.checkIp),
        "portIP": ([], reIpWithPort.match),
        "anyIP": ([], reAnyIp.match),
        "hostname": (["fqdn", "hostname", "domain"], reFqdn.match),
        "url": (["url", "uri", "location"], reUrl.match),
        "asn": (["as", "asn", "asnumber"], lambda field: re.search('AS\d+', field) != None)
        }

class CsvGuesses:

    def __init__(self, csv):
        self.csv = csv


    def getSample(self, sourceFile):
        sample = ""
        with open(sourceFile, 'r') as csvfile:
            for i, row in enumerate(csvfile):
                if(i == 0):
                    firstLine = row
                sample += row
                if(i == 8): #sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                    break
        return firstLine.strip(), sample
        #csvfile.seek(0)
        #csvfile.close()

    def guessDelimiter(self, sample):
        sniffer = Sniffer()
        delimiter = ""
        try:
            delimiter = sniffer.sniff(sample).delimiter
            hasHeader = sniffer.has_header(sample)
        except Error: # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            hasHeader = False # lets just guess the value
            s = sample.split("\n")[1] # we dont take header (there is no empty column for sure)
            for dl in (",", ";", "|"): # lets suppose the doubled sign is delimiter
                if s.find(dl + dl) > -1:
                    delimiter = dl
                    break
            if not delimiter: # try find anything that ressembles delimiter
                for dl in (",", ";", "|"):
                    if s.find(dl) > -1:
                        delimiter = dl
                        break
        return delimiter, hasHeader

    # these are known methods to make a field from another field
    methods = {("anyIP", "ip"): lambda x: "Not yet implemented", # any IP: "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
    ("portIP", "ip"): lambda x: "Not yet implemented", # IP psaná s portem 91.222.204.175.23 -> 91.222.204.175
    ("url", "hostname"): lambda x: Whois.url2hostname(x),
    ("hostname", "ip"): lambda x: Whois.hostname2ip(x),
    ("url", "ip"): lambda x: Whois.url2ip(x),
    ("ip", "whois"): lambda x: Whois(x),
    ("whois", "prefix"): lambda x: (x, x.get[0]),
    ("whois", "asn"): lambda x: (x, x.get[3]),
    ("whois", "abusemail"): lambda x: (x, x.getAbusemail()),
    ("whois", "country"): lambda x: (x, x.get[5]),
    ("whois", "netname"): lambda x: (x, x.get[4]),
    ("whois", "csirt-contact"): lambda x: (x, Config.csirtmails[x.get[5]] if x.get[5] in Config.csirtmails else "-"), # vraci tuple (local|country_code, whois-mail|abuse-contact)
    ("whois", "incident-contact"): lambda x: (x, x.get[2]),
    ("url", "cms"): lambda x: "Not yet implemented",
    ("hostname", "cms"): lambda x: "Not yet implemented"}

    f = lambda x: (lambda x,ip: x, ip, x[4])(x.get(), x.ip)

    # these fields can be added (e.g. whois is a temporary made up field, in can't be added to CSV)
    extendable_fields = ["url", "hostname", "prefix", "ip", "asn", "country", "abusemail", "csirt-contact", "incident-contact"]

    def identifyCols(self):
        self.fieldType = {(i,k):[] for i,k in enumerate(self.csv.fields)} # { (colI, fieldName): [type1, another possible type, ...], (2, "a field name"): ["url", "hostname", ...], ...}
        samples = [[] for _ in self.csv.fields]

        for line in self.csv.sample.split("\n")[1:]:
            for i,val in enumerate(line.split(self.csv.delimiter)):
                samples[i].append(val)

        for i, field in enumerate(self.csv.fields):
            print("FIEld", field)
            for key, (names, checkFn) in guesses.items():
                print("Guess:",key,names,checkFn)
                # guess field type by name
                if self.csv.hasHeader and field.replace(" ", "").replace("'", "").replace('"', "").lower() in names:
                    print("HEADER match", field, names)
                    self.fieldType[i,field].append(key)
                else:
                    # guess field type by few values
                    hits = 0
                    for val in samples[i]:
                        if checkFn(val):
                            print("Match")
                            hits += 1
                    if hits/len(samples[i]) > 0.6:
                        print("Function match", field, checkFn)
                        self.fieldType[i,field].append(key)
                    print("hits", hits)


    def guessCol(csv, colName, checkFn, names, autodetect=True):
        """
        :param o current object of SourceParser
        :param colName "ASN" or "IP"
        :param checkFn auto-checker function so that it knows it guessed right
        :param names - possible IP column names - no space
        """
        guesses = []
        info = None
        if csv.isRepeating == False: # dialog goes for first time -> autodetect
            found = False
            for colI, fieldname in enumerate(csv.fields):
                field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
                if (csv.hasHeader and field in names) or checkFn(field): # file has header, crawl it OR pgrep IP # no IP -> error. May want all different shortened version of IP (notably IPv6).
                    found = True
                    guesses.append(colI)
                    if not info:
                        info = colI, fieldname, colName

            if found and Dialogue.isYes("Does {}. {} column contains {}?".format(*info)):
                return info[0]

        # col not found automatically -> ask user
        print("What is " + colName + " column:\n[0]. no " + colName + " column")
        return Dialogue.pickOption(csv.fields, guesses=guesses, colName=colName)