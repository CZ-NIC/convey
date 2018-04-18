import re
import base64
from csv import Error, Sniffer, reader
from lib.whois import Whois
from lib.config import Config
from lib.graph import Graph

reIpWithPort = re.compile("((\d{1,3}\.){4})(\d+)")
reAnyIp = re.compile("\"?((\d{1,3}\.){3}(\d{1,3}))")
reFqdn = re.compile(
    "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")  # Xtoo long, infinite loop: ^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$
reUrl = re.compile('[a-z]*://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
reBase64 = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')

"""
     guesses - ways to identify a column
        name: ([usual names], method to identify)
"""
guesses = {"ip": (["ip", "sourceipaddress", "ipaddress", "source"], Whois.checkIp, "valid IP addres"),
           "portIP": ([], reIpWithPort.match, "IP in the form 1.2.3.4.port"),
           "anyIP": ([], reAnyIp.match, "IP in the form 'any text 1.2.3.4 any text'"),
           "hostname": (["fqdn", "hostname", "domain"], reFqdn.match, "2nd or 3rd domain name"),
           "url": (["url", "uri", "location"], reUrl.match, "URL starting with http/https"),
           "asn": (["as", "asn", "asnumber"], lambda field: re.search('AS\d+', field) != None, "AS Number"),
           "base64": (["base64"], lambda field: bool(reBase64.search(field)), "Text encoded with Base64")
           }


# descriptions = defaultdict(str, {
# "ip": "ip address"
# })

class _Guessing:
    # _Guessing.base64(field)
    def base64(field):
        try:
            base64.b64decode(field)
        except:
            return False
        return True


class CsvGuesses:

    def __init__(self, csv):
        self.csv = csv
        self.graph = None
        self.private_fields = [
            "whois"]  # these fields cannot be added (e.g. whois is a temporary made up field, in can't be added to CSV)
        self.extendable_fields = sorted(set([k for _, k in self.methods.keys() if k not in self.private_fields]))

    def getGraph(self):
        """
          returns instance of Graph class with methods converting a field to another
        """
        if not self.graph:
            self.graph = Graph(self.private_fields)
            for m in self.methods:
                self.graph.add_edge(*m[:2])
        return self.graph

    def getMethodsFrom(self, target, start):
        methods = []  # list of lambdas to calculate new field
        path = self.graph.dijkstra(target, start=start)  # list of method-names to calculate new fields
        for i in range(len(path) - 1):
            methods.append(self.methods[path[i], path[i + 1]])
        return methods

    def getSample(self, sourceFile):
        sample = ""
        with open(sourceFile, 'r') as csvfile:
            for i, row in enumerate(csvfile):
                if (i == 0):
                    firstLine = row
                sample += row
                if (
                        i == 8):  # sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                    break
        return firstLine.strip(), sample
        # csvfile.seek(0)
        # csvfile.close()

    def guessDialect(self, sample):
        sniffer = Sniffer()
        try:
            dialect = sniffer.sniff(sample)
            hasHeader = sniffer.has_header(sample)
        except Error:  # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            hasHeader = False  # lets just guess the value
            s = sample.split("\n")[1]  # we dont take header (there is no empty column for sure)
            delimiter = ""
            for dl in (",", ";", "|"):  # lets suppose the doubled sign is delimiter
                if s.find(dl + dl) > -1:
                    delimiter = dl
                    break
            if not delimiter:  # try find anything that ressembles delimiter
                for dl in (",", ";", "|"):
                    if s.find(dl) > -1:
                        delimiter = dl
                        break
            dialect = csv.unix_dialect
            dialect.delimiter = delimiter
        if not dialect.escapechar:
            dialect.escapechar = '\\'
        # dialect.quoting = 3
        dialect.doublequote = True
        return dialect, hasHeader

    # these are known methods to make a field from another field
    methods = {("anyIP", "ip"): lambda x: "Not yet implemented",
               # any IP: "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
               ("portIP", "ip"): lambda x: "Not yet implemented",
               # IP psaná s portem 91.222.204.175.23 -> 91.222.204.175
               ("url", "hostname"): lambda x: Whois.url2hostname(x),
               ("hostname", "ip"): lambda x: Whois.hostname2ip(x),
               ("url", "ip"): lambda x: Whois.url2ip(x),
               ("ip", "whois"): lambda x: Whois(x),
               ("whois", "prefix"): lambda x: (x, str(x.get[0])),
               ("whois", "asn"): lambda x: (x, x.get[3]),
               ("whois", "abusemail"): lambda x: (x, x.get[6]),
               ("whois", "country"): lambda x: (x, x.get[5]),
               ("whois", "netname"): lambda x: (x, x.get[4]),
               ("whois", "csirt-contact"): lambda x: (
                   x, Config.csirtmails[x.get[5]] if x.get[5] in Config.csirtmails else "-"),
               # vraci tuple (local|country_code, whois-mail|abuse-contact)
               ("whois", "incident-contact"): lambda x: (x, x.get[2]),
               ("base64", "plaintext"): lambda x: base64.b64decode(x).decode("UTF-8").replace("\n","\\n"),
               # XX ("url", "cms"): lambda x: "Not yet implemented",
               # XX ("hostname", "cms"): lambda x: "Not yet implemented"
               }

    # f = lambda x: (lambda x,ip: x, ip, x[4])(x.get(), x.ip)

    def getDescription(self, column):
        return guesses[column][2]

    def identifyCols(self):
        """
         Higher score mean bigger probability that the field is of that type
         self.fieldType = { (colI, fieldName): [ {type1: score}, {another possible type: 2}, ...], (2, "a field name"): [{"url": 3}, {"hostname": 1}, ...], ...}

        """
        self.fieldType = {(i, k): {} for i, k in enumerate(self.csv.fields)}
        samples = [[] for _ in self.csv.fields]

        for line in reader(self.csv.sample.split("\n")[1:]):
            for i, val in enumerate(line):
                samples[i].append(val)

        for i, field in enumerate(self.csv.fields):
            print("FIEld", field)
            for key, (names, checkFn, desc) in guesses.items():
                score = 0
                print("Guess:", key, names, checkFn)
                # guess field type by name
                if self.csv.hasHeader:
                    s = field.replace(" ", "").replace("'", "").replace('"', "").lower()
                    for n in names:
                        if s in n or n in s:
                            print("HEADER match", field, names)
                            score += 1
                            break
                #else:
                # guess field type by few values
                hits = 0
                for val in samples[i]:
                    if checkFn(val):
                        print("Match")
                        hits += 1
                perc = hits / len(samples[i])
                if perc == 0:
                    continue
                elif perc > 0.6:
                    print("Function match", field, checkFn)
                    score += 1
                    if perc > 0.8:
                        score += 1
                self.fieldType[i, field][key] = score
                print("hits", hits)
        #from pprint import pprint
        #pprint(self.fieldType)
        #import ipdb; ipdb.set_trace()

    def getBestMethod(self, sourceColI, newField):
        """ return best suited method for given column """
        _min = 999
        method = None
        for _type in self.csv.guesses.fieldType[sourceColI, self.csv.fields[sourceColI]]:
            # a column may have multiple types (url, hostname), use the best
            if _type not in self.getGraph().dijkstra(newField):
                continue
            i = self.getGraph().dijkstra(newField)[_type]
            if i < _min:
                _min, method = i, _type
        return method


"""
    def guessCol(csv, colName, checkFn, names, autodetect=True):
        "" "
        :param o current object of SourceParser
        :param colName "ASN" or "IP"
        :param checkFn auto-checker function so that it knows it guessed right
        :param names - possible IP column names - no space
        "" "
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
        return Dialogue.pickOption(csv.fields, title="What is " + colName + " column:\n[0]. no " + colName + " column", guesses=guesses)
        """
