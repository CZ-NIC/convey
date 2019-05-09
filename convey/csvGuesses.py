import base64
import csv
import importlib.util
import ipaddress
import logging
import os
import re
from builtins import ZeroDivisionError
from csv import Error, Sniffer, reader

from .config import Config
from .contacts import Contacts
from .graph import Graph
from .whois import Whois

logger = logging.getLogger(__name__)

reIpWithPort = re.compile("((\d{1,3}\.){4})(\d+)")
reAnyIp = re.compile("\"?((\d{1,3}\.){3}(\d{1,3}))")
reFqdn = re.compile(
    "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")  # Xtoo long, infinite loop: ^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$
reUrl = re.compile('[a-z]*://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
#reBase64 = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')


def check_ip(ip):
    """ True, if IP is well formatted IPv4 or IPv6 """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_cidr(cidr):
    try:
        ipaddress.ip_interface(cidr)
        try:
            ipaddress.ip_address(cidr)
        except ValueError:  # "1.2.3.4" fail, "1.2.3.4/24" pass
            return True
    except ValueError:
        pass


def wrong_url_2_url(s):
    return s.replace("hxxp", "http", 1).replace("[.]", ".").replace("[:]", ":")

def any_ip_2_ip(s):
    m = reAnyIp.search(s)
    if m:
        return m.group(1)


def port_ip_2_ip(s):
    m = reIpWithPort.match(s)
    if m:
        return m.group(1).rstrip(".")


def b64decode(x):
    try:
        return base64.b64decode(x).decode("UTF-8").replace("\n", "\\n")
    except (UnicodeDecodeError, ValueError):
        return None
    
    
"""
     guesses - ways to identify a column
        {name: ([usual names], method to identify, description) }
"""
guesses = {"ip": (["ip", "sourceipaddress", "ipaddress", "source"], check_ip, "valid IP address"),
           "cidr": (["cidr"], check_cidr, "CIDR 127.0.0.1/32"),
           "portIP": ([], reIpWithPort.match, "IP in the form 1.2.3.4.port"),
           "anyIP": ([], reAnyIp.search, "IP in the form 'any text 1.2.3.4 any text'"),
           "hostname": (["fqdn", "hostname", "domain"], reFqdn.match, "2nd or 3rd domain name"),
           # input "example[.]com" would be admitted as a valid URL
           "url": (["url", "uri", "location"], lambda s: reUrl.match(s) and "[.]" not in s, "URL starting with http/https"),
           "asn": (["as", "asn", "asnumber"], lambda field: re.search('AS\d+', field) is not None, "AS Number"),
           "base64": (["base64"], lambda field: bool(b64decode(field)), "Text encoded with Base64"),  # Xbool(reBase64.search(field))
           "wrongURL": ([], lambda s: reUrl.match(wrong_url_2_url(s)), "Deactivated URL"),
           "plaintext": (["plaintext", "text"], lambda field: False, "Plain text")
           }


class CsvGuesses:

    def __init__(self, csv):
        # import custom methods from files
        for path in (x.strip() for x in Config.get("custom_fields_modules").split(",")):
            try:
                module = self.get_module_from_path(path)
                if module:
                    for method in (x for x in dir(module) if not x.startswith("_")):
                        self.methods[("plaintext", method)] = getattr(module, method)
                        logger.info("Successfully added method {method} from module {path}")
            except Exception as e:
                s = "Can't import custom file from path: {}".format(path)
                input(s + ". Press any key...")
                logger.warning(s)

        self.csv = csv
        self.graph = None
        self.private_fields = [
            "whois"]  # these fields cannot be added (e.g. whois is a temporary made up field, in can't be added to CSV)
        self.extendable_fields = sorted(set([k for _, k in self.methods.keys() if k not in self.private_fields]))
        self.field_type = None

    def get_graph(self):
        """
          returns instance of Graph class with methods converting a field to another
        """
        if not self.graph:
            self.graph = Graph(self.private_fields)
            for m in self.methods:
                self.graph.add_edge(*m[:2])
        return self.graph

    def get_methods_from(self, target, start, custom_module_method):
        """
        Returns the nested lambda list that'll receive a value from start field and should produce value in target field.
        :param target: field name
        :param start: field name
        :param custom_module_method: If target is a 'custom' field, we'll receive a tuple (module path, method name).
        :return: lambda[]
        """
        if custom_module_method:
            return [getattr(self.get_module_from_path(custom_module_method[0]), custom_module_method[1])]
        methods = []  # list of lambdas to calculate new field
        path = self.graph.dijkstra(target, start=start)  # list of method-names to calculate new fields
        for i in range(len(path) - 1):
            methods.append(self.methods[path[i], path[i + 1]])
        return methods

    @staticmethod
    def get_sample(source_file):
        sample = []
        first_line = ""
        with open(source_file, 'r') as csv_file:
            for i, row in enumerate(csv_file):
                if i == 0:
                    first_line = row
                sample.append(row)
                if i == 8:  # sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                    break
        return first_line.strip(), sample
        # csvfile.seek(0)
        # csvfile.close()

    @staticmethod
    def get_module_from_path(path):
        if not os.path.isfile(path):
            return False
        spec = importlib.util.spec_from_file_location("", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def guess_dialect(sample):
        sniffer = Sniffer()
        sample_text = "".join(sample)
        try:
            dialect = sniffer.sniff(sample_text)
            has_header = sniffer.has_header(sample_text)
        except Error:  # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            if sample_text.strip() == "":
                print("The file seems empty")
                quit()
            has_header = False  # lets just guess the value
            try:
                s = sample[1]  # we dont take header (there is no empty column for sure)
            except IndexError:  # there is a single line in the file
                s = sample[0]
            delimiter = ""
            for dl in (",", ";", "|"):  # lets suppose the doubled sign is delimiter
                if s.find(dl + dl) > -1:
                    delimiter = dl
                    break
            if not delimiter:  # try find anything that resembles to a delimiter
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

        if dialect.delimiter == "." and "," not in sample_text:
            # let's propose common use case (bare list of IP addresses) over a strange use case with "." delimiting
            dialect.delimiter = ","
        if len(sample) == 1:
            # there is single line in sample = in the input, so this is definitely not a header
            has_header = False
        return dialect, has_header

    # these are known methods to make a field from another field
    methods = {("anyIP", "ip"): any_ip_2_ip,
               # any IP: "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
               ("portIP", "ip"): port_ip_2_ip,
               # portIP: IP written with a port 91.222.204.175.23 -> 91.222.204.175
               ("url", "hostname"): Whois.url2hostname,
               ("hostname", "ip"): Whois.hostname2ip,
               ("url", "ip"): Whois.url2ip,
               ("ip", "whois"): Whois,
               ("cidr", "whois"): Whois,
               ("whois", "prefix"): lambda x: (x, str(x.get[0])),
               ("whois", "asn"): lambda x: (x, x.get[3]),
               ("whois", "abusemail"): lambda x: (x, x.get[6]),
               ("whois", "country"): lambda x: (x, x.get[5]),
               ("whois", "netname"): lambda x: (x, x.get[4]),
               ("whois", "csirt-contact"): lambda x: (x, Contacts.csirtmails[x.get[5]] if x.get[5] in Contacts.csirtmails else "-"),
               # returns tuple (local|country_code, whois-mail|abuse-contact)
               ("whois", "incident-contact"): lambda x: (x, x.get[2]),
               ("base64", "decoded_text"): b64decode,
               ("plaintext", "base64"): lambda x: base64.b64encode(x.encode("UTF-8")).decode("UTF-8"),
               ("plaintext", "custom"): lambda x: x,
               ("wrongURL", "url"): wrong_url_2_url
               }

    @staticmethod
    def get_description(column):
        return guesses[column][2]

    def identify_cols(self):
        """
         Higher score mean bigger probability that the field is of that type
         self.field_type = { (colI, fieldName): {type1: score, another possible type: 2},
                             (2, "a field name"): {"url": 3, "hostname": 1},
                             ...}

        """
        self.field_type = {(i, k): {} for i, k in enumerate(self.csv.fields)}
        samples = [[] for _ in self.csv.fields]

        if len(self.csv.sample) == 1:  # we have too few values, we have to use them
            s = self.csv.sample[:1]
        else:  # we have many values and the first one could be header, let's omit it
            s = self.csv.sample[1:]

        try:
            for row in reader(s, dialect=self.csv.dialect):
                for i, val in enumerate(row):
                    samples[i].append(val)
        except IndexError:
            print("It seems rows have different lengths. Cannot help you with column identifying.")
            print("First row: " + str(list(enumerate(self.csv.fields))))
            print("Current row: " + str(list(enumerate(row))))
            input("\n... Press any key to continue.")
            return

        for i, field in enumerate(self.csv.fields):
            for key, (names, checkFn, desc) in guesses.items():
                score = 0
                # print("Guess:", key, names, checkFn)
                # guess field type by name
                if self.csv.has_header:
                    s = field.replace(" ", "").replace("'", "").replace('"', "").lower()
                    for n in names:
                        if s in n or n in s:
                            # print("HEADER match", field, names)
                            score += 1
                            break
                # else:
                # guess field type by few values
                hits = 0
                for val in samples[i]:
                    if checkFn(val):
                        # print("Match")
                        hits += 1
                try:
                    percent = hits / len(samples[i])
                except ZeroDivisionError:
                    percent = 0
                if percent == 0:
                    continue
                elif percent > 0.6:
                    # print("Function match", field, checkFn)
                    score += 1
                    if percent > 0.8:
                        score += 1
                self.field_type[i, field][key] = score
                # print("hits", hits)

    def get_fitting_type(self, source_col_i, target_field):
        """ Loops all types the field could be and return the type best suited method for compute new field. """
        _min = 999
        fitting_type = None
        try:
            key = self.field_type[source_col_i, self.csv.fields[source_col_i]]
        except KeyError:  # dynamically added fields
            key = self.csv.fields[source_col_i]  # its name is directly given from self.methods
        dijkstra = self.get_graph().dijkstra(target_field)  # get all fields that new_field is computable from
        for _type in key:
            # loop all the types the field could be
            # a column may have multiple types (url, hostname), use the best
            if _type not in dijkstra:
                continue
            i = dijkstra[_type]
            if i < _min:
                _min, fitting_type = i, _type
        return fitting_type


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
        if csv.is_repeating == False: # dialog goes for first time -> autodetect
            found = False
            for colI, fieldname in enumerate(csv.fields):
                field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
                if (csv.has_header and field in names) or checkFn(field): # file has header, crawl it OR pgrep IP # no IP -> error. May want all different shortened version of IP (notably IPv6).
                    found = True
                    guesses.append(colI)
                    if not info:
                        info = colI, fieldname, colName

            if found and Dialogue.is_yes("Does {}. {} column contains {}?".format(*info)):
                return info[0]

        # col not found automatically -> ask user
        return Dialogue.pick_option(csv.fields, title="What is " + colName + " column:\n[0]. no " + colName + " column", guesses=guesses)
        """
