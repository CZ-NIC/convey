import csv
import importlib.util
import ipaddress
import logging
import re
import subprocess
from base64 import b64decode, b64encode
from builtins import ZeroDivisionError
from csv import Error, Sniffer, reader
from enum import IntEnum
from pathlib import Path
from typing import List

import ipdb
import requests
from bs4 import BeautifulSoup

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


# reBase64 = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')


def check_ip(ip):
    """ True, if IP is well formatted IPv4 or IPv6 """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class Checker:
    """ To not pollute the namespace, we put the methods here """

    @staticmethod
    def check_cidr(cidr):
        try:
            ipaddress.ip_interface(cidr)
            try:
                ipaddress.ip_address(cidr)
            except ValueError:  # "1.2.3.4" fail, "1.2.3.4/24" pass
                return True
        except ValueError:
            pass

    @staticmethod
    def is_base64(x):
        # there must be at least single letter, port number would be mistaken for base64 fields
        return base64decode(x) and re.search(r"[A-Za-z]", x)

    @staticmethod
    def check_wrong_url(w):
        s = wrong_url_2_url(w)
        return (not reUrl.match(w) and not reFqdn.match(w)) and (reUrl.match(s) or reFqdn.match(s))


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


def base64decode(x):
    try:
        return b64decode(x).decode("UTF-8").replace("\n", "\\n")
    except (UnicodeDecodeError, ValueError):
        return None


class ScrapeUrl:
    """
    :return: self.get = [http status | error, shortened text, original html, redirects]
    """
    cache = {}
    store_html = True
    store_text = True
    headers = {}

    @classmethod
    def init(cls, fields=[]):
        if fields:
            cls.store_html = Types.html in [f.type for f in fields]
            cls.store_text = Types.web in [f.type for f in fields]
        else:
            cls.store_html = cls.store_text = True
        if Config.get("user_agent"):
            cls.headers = {"User-Agent": Config.get("user_agent")}

    def __init__(self, url):
        if url in self.cache:
            self.get = self.cache[url]
            return
        try:
            logger.info("Scrapping " + url + "...")
            response = requests.get(url, timeout=3, headers=self.headers)
        except IOError as e:
            # append("status", 0)
            # append("scrape-error", str(e))
            self.get = str(e), None, None, None
        else:
            response.encoding = response.apparent_encoding  # https://stackoverflow.com/a/52615216/2036148
            if self.store_text:
                soup = BeautifulSoup(response.text, features="html.parser")
                [s.extract() for s in soup(["style", "script", "head"])]  # remove tags with low probability of content
                text = re.sub(r'\n\s*\n', '\n', soup.text)  # reduce multiple new lines to singles
                text = re.sub(r'[^\S\r\n][^\S\r\n]*[^\S\r\n]', ' ', text)  # reduce multiple spaces (not new lines) to singles
            else:
                text = None
            redirects = ""
            for res in response.history[1:]:
                redirects = f"REDIRECT {res.status_code} → {res.url}\n" + text
            self.get = response.status_code, text, response.text if self.store_html else None, redirects
        self.cache[url] = self.get


def nmap(val):
    logger.info(f"NMAPing... {val}")
    text = subprocess.run(["nmap", val], stdout=subprocess.PIPE).stdout.decode("utf-8")
    text = text[text.find("PORT"):]
    text = text[text.find("\n") + 1:]
    text = text[:text.find("\n\n")]
    return text


class TypeGroup(IntEnum):
    general = 1
    custom = 2
    whois = 3
    dns = 4
    ports = 5
    scrape = 6


class Type:
    """
    A field type Convey is able to identify or compute
    """

    def __init__(self, name, group=TypeGroup.general, description=None, usual_names=[], identify_method=None, is_private=False,
                 from_message=None):
        """
        :param name: Key name
        :param description: Help text
        :param usual_names: Names this column usually has (ex: source_ip for an IP column). List of str, lowercase, no spaces.
        :param identify_method: Lambda used to identify a value may be of this field type
        :param is_private: User cannot add the field type (ex: whois, user can extend only netname which is accessed through it).
        """
        self.name = name
        self.group = group
        self.usual_names = usual_names
        self.identify_method = identify_method
        self.description = description
        self.is_private = is_private
        self.from_message = from_message
        types.append(self)
        if self.identify_method or self.usual_names:
            guessable_types.append(self)

    def __eq__(self, other):
        if type(other) is str:
            return self.name == other
        return self.name == other.name

    def __lt__(self, other):
        if isinstance(other, str):
            return self.name < other
        return (self.group, self.name) < (other.group, other.name)

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"Type({self.name})"

    def doc(self):
        s = self.name
        if self.description:
            s += f" ({self.description})"
        if self.usual_names:
            s += f" usual names: " + ", ".join(self.usual_names)
        return s

    def __add__(self, other):  # sometimes we might get compared to string columns names from the CSV
        if isinstance(other, str):
            return self.name + " " + other
        return self.name + " " + other.name

    def __radd__(self, other):  # sometimes we might get compared to string columns names from the CSV
        if isinstance(other, str):
            return other + " " + self.name
        return self.other + " " + self.name


types: List[Type] = []  # all field types
guessable_types: List[Type] = []  # these field types can be guessed from a string


class Types:
    """
    Methods sourcing from private type should return a tuple, with the private type as the first
    Ex: (whois, asn): lambda x: (x, x.get[3])

    """

    whois = Type("whois", TypeGroup.whois, "ask whois servers", is_private=True)
    scrape = Type("scrape", TypeGroup.scrape, "scrape web contents", is_private=True)

    custom = Type("custom", TypeGroup.custom, from_message="from a method in your .py file")
    code = Type("code", TypeGroup.custom, from_message="from a code you write")
    netname = Type("netname", TypeGroup.whois)
    country = Type("country", TypeGroup.whois)
    abusemail = Type("abusemail", TypeGroup.whois)
    prefix = Type("prefix", TypeGroup.whois)
    csirt_contact = Type("csirt_contact", TypeGroup.whois)
    incident_contact = Type("incident_contact", TypeGroup.whois)
    decoded_text = Type("decoded_text", TypeGroup.general)
    web = Type("web", TypeGroup.scrape)
    http_status = Type("http_status", TypeGroup.scrape)
    html = Type("html", TypeGroup.scrape)
    redirects = Type("redirects", TypeGroup.scrape)
    ports = Type("ports", TypeGroup.ports)

    ip = Type("ip", TypeGroup.general, "valid IP address", ["ip", "sourceipaddress", "ipaddress", "source"], check_ip)
    cidr = Type("cidr", TypeGroup.general, "CIDR 127.0.0.1/32", ["cidr"], Checker.check_cidr)
    port_ip = Type("portIP", TypeGroup.general, "IP in the form 1.2.3.4.port", [], reIpWithPort.match)
    any_ip = Type("anyIP", TypeGroup.general, "IP in the form 'any text 1.2.3.4 any text'", [],
                  lambda x: reAnyIp.search(x) and not check_ip(x))
    hostname = Type("hostname", TypeGroup.general, "2nd or 3rd domain name", ["fqdn", "hostname", "domain"], reFqdn.match)
    url = Type("url", TypeGroup.general, "URL starting with http/https", ["url", "uri", "location"],
               lambda s: reUrl.match(s) and "[.]" not in s)  # input "example[.]com" would be admitted as a valid URL)
    asn = Type("asn", TypeGroup.whois, "AS Number", ["as", "asn", "asnumber"],
               lambda x: re.search('AS\d+', x) is not None)
    base64 = Type("base64", TypeGroup.general, "Text encoded with Base64", ["base64"], Checker.is_base64)
    wrong_url = Type("wrongURL", TypeGroup.general, "Deactivated URL", [], Checker.check_wrong_url)
    plaintext = Type("plaintext", TypeGroup.general, "Plain text", ["plaintext", "text"], lambda x: False)


def _get_methods():
    """  these are known methods to make a field from another field
        Note that Whois only produces tuple to be fetchable to stats in Processor, the others are rather strings.
    """
    f = Types
    return {(f.any_ip, f.ip): any_ip_2_ip,
            # any IP: "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
            (f.port_ip, f.ip): port_ip_2_ip,
            # portIP: IP written with a port 91.222.204.175.23 -> 91.222.204.175
            (f.url, f.hostname): Whois.url2hostname,
            (f.hostname, f.ip): Whois.hostname2ip,
            (f.url, f.ip): Whois.url2ip,
            (f.ip, f.whois): Whois,
            (f.cidr, f.ip): lambda x: str(ipaddress.ip_interface(x).ip),
            (f.whois, f.prefix): lambda x: (x, str(x.get[0])),
            (f.whois, f.asn): lambda x: (x, x.get[3]),
            (f.whois, f.abusemail): lambda x: (x, x.get[6]),
            (f.whois, f.country): lambda x: (x, x.get[5]),
            (f.whois, f.netname): lambda x: (x, x.get[4]),
            (f.whois, f.csirt_contact): lambda x: (x, Contacts.csirtmails[x.get[5]] if x.get[5] in Contacts.csirtmails else "-"),
            # returns tuple (local|country_code, whois-mail|abuse-contact)
            (f.whois, f.incident_contact): lambda x: (x, x.get[2]),
            (f.base64, f.decoded_text): base64decode,
            (f.plaintext, f.base64): lambda x: b64encode(x.encode("UTF-8")).decode("UTF-8"),
            (f.plaintext, f.custom): lambda x: x,
            (f.plaintext, f.code): lambda x: x,
            (f.wrong_url, f.url): wrong_url_2_url,
            (f.hostname, f.url): lambda x: "http://" + x,
            (f.ip, f.url): lambda x: "http://" + x,
            (f.url, f.scrape): ScrapeUrl,
            (f.scrape, f.http_status): lambda x: x.get[0],
            (f.scrape, f.web): lambda x: x.get[1],
            (f.scrape, f.html): lambda x: x.get[2],
            (f.scrape, f.redirects): lambda x: x.get[3],
            (f.hostname, f.ports): nmap,
            (f.ip, f.ports): nmap
            # ("hostname", "spf"):
            # XX dns dig
            # XX url decode
            # XX timestamp
            }


methods = _get_methods()
# List of all suitable fields that we may compute from a suitable output
computable_types = sorted({target_type for _, target_type in methods.keys() if not target_type.is_private})


def get_uml():
    """ Return DOT UML source code of types and methods"""
    l = ['digraph { ']
    l.append('label="Convey field types (dashed = identifiable automatically, circled = IO actions)"')
    for f in types:
        label = [f.name]
        if f.description:
            label.append(f.description)
        if f.usual_names:
            label.append("usual names: " + ", ".join(f.usual_names))
        s = "\n".join(label)
        l.append(f'{f.name} [label="{s}"]')
        if f in guessable_types:
            l.append(f'{f.name} [style=dashed]')
        if f.is_private:
            l.append(f'{f.name} [shape=circled]')

    for k, v in methods:
        l.append(f"{k} -> {v};")
    l.append("}")
    return "\n".join(l)


def get_type_names():
    l = []
    for f in types:
        s = f.name
        if f.description:
            s += f" ({f.description})"
        if f.usual_names:
            s += f" usual names: " + ", ".join(f.usual_names)
        l.append(s)
    return "\n* ".join(l)


class Identifier:

    def __init__(self, csv):
        """ import custom methods from files """
        for path in (x.strip() for x in Config.get("custom_fields_modules", get=str).split(",")):
            try:
                module = self.get_module_from_path(path)
                if module:
                    for method in (x for x in dir(module) if not x.startswith("_")):
                        methods[("plaintext", method)] = getattr(module, method)
                        logger.info("Successfully added method {method} from module {path}")
            except Exception as e:
                s = "Can't import custom file from path: {}".format(path)
                input(s + ". Press any key...")
                logger.warning(s)

        self.csv = csv
        self.graph = None
        #self.field_type = None

    def get_graph(self):
        """
          returns instance of Graph class with methods converting a field type to another
        """
        if not self.graph:
            self.graph = Graph([t for t in types if t.is_private])
            [self.graph.add_edge(to, from_) for to, from_ in methods]
        return self.graph

    def get_methods_from(self, target, start, custom_module_method):
        """
        Returns the nested lambda list that'll receive a value from start field and should produce value in target field.
        :param target: field type name
        :param start: field type name
        :param custom_module_method: If target is a 'custom' field type, we'll receive a tuple (module path, method name).
        :return: lambda[]
        """

        def custom_lambda(e):
            def method(x):
                l = locals()
                try:
                    exec(compile(e, '', 'exec'), l)
                except Exception as exception:
                    logger.error(f"{exception}: input value 'x' = {x}, your expression 'e' = {e}")
                    if Config.is_debug():
                        ipdb.set_trace()
                    else:
                        input("We consider 'x' unchanged...")
                    return x
                x = l["x"]
                return x

            return method

        if custom_module_method:
            if type(custom_module_method) is tuple:  # Type.custom
                return [getattr(self.get_module_from_path(custom_module_method[0]), custom_module_method[1])]
            return [custom_lambda(custom_module_method)]  # Type.code
        lambdas = []  # list of lambdas to calculate new field
        path = self.get_graph().dijkstra(target, start=start)  # list of method-names to calculate new fields
        for i in range(len(path) - 1):
            lambdas.append(methods[path[i], path[i + 1]])
        return lambdas

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
        if not Path(path).is_file():
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
            if delimiter:
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

    def init(self, quiet=False):
        """
        Identify self.csv.fields got in __init__
        Sets them possible types (sorted, higher score mean bigger probability that the field is of that type)
        :type quiet: bool If True, we do not raise exception when sample cannot be processed.
                            Ex: We attempt consider user input "1,2,3" as single field which is not, we silently return False
        """
        samples = [[] for _ in self.csv.fields]
        if len(self.csv.sample) == 1:  # we have too few values, we have to use them
            s = self.csv.sample[:1]
        else:  # we have many values and the first one could be header, let's omit it
            s = self.csv.sample[1:]

        for row in reader(s, dialect=self.csv.dialect):
            for i, val in enumerate(row):
                try:
                    samples[i].append(val)
                except IndexError:
                    if not quiet:
                        print("It seems rows have different lengths. Cannot help you with column identifying.")
                        print("Fields row: " + str([(i, str(f)) for i, f in enumerate(self.csv.fields)]))
                        print("Current row: " + str(list(enumerate(row))))
                        if Config.is_debug():
                            ipdb.set_trace()
                        else:
                            input("\n... Press any key to continue.")
                    return False

        for i, field in enumerate(self.csv.fields):
            possible_types = {}
            for type_ in guessable_types:
                score = 0
                # print("Guess:", key, names, checkFn)
                # guess field type by name
                if self.csv.has_header:
                    s = str(field).replace(" ", "").replace("'", "").replace('"', "").lower()
                    for n in type_.usual_names:
                        if s in n or n in s:
                            # print("HEADER match", field, names)
                            score += 1
                            break
                # else:
                # guess field type by few values
                hits = 0
                for val in samples[i]:
                    if type_.identify_method(val):
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

                possible_types[type_] = score
                # print("hits", hits)
            if possible_types:  # sort by biggest score - biggest probability the column is of this type
                field.possible_types = {k: v for k, v in sorted(possible_types.items(), key=lambda k: k[1], reverse=True)}
            else:
                field.possible_types = {Types.plaintext: 1}
        return True

    def get_fitting_type(self, source_field_i, target_field, try_plaintext=False):
        """ Loops all types the field could be and return the type best suited method for compute new field. """
        _min = 999
        fitting_type = None
        possible_fields = list(self.csv.fields[source_field_i].possible_types)
        if try_plaintext:  # try plaintext field as the last one
            possible_fields.append(Types.plaintext)
        dijkstra = self.get_graph().dijkstra(target_field)  # get all fields that new_field is computable from
        for _type in possible_fields:
            # loop all the types the field could be, loop from the FieldType we think the source_col correspond the most
            # a column may have multiple types (url, hostname), use the best
            if _type not in dijkstra:
                continue
            i = dijkstra[_type]
            if i < _min:
                _min, fitting_type = i, _type
        return fitting_type

    def get_fitting_source_i(self, new_field):
        """ Get list of source_i that may be of such a field type that new_field would be computed effectively. """
        valid_types = self.get_graph().dijkstra(new_field)
        possible_cols = {}
        for val in valid_types:  # loop from the best suited type
            for i, f in enumerate(self.csv.fields):  # loop from the column we are most sure with its field type
                if val in f.possible_types:
                    possible_cols[i] = f.possible_types[val]
                    break
        return list(possible_cols)

    def get_fitting_source(self, new_field, column_or_source, source):
        """
        For a new field, we need source column and its field type to compute new field from.
        :param new_field: str of Type
        :param column_or_source: [int|existing name|field name|field usual names]
        :param source: [field name|field usual names]
        :return: (source_field, source_type) or exit.
        """
        source_col_i = None
        source_type = None
        custom = None
        print(new_field, column_or_source, source) # XX
        if column_or_source:  # determine COLUMN
            source_col_i = self.get_column_i(column_or_source)
            if source_col_i is None:
                if source:
                    print("Invalid field", source, ", already having defined field by " + column_or_source)
                    quit()
                else:  # this was not COLUMN but SOURCE_FIELD, COLUMN remains empty
                    source = column_or_source
        else:  # get a column whose field could be fitting for that new_field
            try:
                source_col_i = self.get_fitting_source_i(new_field)[0]
            except IndexError:
                pass
        if source:  # determine SOURCE_FIELD
            if new_field.group is TypeGroup.custom:
                custom = source
                source_type = Types.plaintext
            else:
                source_t = source.lower().replace(" ", "")  # make it seem like a usual field name
                possible = None
                for t in types:
                    if source_t == t:  # exact field name
                        source_type = t
                        break
                    if source_t in t.usual_names:  # usual field name
                        possible = t
                else:
                    if possible:
                        source_type = possible
                if not source_type:
                    print(f"Cannot determine new field from {source_t}")
                    quit()
        if source_col_i is not None and not source_type:
            source_type = self.get_fitting_type(source_col_i, new_field, try_plaintext=True)
            if not source_type:
                print(f"We could not identify a method how to make '{new_field}' from '{self.csv.fields[source_col_i]}'")
                quit()
        if source_type and source_col_i is None:
            # searching for a fitting type amongst existing columns
            # for col in self.
            possibles = {}  # [source col i] = score (bigger is better)
            for i, t in enumerate(self.csv.fields):
                if source_type in t.possible_types:
                    possibles[i] = t.possible_types[source_type]

            try:
                source_col_i = sorted(possibles, key=possibles.get, reverse=True)[0]
            except IndexError:
                print(f"No suitable column of type '{source_type}' found to make field '{new_field}'")
                quit()
        if not source_type or source_col_i is None:
            print(f"No suitable column found for field '{new_field}'")
            quit()
        return self.csv.fields[source_col_i], source_type, custom

    def get_column_i(self, column):
        """
        Useful for parsing user input COLUMN from the CLI args.
        :type column: object Either the order of the column or an exact column name
        :rtype: int Either column_i or None if not found.
        """
        source_col_i = None
        if column.isdigit():  # number of column
            source_col_i = int(column) - 1
        elif column in self.csv.first_line_fields:  # exact column name
            source_col_i = self.csv.first_line_fields.index(column)
        return source_col_i
