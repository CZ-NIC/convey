import bdb
import csv
import importlib.util
import inspect
import ipaddress
import itertools
import logging
import re
import socket
import subprocess
from abc import ABC, abstractmethod, ABCMeta
from base64 import b64decode, b64encode
from builtins import ZeroDivisionError
from copy import copy
from csv import Error, Sniffer, reader
from datetime import datetime
from difflib import SequenceMatcher
from enum import IntEnum
from pathlib import Path
from quopri import decodestring, encodestring
from statistics import mean
from typing import List
from urllib.parse import unquote, quote, urlparse

import dateutil.parser
import requests
from bs4 import BeautifulSoup
from chardet import detect
from netaddr import IPRange, IPNetwork
from validate_email import validate_email

from .config import Config
from .contacts import Contacts
from .graph import Graph
from .infodicts import is_phone, phone_country, address_country, country_codes
from .whois import Whois

logger = logging.getLogger(__name__)

reIpWithPort = re.compile("((\d{1,3}\.){4})(\d+)")
reAnyIp = re.compile("\"?((\d{1,3}\.){3}(\d{1,3}))")
reFqdn = re.compile(
    "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")  # Xtoo long, infinite loop: ^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$
reUrl = re.compile('[htps]*://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

# reBase64 = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')


types: List["Type"] = []  # all field types
methods = {}
graph = Graph()


class PickBase(ABC):
    default = None

    @abstractmethod
    def get_lambda(self): pass


class PickMethod(PickBase):
    """ If you need to ask a question before computing values,
    make a class with methods that will be considered as options.
    User will be asked what computing option they tend to use,
    whilst the description is taken directly from the methods' __doc__ string.
    Than decorate with @PickMethod with optional default:str parameter that points to the default method.

     Ex: A user should be asked if a generator should return every value or perform a filtering.

     @PickMethod("all")
     class MyValues():
        def all(x):
            ''' return every value (this very text will be displayed to the user) '''
            return x

        def filtered(cls, x):
            ''' return only specific values '''
            if x in my_set:
                return x
    """

    def get_lambda(self, custom=None):
        if custom is None:
            custom = self.default
        for name in self._get_options():
            if name == custom:
                return getattr(self.subtype, name)
        else:
            raise NotImplementedError(f"Option {custom} has not been implemented for {self.subtype}, only {self._get_options()}.")

    def get_options(self):
        """ Return generator of options name and description tuples """
        return ((name, getattr(self.subtype, name).__doc__.strip()) for name in self._get_options())

    def _get_options(self):
        return (name for name in self.subtype.__dict__ if not name.startswith("_"))

    def __init__(self, default: str = None):
        self.default = default

    def __call__(self, subtype):
        self.subtype = subtype
        return self


class PickInput(PickBase):
    """ If your external function need to be setup with a variable first,
     decorate with @PickInput and register a function having two parameters. The second may have a default value.

    In this example, we let the user decide what should be the value of `format` before processing.
    All values will be formatted with the same pattern.

    @PickInput
    def time_format(val, format="%H:%i"):
        ''' this text will be displayed to the user '''
        return dateutil.parser.parse(val).strftime(format)

    """

    def get_lambda(self, custom=None):
        if custom:
            return lambda x: self.subtype(x, custom)
        else:
            return lambda x: self.subtype(x)

    def __init__(self, subtype):
        self.subtype = subtype
        par = list(inspect.signature(subtype).parameters)
        if len(par) != 2:
            raise RuntimeError(f"Cannot import {subtype.__name__}, it has not got two parameters.")
        p = inspect.signature(subtype).parameters[par[1]]
        self.default = None if p.default is p.empty else p.default
        self.description = subtype.__doc__ or (f"Input {subtype.__name__} variable " + par[1])
        self.parameter_name = par[0]


def is_ip(ip):
    """ True, if IP is well formatted IPv4 or IPv6 """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class Checker:
    """ To not pollute the namespace, we put the methods here """

    hostname_ips_cache = {}
    hostname_cache = {}

    @staticmethod
    def hostname2ips(hostname):
        if hostname not in Checker.hostname_ips_cache:
            try:
                Checker.hostname_ips_cache[hostname] = list({addr[4][0] for addr in socket.getaddrinfo(hostname, None)})
            except OSError:
                Checker.hostname_ips_cache[hostname] = []
        return Checker.hostname_ips_cache[hostname]

    @classmethod
    def hostname2ip(cls, hostname):
        if hostname not in cls.hostname_cache:
            try:
                cls.hostname_cache[hostname] = socket.gethostbyname(hostname)
            except OSError:
                cls.hostname_cache[hostname] = False
        return cls.hostname_cache[hostname]

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
        """ 1. We consider base64-endocded only such strings that could be decoded to UTF-8
                because otherwise any ASCII input would be considered as base64, even when well readable at first sight
            2. There must be at least single letter, port number would be mistaken for base64 fields """
        try:
            return b64decode(x).decode("UTF-8") and re.search(r"[A-Za-z]+", x)
        except (UnicodeDecodeError, ValueError):
            return None

    @staticmethod
    def is_quopri(x):
        try:
            return decodestring(x).decode("UTF-8") != x
        except (UnicodeDecodeError, ValueError):
            return False

    @staticmethod
    def bytes_plaintext(x):
        try:
            return x.decode("UTF-8").replace("\n", r"\n")
        except UnicodeDecodeError:
            enc = detect(x)["encoding"]
            # Czech phrase: "Žluťoučký kůň pěl ďábelské ódy.".encode("iso-8859-2")
            # results in turkish {'encoding': 'ISO-8859-9', 'confidence': 0.47567063613812527, 'language': 'Turkish'}
            # which is not perfect but better than nothing.
            if enc:
                return x.decode(enc)
            return x

    @staticmethod
    def is_urlencode(x):
        return unquote(x) != x

    @staticmethod
    def check_wrong_url(wrong):
        if (reUrl.match(wrong) and "[.]" not in wrong) or reFqdn.match(wrong) or is_ip(wrong):
            # input "example[.]com" would be admitted as a valid URL)
            return False
        s = wrong_url_2_url(wrong, make=False)
        s2 = wrong_url_2_url(wrong, make=True)
        #Xm = reUrl.match(s2)
        if reFqdn.match(s) or reFqdn.match(urlparse(s2).netloc):  #X(m and m.span(0)[1] == len(s2) and "." in s2):
            #Xwe impose full match
            #Xstring created from "x"*100 would be submitted for a valid URL
            return True
        return False

    @staticmethod
    @PickInput
    def decode(val, encoding="utf-8"):
        if type(val) is str:
            val = val.encode("utf-8")
        return val.decode(encoding).replace("\n", r"\n")

    @staticmethod
    @PickInput
    def time_format(val, fmt):
        return dateutil.parser.parse(val, fuzzy=True).strftime(fmt)

    @staticmethod
    def is_timestamp(val):
        try:
            o = dateutil.parser.parse(val)
            reference = datetime.now()
            if not (o.second == o.minute == o.hour == 0 and o.day == reference.day and o.month == reference.month):
                # if parser accepts a plain number, ex: 1920,
                # it thinks this is a year without time (assigns midnight) and without date (assigns current date)
                # We try to skip such result.
                return True
        except ValueError:
            pass
        except OverflowError:
            return False

        try:
            o = Checker.parse_timestamp(val)
            if 2100 > o.year > 1900 and not (o.second == o.minute == o.hour == 0 and o.day == o.month == 1):
                # this year seems reasonable and it is not suspicious
                # fuzzy search often return crazy things like year from port number - these records have 1 Jan midnight
                return True
        except ValueError:
            pass
        return False

    default_datetime = datetime(1, 1, 1)

    @staticmethod
    def parse_timestamp(val):
        try:
            return dateutil.parser.parse(val, fuzzy=True, default=Checker.default_datetime)
        except OverflowError:
            return Checker.default_datetime

    @staticmethod
    def isotimestamp(val):
        o = Checker.parse_timestamp(val)
        s = o.isoformat()
        if o.year == 1:  # this is a fake year from our default_datetime object
            s = "0000-00-00" + s[10:]
        return s

    @staticmethod
    def date(val):
        o = Checker.parse_timestamp(val)
        if o.year == 1:  # this is a fake year from our default_datetime object
            return ""
        return o.date()

    @staticmethod
    @PickMethod("all")
    class HostnameTld:
        @staticmethod
        def all(x):
            """ take all TLD """
            x = x[x.rindex(".") + 1:]
            if not x.isdigit():
                return x

        @classmethod
        def ccTLD(cls, x):
            """ country code only """
            x = cls.all(x)
            return x if len(x) == 2 else ""

        @classmethod
        def gTLD(cls, x):
            """ generic only """
            x = cls.all(x)
            return x if len(x) != 2 else ""

    @staticmethod
    def prefix_cidr(val):
        return IPRange(*val.split("-")).cidrs()

    @staticmethod
    def cidr_ips(val):
        return [ip for ip in IPNetwork(val)]


def wrong_url_2_url(s, make=True):
    s = s.replace("hxxp", "http", 1).replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if make and not s.startswith("http"):
        s = "http://" + s
    return s


def any_ip_2_ip(s):
    m = reAnyIp.search(s)
    if m:
        return m.group(1)


def port_ip_2_ip(s):
    m = reIpWithPort.match(s)
    if m:
        return m.group(1).rstrip(".")


class Web:
    """
    :return: self.get = [http status | error, shortened text, original html, redirects, x-frame-options, csp]
    """
    cache = {}
    store_html = True
    store_text = True
    headers = {}

    @classmethod
    def init(cls, fields: List = None):
        if fields:
            cls.store_html = Types.html in [f.type for f in fields]
            cls.store_text = Types.text in [f.type for f in fields]
        else:
            cls.store_html = cls.store_text = True
        if Config.get("user_agent", "FIELDS"):
            cls.headers = {"User-Agent": Config.get("user_agent", "FIELDS")}

    def __init__(self, url):
        if url in self.cache:
            self.get = self.cache[url]
            return
        logger.info(f"Scrapping {url}...")
        redirects = []
        current_url = url
        while True:
            try:
                logger.debug(f"Scrapping connection to {current_url}")
                response = requests.get(current_url, timeout=3, headers=self.headers, allow_redirects=False)
            except IOError as e:
                if isinstance(e, requests.exceptions.HTTPError):
                    s = "Http error"
                elif isinstance(e, requests.exceptions.ConnectionError):
                    s = "Error Connecting"
                elif isinstance(e, requests.exceptions.Timeout):
                    s = "Timeout Error:"
                elif isinstance(e, requests.exceptions.RequestException):
                    s = "Oops : Something Else"
                else:
                    s = e
                self.cache[url] = self.get = str(s), None, None, redirects, None, None
                break
            if response.headers.get("Location"):
                current_url = response.headers.get("Location")
                redirects.append(current_url)
                continue
            else:
                response.encoding = response.apparent_encoding  # https://stackoverflow.com/a/52615216/2036148
                if self.store_text:
                    soup = BeautifulSoup(response.text, features="html.parser")
                    # check redirect
                    res = soup.select("meta[http-equiv=refresh i]")
                    if res:
                        wait, txt = res[0].attrs["content"].split(";")
                        m = re.search(r"http[^\"'\s]*", txt)
                        if m:
                            current_url = m.group(0)
                            redirects.append(current_url)
                            continue
                    # prepare content to be shortened
                    [s.extract() for s in soup(["style", "script", "head"])]  # remove tags with low probability of content
                    text = re.sub(r'\n\s*\n', '\n', soup.text)  # reduce multiple new lines to singles
                    text = re.sub(r'[^\S\r\n][^\S\r\n]*[^\S\r\n]', ' ', text)  # reduce multiple spaces (not new lines) to singles
                else:
                    text = None
                # for res in response.history[1:]:
                #     redirects += f"REDIRECT {res.status_code} → {res.url}\n" + text
                #     redirects.append(res.url)
                self.cache[url] = self.get = response.status_code, text, response.text if self.store_html else None, \
                                             redirects, \
                                             response.headers.get('X-Frame-Options', None), \
                                             response.headers.get('Content-Security-Policy', None)
                if current_url == url:
                    break
                url = current_url


def dig(rr):
    def dig_query(query):
        if rr == "SPF":
            t = "TXT"
        elif rr == "DMARC":
            query = "_dmarc." + query
            t = "TXT"
        else:
            t = rr
        text = subprocess.check_output(["dig", "+short", "-t", t, query]).decode("utf-8")
        if text.startswith(";;"):
            return None
        spl = text.split("\n")[:-1]
        if t == "TXT":
            spl = [r[1:-1] for r in spl if r.startswith('"') and r.endswith('"')]  # row without " may be CNAME redirect
            if rr == "SPF":
                return [r for r in spl if r.startswith('v=spf')]
            elif rr == "TXT":
                return [r for r in spl if not r.startswith('v=spf')]
        return spl

    return dig_query


def nmap(val):
    logger.info(f"NMAPing {val}...")
    text = subprocess.run(["nmap", val], stdout=subprocess.PIPE).stdout.decode("utf-8")
    text = text[text.find("PORT"):]
    text = text[text.find("\n") + 1:]
    text = text[:text.find("\n\n")]
    return text


methods_deleted = {}


class TypeGroup(IntEnum):
    general = 1
    custom = 2
    whois = 3
    dns = 4
    nmap = 5
    web = 6

    def disable(self):
        for start, target in copy(methods):
            if start.group is self or target.group is self:
                methods_deleted[start, target] = methods[start, target]
                del methods[start, target]
        for t in Types.get_guessable_types():
            if t.group is self:
                t.is_disabled = True


class Type:
    """
    A field type Convey is able to identify or compute
    """

    def __init__(self, name, group=TypeGroup.general, description="", usual_names=[], identify_method=None, is_private=False,
                 from_message=None, usual_must_match=False):
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
        self.usual_must_match = usual_must_match
        self.identify_method = identify_method
        self.description = description
        self.is_private = is_private
        self.is_disabled = False  # disabled field cannot be added (and computed)
        self.from_message = from_message
        types.append(self)
        # Type considered equal when starting computing.
        # Ex: hostname from source_ip will be computed as if from an ip.
        # So that Types.source_ip will have `computing_start = ip`
        self.computing_start: Type = self
        # Types considered equal to be computed from.
        # Ex: hostname from ip may be computed even from a source_ip.
        # So that Types.ip will have `equals = [ip, source_ip]`
        self.equals: List["Types"] = [self]
        self.is_plaintext_derivable = False

    def __getstate__(self):
        return str(self)

    def __setstate__(self, state):
        self.__dict__.update(getattr(Types, state).__dict__)

    def __eq__(self, other):
        if other is None:
            return False
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

    def init(self):
        """ Init self.computing_start and self.equals . """
        computing_start = [stop for start, stop in methods if start is self and methods[start, stop] is True]
        equals = [start for start, stop in methods if stop is self and methods[start, stop] is True]
        if len(computing_start) == 1:
            self.computing_start = computing_start[0]
        elif len(computing_start):
            raise RuntimeWarning(f"Multiple 'computing_start' types defined for {self}: {computing_start}")
        if equals:
            self.equals = equals + [self]

        # check if this is plaintext derivable
        if self != Types.plaintext:
            self.is_plaintext_derivable = bool(graph.dijkstra(self, start=Types.plaintext))

    def check_conformity(self, samples, has_header, field):
        """
        :rtype: int|False Score if the given info conforms to this type.
        """
        score = 0
        # print("Guess:", key, names, checkFn)
        # guess field type by name

        if has_header:
            s = str(field).replace(" ", "").replace("'", "").replace('"', "").lower()
            for n in self.usual_names:
                if s in n or n in s:
                    # print("HEADER match", field, self, self.usual_names)
                    score += 2 if self.usual_must_match else 1
                    break
        if not score and self.usual_must_match:
            return False
        # else:
        # guess field type by few values
        hits = 0
        for val in samples:
            if self.identify_method(val):
                # print("Match")
                hits += 1
        try:
            percent = hits / len(samples)
        except ZeroDivisionError:
            percent = 0
        if percent == 0:
            return False
        elif percent > 0.6:
            # print("Function match", field, checkFn)
            score += 1
            if percent > 0.8:
                score += 1
        return score


class Types:
    """
    Methods sourcing from private type should return a tuple, with the private type as the first
    Ex: (whois, asn): lambda x: (x, x.get[3])

    """

    @staticmethod
    def refresh():
        methods.clear()
        methods.update(Types._get_methods())
        [graph.add_edge(to, from_) for to, from_ in methods if methods[to, from_] is not True]
        [t.init() for t in types]

        """ import custom methods from files """
        try:
            externals = Config.config["EXTERNAL"]
        except KeyError:
            externals = []
        for field_name in externals:
            if field_name == "external_fields":  # this is a genuine field, user did not make it
                continue
            path, method_name = Config.config["EXTERNAL"][field_name].rsplit(":")
            module = Identifier.get_module_from_path(path)
            Types.import_method(module, method_name, path, name=field_name)

        for path in (x.strip() for x in Config.get("external_fields", "EXTERNAL", get=str).split(",") if x.strip()):
            try:
                module = Identifier.get_module_from_path(path)
                if module:
                    for method_name in (x for x in dir(module) if not x.startswith("_")):
                        Types.import_method(module, method_name, path)
            except bdb.BdbQuit:
                raise
            except Exception as e:
                s = "Can't import custom file from path: {}".format(path)
                input(s + ". Press any key...")
                logger.warning(s)

    @staticmethod
    def import_method(module, method_name, path, name=None):
        if not name:
            name = method_name
        lambda_ = getattr(module, method_name)
        if isinstance(lambda_, ABCMeta):  # this is just an import statement of ex: PickBase
            return
        setattr(Types, name, Type(name, TypeGroup.general, lambda_.__doc__))  # fachá?
        type_ = getattr(Types, name)
        methods[(Types.plaintext, type_)] = lambda_
        if lambda_ is not True:
            graph.add_edge(Types.plaintext, type_)
        type_.init()
        logger.debug(f"Successfully added method {method_name} from module {path}")

    @staticmethod
    def find_type(source_type_candidate):
        source_type = None
        source_t = source_type_candidate.lower().replace(" ", "")  # make it seem like a usual field name
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
        return source_type

    whois = Type("whois", TypeGroup.whois, "ask whois servers", is_private=True)
    web = Type("web", TypeGroup.web, "scrape web contents", is_private=True)

    external = Type("external", TypeGroup.custom, from_message="from a method in your .py file")
    code = Type("code", TypeGroup.custom, from_message="from a code you write")
    reg = Type("reg", TypeGroup.custom, from_message="from a regular expression")
    reg_s = Type("reg_s", TypeGroup.custom, from_message="substitution from a regular expression")
    reg_m = Type("reg_m", TypeGroup.custom, from_message="match from a regular expression")
    netname = Type("netname", TypeGroup.whois)
    country = Type("country", TypeGroup.whois)
    abusemail = Type("abusemail", TypeGroup.whois)
    prefix = Type("prefix", TypeGroup.whois)  # XX rename to 'inetnum'? to 'range'?
    csirt_contact = Type("csirt_contact", TypeGroup.whois)
    incident_contact = Type("incident_contact", TypeGroup.whois)
    text = Type("text", TypeGroup.web)
    http_status = Type("http_status", TypeGroup.web)
    html = Type("html", TypeGroup.web)
    redirects = Type("redirects", TypeGroup.web)
    x_frame_options = Type("x_frame_options", TypeGroup.web)
    csp = Type("csp", TypeGroup.web)
    ports = Type("ports", TypeGroup.nmap)
    spf = Type("spf", TypeGroup.dns)
    txt = Type("txt", TypeGroup.dns)
    a = Type("a", TypeGroup.dns)
    aaaa = Type("aaaa", TypeGroup.dns)
    ns = Type("ns", TypeGroup.dns)
    mx = Type("mx", TypeGroup.dns)
    dmarc = Type("dmarc", TypeGroup.dns)
    tld = Type("tld", TypeGroup.general)
    formatted_time = Type("formatted_time", TypeGroup.general)
    isotimestamp = Type("isotimestamp", TypeGroup.general)
    time = Type("time", TypeGroup.general)
    date = Type("date", TypeGroup.general)
    bytes = Type("bytes", TypeGroup.general, is_private=True)
    charset = Type("charset", TypeGroup.general)
    country_name = Type("country_name", TypeGroup.general)  # XX not identifiable, user has to be told somehow there is such method
    phone = Type("phone", TypeGroup.general, "telephone number", ["telephone", "tel"], is_phone)

    timestamp = Type("timestamp", TypeGroup.general, "time or date", ["time"], Checker.is_timestamp)
    ip = Type("ip", TypeGroup.general, "valid IP address", ["ip", "ipaddress"], is_ip)
    source_ip = Type("source_ip", TypeGroup.general, "valid source IP address",
                     ["sourceipaddress", "source", "src"], is_ip, usual_must_match=True)
    destination_ip = Type("destination_ip", TypeGroup.general, "valid destination IP address",
                          ["destinationipaddress", "destination", "dest", "dst"], is_ip, usual_must_match=True)
    cidr = Type("cidr", TypeGroup.general, "CIDR 127.0.0.1/32", ["cidr"], Checker.check_cidr)
    port_ip = Type("port_ip", TypeGroup.general, "IP in the form 1.2.3.4.port", [], reIpWithPort.match)
    any_ip = Type("any_ip", TypeGroup.general, "IP in the form 'any text 1.2.3.4 any text'", [],
                  lambda x: reAnyIp.search(x) and not is_ip(x))
    hostname = Type("hostname", TypeGroup.general, "2nd or 3rd domain name", ["fqdn", "hostname", "domain"], reFqdn.match)
    email = Type("email", TypeGroup.general, "E-mail address", ["mail"], validate_email)
    url = Type("url", TypeGroup.general, "URL starting with http/https", ["url", "uri", "location"],
               lambda s: reUrl.match(s) and "[.]" not in s)  # input "example[.]com" would be admitted as a valid URL)
    asn = Type("asn", TypeGroup.whois, "AS Number", ["as", "asn", "asnumber"],
               lambda x: re.search('AS\d+', x) is not None)
    base64 = Type("base64", TypeGroup.general, "Text encoded with Base64", ["base64"], Checker.is_base64)
    quoted_printable = Type("quoted_printable", TypeGroup.general, "Text encoded as quotedprintable", [], Checker.is_quopri)
    urlencode = Type("urlencode", TypeGroup.general, "Text encoded with urlencode", ["urlencode"], Checker.is_urlencode)
    wrong_url = Type("wrong_url", TypeGroup.general, "Deactivated URL", [], Checker.check_wrong_url)
    plaintext = Type("plaintext", TypeGroup.general, "Plain text", ["plaintext", "text"], lambda x: False)

    @staticmethod
    def get_computable_types(ignore_custom=False):
        """ List of all suitable fields that we may compute from a suitable output
        :type ignore_custom: bool Ignore types that may not be reachable because user input would be needed.
            These are TypeGroup.custom and instances of PickBase.
        """
        s = set()
        for (_, target_type), m in methods.items():
            if ignore_custom and (target_type.group == TypeGroup.custom or (isinstance(m, PickBase) and not m.default)):
                continue
            if target_type.is_private or target_type.is_disabled:
                continue
            s.add(target_type)
        return sorted(s)

    @staticmethod
    def get_guessable_types() -> List[Type]:
        """ these field types can be guessed from a string """
        return sorted([t for t in types if not t.is_disabled and (t.identify_method or t.usual_names)])

    @staticmethod
    def get_uml():
        """ Return DOT UML source code of types and methods
            dashed nodes = identifiable automatically
            dashed edges = lambda-True relation (see _get_methods() help)
            squares = category border
            edge label = possible ways of processing (@PickBase decorated methods)
        """
        l = ['digraph { ', 'label="Convey field types (dashed nodes = identifiable automatically)"']
        used = set()
        formatting_disabled = "[color=lightgray fontcolor=lightgray]"
        loop = []
        existing_edges = set()

        def add(start, target, disable_s):
            if (start, target) not in used:
                used.add((start, target))
                used.add((target, start))
                if not disable_s:
                    used.update([start, target])
                l.append(f"{start} -> {target}{disable_s}")
                if (target, start) in existing_edges:
                    l[-1] += "[dir=both]"
                return True
            return False

        for enabled, ((start, target), m) in [(True, f) for f in methods.items()] + [(False, f) for f in methods_deleted.items()]:
            loop.append((enabled, start, target, m))
            existing_edges.add((start, target))
        # for enabled, ((start, target), m) in [(True, f) for f in methods.items()] + [(False, f) for f in methods_deleted.items()]:
        for enabled, start, target, m in loop:
            disable_s = "" if enabled else formatting_disabled
            if start.group != target.group and target.group.name != target and target.group is not TypeGroup.general:
                add(start, target.group.name, disable_s)
                start = target.group.name
            if add(start, target, disable_s):
                if m is True:
                    l[-1] += "[style=dashed]"
                if isinstance(m, PickMethod):
                    l[-1] += '[label="choose ' + ",".join([name for name, _ in m.get_options()]) + '" fontsize=10]'
                elif isinstance(m, PickInput):
                    l[-1] += f'[label="{m.parameter_name}" fontsize=10]'
        for tg in TypeGroup:
            if tg is not TypeGroup.general:
                if tg.name in used:
                    l.append(f"{tg.name} [shape=box]")
                else:
                    l.append(f"{tg.name} [shape=box]{formatting_disabled}")
        for f in types:
            disable_s = "" if f in used else formatting_disabled
            label = [f.name]
            s = ""
            if f.description:
                label.append(f.description)
            if Config.is_verbose():
                if f.usual_names:
                    label.append("usual names: " + ", ".join(f.usual_names))
                s = ' [label="' + r"\n".join(label) + '"]'
            l.append(f'{f.name}{s}{disable_s}')
            if f in Types.get_guessable_types():
                l.append(f'{f.name} [style=dashed]')
            # if f.is_private:
            #    l.append(f'{f.name} [shape=box]')

        l.append("}")
        return "\n".join(l)

    @staticmethod
    def _get_methods():
        """  These are known methods to compute a field from another field.
            They should return scalar or list.

            Method ~ lambda: Will be processed when converting one type to another
            Method ~ None: Will be skipped. (TypeGroup.custom fields usually have None.)
            Method ~ True: The user should not be offered to compute from the field to another from a longer distance.
                However if they already got the first type, it is the same as if they had the other.
                Example: (source_ip → ip) hostname from source_ip will be computed as if from an ip,
                Example: (abusemail → email) We do not want to offer the conversion hostname → whois → abusemail → email → hostname,
                    in other words we do not offer to compute a hostname from a hostname, however when selecting
                    an existing abusemail column, we offer conversion abusemail → (invisible email) → hostname
        """

        t = Types
        return {
            (t.source_ip, t.ip): True,
            (t.destination_ip, t.ip): True,
            (t.any_ip, t.ip): any_ip_2_ip,  # "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
            (t.port_ip, t.ip): port_ip_2_ip,  # IP written with a port 91.222.204.175.23 -> 91.222.204.175
            (t.url, t.hostname): Whois.url2hostname,
            (t.hostname, t.ip): Checker.hostname2ips if Config.get("multiple_hostname_ip", "FIELDS") else Checker.hostname2ip,
            # (t.url, t.ip): Whois.url2ip,
            (t.ip, t.whois): Whois,
            (t.cidr, t.ip): Checker.cidr_ips if Config.get("multiple_cidr_ip", "FIELDS") else
            lambda x: str(ipaddress.ip_interface(x).ip),
            (t.whois, t.prefix): lambda x: str(x.get[0]),
            (t.whois, t.asn): lambda x: x.get[3],
            (t.whois, t.abusemail): lambda x: x.get[6],
            (t.whois, t.country): lambda x: x.get[5],
            (t.whois, t.netname): lambda x: x.get[4],
            (t.whois, t.csirt_contact): lambda x: Contacts.csirtmails[x.get[5]] if x.get[5] in Contacts.csirtmails else "-",
            (t.whois, t.incident_contact): lambda x: x.get[2],
            (t.plaintext, t.bytes): lambda x: x.encode("UTF-8"),
            (t.bytes, t.plaintext): Checker.bytes_plaintext,
            (t.bytes, t.base64): lambda x: b64encode(x).decode("UTF-8"),
            (t.base64, t.bytes): b64decode,
            (t.bytes, t.quoted_printable): lambda x: encodestring(x).decode("UTF-8"),
            (t.quoted_printable, t.bytes): decodestring,
            (t.urlencode, t.plaintext): lambda x: unquote(x),
            (t.plaintext, t.urlencode): lambda x: quote(x),
            (t.plaintext, t.external): None,
            (t.plaintext, t.code): None,
            (t.plaintext, t.reg): None,
            (t.bytes, t.charset): Checker.decode,
            (t.reg, t.reg_s): None,
            (t.reg, t.reg_m): None,
            (t.wrong_url, t.url): wrong_url_2_url,
            (t.hostname, t.url): lambda x: "http://" + x,
            (t.ip, t.url): lambda x: "http://" + x,
            (t.url, t.web): Web,
            (t.web, t.http_status): lambda x: x.get[0],
            (t.web, t.text): lambda x: x.get[1],
            (t.web, t.html): lambda x: x.get[2],
            (t.web, t.redirects): lambda x: x.get[3],
            (t.web, t.x_frame_options): lambda x: x.get[4],
            (t.web, t.csp): lambda x: x.get[5],
            (t.hostname, t.ports): nmap,
            (t.ip, t.ports): nmap,
            (t.hostname, t.spf): dig("SPF"),
            (t.hostname, t.txt): dig("TXT"),
            (t.hostname, t.a): dig("A"),
            (t.hostname, t.aaaa): dig("AAAA"),
            (t.hostname, t.ns): dig("NS"),
            (t.hostname, t.mx): dig("MX"),
            (t.hostname, t.dmarc): dig("DMARC"),
            (t.abusemail, t.email): True,
            (t.email, t.hostname): lambda x: x[x.index("@") + 1:],
            # (t.email, check legit mailbox)
            (t.country_name, t.country): address_country,
            (t.country, t.country_name): lambda x: country_codes[x],
            (t.phone, t.country): phone_country,
            (t.hostname, t.tld): Checker.HostnameTld,
            (t.prefix, t.cidr): Checker.prefix_cidr,
            (t.redirects, t.url): True,
            (t.tld, t.country): True,
            (t.timestamp, t.formatted_time): Checker.time_format,
            (t.timestamp, t.isotimestamp): Checker.isotimestamp,
            (t.timestamp, t.date): Checker.date,
            (t.timestamp, t.time): lambda val: Checker.parse_timestamp(val).time(),
        }


class Identifier:

    def __init__(self, parser):
        self.parser = parser
        self.graph = None

    def get_methods_from(self, target, start, custom):
        """
        Returns the nested lambda list that'll receive a value from start field and should produce value in target field.
        :param target: field type name
        :param start: field type name
        :param custom: List of strings that are being used by TypeGroup.custom and PickBase
        :return: lambda[]
        """
        custom = copy(custom)

        def custom_code(e: str):
            def method(x):
                l = locals()
                try:
                    exec(compile(e, '', 'exec'), l)
                except Exception as exception:
                    code = "\n  ".join(e.split("\n"))
                    logger.error(f"Statement failed with {exception}.\n  x = '{x}'; {code}")
                    if not Config.error_caught():  # XX ipdb cant be quit with q here
                        input("We consider 'x' unchanged...")
                    return x
                x = l["x"]
                return x

            return method

        def regex(type_, search, replace=None):
            search = re.compile(search)

            def reg_m_method(s):
                match = search.search(s)
                if not match:
                    return ""
                groups = match.groups()
                if not replace:
                    if not groups:
                        return match.group(0)
                    return match.group(1)
                try:
                    return replace.format(match.group(0), *[g for g in groups])
                except IndexError:
                    logger.error(f"RegExp failed: `{replace}` cannot be used to replace `{s}` with `{search}`")
                    if not Config.error_caught():
                        input("We consider string unmatched...")
                    return ""

            def reg_s_method(s):
                match = search.search(s)
                if not match:
                    return ""
                if not replace:
                    return search.sub("", s)
                try:
                    # we convert "str{0}" → "\g<0>" (works better than conversion to a mere "\0" that may result to ambiguity
                    return search.sub(re.sub("{(\d+)}", r"\\g<\1>", replace), s)
                except re.error:
                    logger.error(f"RegExp failed: `{replace}` cannot be used to substitute `{s}` with `{search}`")
                    if not Config.error_caught():
                        input("We consider string unmatched...")
                    return ""

            return reg_s_method if type_ == Types.reg_s else reg_m_method

        path = graph.dijkstra(target, start=start)  # list of method-names to calculate new fields
        lambdas = []  # list of lambdas to calculate new field
        for i in range(len(path) - 1):
            lambda_ = methods[path[i], path[i + 1]]
            if isinstance(lambda_, PickBase):
                # either the fields was added (has custom:List)
                # or is being computed in run_single_query() through get_computable_fields that makes us sure PickBase has a default
                lambda_ = lambda_.get_lambda(custom.pop(0) if custom is not None else None)
            elif not hasattr(lambda_, "__call__"):  # the field is invisible, see help text for Types; may be False, None or True
                continue
            lambdas.append(lambda_)

        if target.group == TypeGroup.custom:
            if target == Types.external:
                lambdas += [getattr(self.get_module_from_path(custom[0]), custom[1])]  # (module path, method name).
            elif target == Types.code:
                if type(custom) is list and len(custom) == 1:
                    custom = custom[0]  # code accepts a string
                lambdas += [custom_code(custom)]
            elif target in [Types.reg, Types.reg_m, Types.reg_s]:
                lambdas += [regex(target, *custom)]  # custom is in the form (search, replace)
            else:
                raise ValueError(f"Unknown type {target}")

        logger.debug(f"Preparing path from {start} to {target}: " + ", ".join([str(p) for p in path])
                     + " ('" + "', '".join(custom) + "')" if custom else "")
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

            # header detection
            l = [line.strip() for line in sample]
            rows_similarity = mean([SequenceMatcher(None, *comb).ratio() for comb in itertools.combinations(l[1:], 2)])
            header_to_rows_similarity = mean([SequenceMatcher(None, l[0], it).ratio() for it in l[1:]])
            has_header = rows_similarity > header_to_rows_similarity + 0.1  # it seems that first line differs -> header

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

        seems_single = False
        if len(sample) == 1:
            # there is single line in sample = in the input, so this is definitely not a header
            has_header = False
            if dialect.delimiter not in [".", ",", "\t"] and "|" not in sample_text:
                # usecase: short one-line like "convey hello" would produce stupid "l" delimiter
                # XX should be None maybe, let's think a whole row is a single column – but then we could not add columns
                dialect.delimiter = "|"
                seems_single = True
        if dialect.delimiter == "." and "," not in sample_text:
            # let's propose common use case (bare list of IP addresses) over a strange use case with "." delimiting
            dialect.delimiter = ","
        return dialect, has_header, seems_single

    def identify_fields(self, quiet=False):
        """
        Identify self.csv.fields got in __init__
        Sets them possible types (sorted, higher score mean bigger probability that the field is of that type)
        :type quiet: bool If True, we do not raise exception when sample cannot be processed.
                            Ex: We attempt consider user input "1,2,3" as single field which is not, we silently return False
        """
        samples = [[] for _ in self.parser.fields]
        if len(self.parser.sample) == 1:  # we have too few values, we have to use them
            s = self.parser.sample[:1]
        else:  # we have many values and the first one could be header, let's omit it
            s = self.parser.sample[1:]

        for row in reader(s, dialect=self.parser.dialect) if self.parser.dialect else [s]:
            for i, val in enumerate(row):
                try:
                    samples[i].append(val)
                except IndexError:
                    if not quiet:
                        print("It seems rows have different lengths. Cannot help you with column identifying.")
                        print("Fields row: " + str([(i, str(f)) for i, f in enumerate(self.parser.fields)]))
                        print("Current row: " + str(list(enumerate(row))))
                        if not Config.error_caught():
                            input("\n... Press any key to continue.")
                    return False

        for i, field in enumerate(self.parser.fields):
            possible_types = {}
            for type_ in Types.get_guessable_types():
                score = type_.check_conformity(samples[i], self.parser.has_header, field)
                if score:
                    possible_types[type_] = score
                # print("hits", hits)

            if possible_types:  # sort by biggest score - biggest probability the column is of this type
                field.possible_types = {k: v for k, v in sorted(possible_types.items(), key=lambda k: k[1], reverse=True)}
        return True

    def get_fitting_type(self, source_field_i, target_field, try_plaintext=False):
        """ Loops all types the field could be and return the type best suited method for compute new field. """
        _min = 999
        fitting_type = None
        possible_fields = list(self.parser.fields[source_field_i].possible_types)
        dijkstra = graph.dijkstra(target_field)  # get all fields that new_field is computable from
        for _type in possible_fields:
            # loop all the types the field could be, loop from the FieldType we think the source_col correspond the most
            # a column may have multiple types (url, hostname), use the best
            if _type not in dijkstra:
                continue
            i = dijkstra[_type]
            if i < _min:
                _min, fitting_type = i, _type
        if not fitting_type and try_plaintext and Types.plaintext in dijkstra:
            # try plaintext field as the last one. Do not try it earlier, usecase:
            # we want to produce reg_s from base64. If we inserted plaintext earlier,
            #  fitting_type would be plaintext since it is a step nearer - but the field would not be decoded
            return Types.plaintext
        return fitting_type

    def get_fitting_source_i(self, target_type, try_hard=False):
        """ Get list of source_i that may be of such a field type that new_field would be computed effectively.
            Note there is no fitting column for TypeGroup.custom, if you try_hard, you receive first column as a plaintext.
        """
        possible_cols = {}
        if target_type.group != TypeGroup.custom:
            valid_types = graph.dijkstra(target_type)
            for val in valid_types:  # loop from the best suited type
                for i, f in enumerate(self.parser.fields):  # loop from the column we are most sure with its field type
                    if val in f.possible_types:
                        possible_cols[i] = f.possible_types[val]
                        break
        if not possible_cols and try_hard and target_type.is_plaintext_derivable:
            # because any plaintext would do (and no plaintext-only type has been found), take the first column
            possible_cols = [0]
        return list(possible_cols)

    def get_fitting_source(self, target_type: Type, *task):
        """
        For a new field, we need source column and its field type to compute new field from.
        :rtype: source_field: Field, source_type: Type, custom: List[str]
        :param target_type: Type
        :type task: List[str]: [COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM...]
            COLUMN: int|existing name
            SOURCE_TYPE: field type name|field type usual names
            CUSTOM: any parameter
        """
        source_col_i = None
        source_type = None
        task = list(task)

        if Config.is_debug():
            print(f"Getting type {target_type} with args {task}")

        # determining source_col_i from a column candidate
        column_candidate = task.pop(0) if len(task) else None
        if column_candidate:  # determine COLUMN
            source_col_i = self.get_column_i(column_candidate)  # get field by exact column name, ID or type
            if source_col_i is None:
                if len(task) and target_type.group != TypeGroup.custom:
                    print(f"Invalid field type {task[0]}, already having defined by {column_candidate}")
                    quit()
                task.insert(0, column_candidate)  # this was not COLUMN but SOURCE_TYPE or CUSTOM, COLUMN remains empty
        if source_col_i is None:  # get a column whose field could be fitting for that target_tape or any column as a plaintext
            try:
                source_col_i = self.get_fitting_source_i(target_type, True)[0]
            except IndexError:
                pass

        # determining source_type
        source_type_candidate = task.pop(0) if len(task) else None
        if source_type_candidate:  # determine SOURCE_TYPE
            source_type = Types.find_type(source_type_candidate)
            if not source_type:
                if target_type.group == TypeGroup.custom:
                    # this was not SOURCE_TYPE but CUSTOM, for custom fields, SOURCE_TYPE may be implicitly plaintext
                    #   (if preprocessing ex: from base64 to plaintext is not needed)
                    task.insert(0, source_type_candidate)
                    # source_type = Types.plaintext
                else:
                    print(f"Cannot determine new field from {source_type_candidate}")
                    quit()

        # determining missing info
        if source_col_i is not None and not source_type:
            try:
                source_type = self.get_fitting_type(source_col_i, target_type, try_plaintext=True)
            except IndexError:
                print(f"Column ID {source_col_i + 1} does not exist. We have these so far: " +
                      ", ".join([f.name for f in self.parser.fields]))
                quit()
            if not source_type:
                print(f"We could not identify a method how to make '{target_type}' from '{self.parser.fields[source_col_i]}'")
                quit()
        if source_type and source_col_i is None:
            # searching for a fitting type amongst existing columns
            # for col in self.
            possibles = {}  # [source col i] = score (bigger is better)
            for i, t in enumerate(self.parser.fields):
                if source_type in t.possible_types:
                    possibles[i] = t.possible_types[source_type]

            try:
                source_col_i = sorted(possibles, key=possibles.get, reverse=True)[0]
            except IndexError:
                print(f"No suitable column of type '{source_type}' found to make field '{target_type}'")
                quit()

        if not source_type or source_col_i is None:
            print(f"No suitable column found for field '{target_type}'")
            quit()

        try:
            f = self.parser.fields[source_col_i]
        except IndexError:
            print(f"Column ID {source_col_i + 1} does not exist, only these: " + ", ".join(f.name for f in self.parser.fields))
            quit()

        # Check there is a path between nodes and that path is resolvable
        path = graph.dijkstra(target_type, start=source_type)
        if path is False:
            print(f"No suitable path from '{f.name}' treated as '{source_type}' to '{target_type}'")
            quit()
        for i in range(len(path) - 1):
            t = (path[i], path[i + 1])
            if t not in methods:
                if t in methods_deleted:
                    print(f"Disabled path at " + ", ".join([str(t_) for t_ in t]) + ". Launch --config to enable it.")
                else:
                    print(f"Path from '{f.name}' treated as '{source_type}' to '{target_type}' blocked at " +
                          ", ".join([str(t_) for t_ in t]))
                quit()

        if Config.is_debug():
            print(f"Preparing type {target_type} of field={f}, source_type={source_type}, custom={task}, path={path}")
        return f, source_type, task

    def get_column_i(self, column):
        """
        Useful for parsing user input COLUMN from the CLI args.
        :type column: object Either column ID (ex "1" points to column index 0) or an exact column name or the field
        :rtype: int Either column_i or None if not found.
        """
        source_col_i = None
        if hasattr(column, "col_i"):
            return column.col_i
        if column.isdigit():  # number of column
            source_col_i = int(column) - 1
        elif column in self.parser.first_line_fields:  # exact column name
            source_col_i = self.parser.first_line_fields.index(column)
        else:
            searched_type = Types.find_type(column)  # get field by its type
            if searched_type:
                reserve = None
                for f in self.parser.fields:
                    if f.type == searched_type:
                        source_col_i = f.col_i
                    elif searched_type in f.possible_types and not reserve:
                        reserve = f.col_i
                if not source_col_i:
                    source_col_i = reserve
        return source_col_i
