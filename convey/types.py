import bdb
import importlib.util
import ipaddress
import logging
import re
import socket
from abc import ABCMeta
from base64 import b64decode, b64encode
from builtins import ZeroDivisionError
from copy import copy
from enum import IntEnum
from pathlib import Path
from quopri import decodestring, encodestring
from sys import exit
from typing import TYPE_CHECKING, Callable, List, Union
from urllib.parse import unquote, quote

from validate_email import validate_email


from .config import Config
from .convert import any_ip_ip, port_ip_ip, port_ip_port, reAnyIp, reFqdn, reIpWithPort, reUrl, url_hostname, url_port, wrong_url_2_url, dig, nmap
from .contacts import Contacts
from .checker import Checker
from .decorators import PickBase, PickMethod, PickInput
from .graph import Graph
from .infodicts import phone_country, address_country, country_codes
from .web import Web
from .whois import Whois

if TYPE_CHECKING:
    from .args_controller import Env
logger = logging.getLogger(__name__)

types: List["Type"] = []  # all field types
methods: dict[tuple["Type", "Type"], Callable] = {}
graph: Graph["Type"] = Graph()
methods_deleted = {}


class TypeGroup(IntEnum):
    general = 1
    custom = 2
    whois = 3
    dns = 4
    nmap = 5
    web = 6

    @staticmethod
    def init():
        for module in ["whois", "web", "nmap", "dig"]:
            if getattr(Config.get_env().mod, module) is False:
                if module == "dig":
                    module = "dns"
                getattr(TypeGroup, module).disable()

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

    def __init__(self, name, group=TypeGroup.general, description="", usual_names=[], identify_method=None,
                 is_private=False,
                 from_message=None, usual_must_match=False):
        """
        :param name: Key name
        :param description: Help text
        :param usual_names: Names this column usually has (ex: source_ip for an IP column). List of str, lowercase, no spaces.
        :param identify_method: Lambda used to identify a value conforms this field type (return true).
            If float is returned, this should be added to the score (ex: malus when we are not sure this is a base64 string).
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
            raise ConnectionAbortedError(f"Multiple 'computing_start' types defined for {self}: {computing_start}")
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
            sc = self.identify_method(val)
            if sc:
                hits += 1
                if isinstance(sc, float):
                    score += sc

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


class _AlwaysFalse:
    def __getattr__(self, name):
        return self

    def __getitem__(self, key):
        return self

    def __call__(self, *args, **kwargs):
        return self

    def __bool__(self):
        return False

    def __repr__(self):
        return "False"

    def __str__(self):
        return "False"


class Types:
    """
    Methods sourcing from private type should return a tuple, with the private type as the first
    Ex: (whois, asn): lambda x: (x, x.get[3])

    """

    @staticmethod
    def refresh(init=False):
        """ refreshes methods and import custom methods from files """
        # we cannot use Config.get_env() in the init phase
        config = _AlwaysFalse() if init else Config.get_env()

        methods.clear()
        methods.update(Types._get_methods(config))
        graph.clear()
        [graph.add_edge(to, from_) for to, from_ in methods if methods[to, from_] is not True]
        [t.init() for t in types]

        for field_name in config.comp.external_fields or []:
            if ":" in field_name:
                path, method_name = field_name.rsplit(":")
                module = get_module_from_path(path)
                Types.import_method(module, method_name, path)
            else:
                try:
                    path = field_name
                    module = get_module_from_path(path)
                    if module:
                        for method_name in (x for x in dir(module) if not x.startswith("_")):
                            Types.import_method(module, method_name, path)
                except bdb.BdbQuit:
                    raise
                except Exception as e:
                    s = f"Cannot import custom file from path: {path}"
                    input(s + ". Press any key...")
                    logger.warning(s)

    @staticmethod
    def import_method(module, method_name, path, name=None):
        if not name:
            name = method_name
        lambda_ = getattr(module, method_name)
        if isinstance(lambda_, ABCMeta):  # this is just an import statement of ex: PickBase
            return
        doc = lambda_.__doc__ if not isinstance(lambda_, PickBase) else lambda_.get_type_description()
        # if disable_external is True:
        #     # user do not want to allow externals to be added but we have added them before argparse was parsed
        #     # so that we could inform the user in the help text of the computable fields
        #     types.pop(types.index(getattr(Types, name)))
        #     delattr(Types, name)
        # else:
        setattr(Types, name, Type(name, TypeGroup.general, doc))
        type_ = getattr(Types, name)
        methods[(Types.plaintext, type_)] = lambda_
        if lambda_ is not True:
            graph.add_edge(Types.plaintext, type_)
        type_.init()
        # Xif disable_external is False:
        # Xwhen "disable_external" is None it means this method is called before argparse flags are parsed,
        # Xwe do not know yet if "disable_external" will be set to True or False
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

    @staticmethod
    def get_method(start: Type, target: Type):
        try:
            return methods[start, target]
        except KeyError:
            if (start, target) in methods_deleted:
                print(f"Disabled path at {start} – {target}. Launch --config to enable it.")
                exit()
            else:
                raise LookupError

    whois = Type("whois", TypeGroup.whois, "ask whois servers", is_private=True)
    whoisdomain = Type("whoisdomain", TypeGroup.whois, "ask whois servers for domain", is_private=True)
    web = Type("web", TypeGroup.web, "scrape web contents", is_private=True)

    external = Type("external", TypeGroup.custom, from_message="from a method in your .py file")
    code = Type("code", TypeGroup.custom, from_message="from a code you write")
    reg = Type("reg", TypeGroup.custom, from_message="from a regular expression")
    reg_s = Type("reg_s", TypeGroup.custom, from_message="substitution from a regular expression")
    reg_m = Type("reg_m", TypeGroup.custom, from_message="match from a regular expression")
    netname = Type("netname", TypeGroup.whois)
    country = Type("country", TypeGroup.whois)
    registrar_abusemail = Type("registrar_abusemail", TypeGroup.whois, "Abuse e-mail contact from whois")
    abusemail = Type("abusemail", TypeGroup.whois, "Abuse e-mail contact from whois")
    prefix = Type("prefix", TypeGroup.whois)  # XX rename to 'inetnum'? to 'range'?
    csirt_contact = Type("csirt_contact", TypeGroup.whois,
                         "E-mail address corresponding with country code, taken from your personal contacts_abroad CSV"
                         " in the format `country,abusemail`. See config.ini/contacts_abroad")
    incident_contact = Type("incident_contact", TypeGroup.whois)
    cc_contact = Type("cc_contact", TypeGroup.whois,
                      "E-mail address corresponding with the abusemail, taken from your personal contacts_cc CSV"
                      " in the format `domain,cc;cc` (mails delimited by a semicolon). See config.ini/contacts_cc."
                      " Note:  when sending an e-mail to a csirt_contact, the e-mail template fills Cc header"
                      " from the csirt_contact through contacts_cc.csv too. So you may end up with another Cc field"
                      " than in cc_contact.")
    text = Type("text", TypeGroup.web)
    http_status = Type("http_status", TypeGroup.web, "HTTP response status. If 0 or negative, request failed.")
    html = Type("html", TypeGroup.web)
    redirects = Type("redirects", TypeGroup.web)
    x_frame_options = Type("x_frame_options", TypeGroup.web)
    csp = Type("csp", TypeGroup.web)
    form_names = Type("form_names", TypeGroup.web)
    ports = Type("ports", TypeGroup.nmap, "Open ports given by nmap")
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
    country_name = Type("country_name",
                        TypeGroup.general)  # XX not identifiable, user has to be told somehow there is such method
    phone = Type("phone", TypeGroup.general, "telephone number", ["telephone", "tel"], Checker.is_phone)

    unit = Type("unit", TypeGroup.general, "any physical quantity", [], Checker.is_unit)
    timestamp = Type("timestamp", TypeGroup.general, "time or date", ["time"], Checker.is_timestamp)
    ip = Type("ip", TypeGroup.general, "valid IP address", ["ip", "ipaddress"], Checker.is_ip)
    source_ip = Type("source_ip", TypeGroup.general, "valid source IP address",
                     ["sourceipaddress", "source", "src"], Checker.is_ip, usual_must_match=True)
    destination_ip = Type("destination_ip", TypeGroup.general, "valid destination IP address",
                          ["destinationipaddress", "destination", "dest", "dst"], Checker.is_ip, usual_must_match=True)
    port = Type("port", TypeGroup.general, "port", ["port", "prt"], lambda x: re.match(r"\d{1,5}", x),
                usual_must_match=True)
    cidr = Type("cidr", TypeGroup.general, "CIDR 127.0.0.1/32", ["cidr"], Checker.check_cidr)
    port_ip = Type("port_ip", TypeGroup.general, "IP in the form 1.2.3.4.port", [], reIpWithPort.match)
    any_ip = Type("any_ip", TypeGroup.general, "IP in the form 'any text 1.2.3.4 any text'", [],
                  lambda x: reAnyIp.search(x) and not Checker.is_ip(x))
    hostname = Type("hostname", TypeGroup.general, "2nd or 3rd domain name", ["fqdn", "hostname", "domain"],
                    reFqdn.match)
    email = Type("email", TypeGroup.general, "E-mail address", ["mail"],
                 lambda e: validate_email(e, check_dns=False, check_smtp=False))
    url = Type("url", TypeGroup.general, "URL starting with http/https", ["url", "uri", "location"],
               lambda s: reUrl.match(s) and "[.]" not in s)  # input "example[.]com" would be admitted as a valid URL)
    asn = Type("asn", TypeGroup.whois, "Autonomous system number", ["as", "asn", "asnumber"],
               lambda x: re.search(r'AS\d+', x) is not None)
    base64 = Type("base64", TypeGroup.general, "Text encoded with Base64", ["base64"], Checker.is_base64)
    quoted_printable = Type("quoted_printable", TypeGroup.general, "Text encoded as quotedprintable", [],
                            Checker.is_quopri)
    urlencode = Type("urlencode", TypeGroup.general, "Text encoded with urlencode", ["urlencode"], Checker.is_urlencode)
    wrong_url = Type("wrong_url", TypeGroup.general, "Deactivated URL", [], Checker.check_wrong_url)
    plaintext = Type("plaintext", TypeGroup.general, "Plain text", ["plaintext", "text"], lambda x: False)
    path = Type("path", usual_names=["path"], identify_method=lambda x: False)

    @staticmethod
    def get_computable_types(ignore_custom=False) -> list[Type]:
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
    def get_guessable_types() -> list[Type]:
        """ these field types can be guessed from a string """
        return sorted([t for t in types if not t.is_disabled and (t.identify_method or t.usual_names)])

    @staticmethod
    def get_uml(flags):
        """ Return DOT UML source code of types and methods
            dashed nodes = identifiable automatically
            dashed edges = lambda-True relation (see _get_methods() help)
            squares = category border
            edge label = possible ways of processing (@PickBase decorated methods)

          FLAGS:
             * +1 to gray out disabled fields/methods
             * +2 to include usual field names
             * +16 wide-screen suitable (presenting) else tall graph
        """
        l = ['digraph { ',
             # 'rankdir=LR',  # XX I really wish to have TB, with rows: IP, plaintext, timestamp
             'label="Convey field types (dashed nodes = identifiable automatically, dashed edges = field identity)"']
        used = set()
        formatting_disabled = "[color=lightgray fontcolor=lightgray]" if flags & 1 else ""
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

        for enabled, ((start, target), m) in [(True, f) for f in methods.items()] + [(False, f) for f in
                                                                                     methods_deleted.items()]:
            loop.append((enabled, start, target, m))
            existing_edges.add((start, target))
        # for enabled, ((start, target), m) in [(True, f) for f in methods.items()] + [(False, f) for f in methods_deleted.items()]:
        for enabled, start, target, m in loop:
            disable_s = "" if enabled else formatting_disabled
            if start.group != target.group and target.group.name != target and target.group in [TypeGroup.dns,
                                                                                                TypeGroup.nmap,
                                                                                                TypeGroup.custom]:
                # Every type that goes to ex: `dns`, continues to all `dns` subtypes. We want `hostname -> spf` to go through `dns`.
                # This is not the case of the group `whois` - this group has explicitly stated the path in methods,
                #   ex: `ip → whois → country` but also `phone → country`.
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
            if flags & 2:
                if f.usual_names:
                    label.append("usual names: " + ", ".join(f.usual_names))
                s = ' [label="' + r"\n".join(label) + '"]'
            l.append(f'{f.name}{s}{disable_s}')
            if f in Types.get_guessable_types():
                l.append(f'{f.name} [style=dashed]')
            # if f.is_private:
            #    l.append(f'{f.name} [shape=box]')

        # formatting mark to put one cluster below another, not aside
        if flags & 16:  # looks nicer in a presentation
            l.extend([
                # "spf -> timestamp[style=invis]",
                # "formatted_time -> plaintext[style=invis]",
            ])
        else:  # looks nicer in README.md
            l.extend([
                "port -> urlencode[style=invis]",
                "charset -> timestamp[style=invis]"
            ])
        l.append("}")
        return "\n".join(l)

    @staticmethod
    def _get_methods(config: Union["Env", _AlwaysFalse]):
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
            (t.any_ip, t.ip): any_ip_ip,  # "91.222.204.175 93.171.205.34" -> "91.222.204.175" OR '"1.2.3.4"' -> 1.2.3.4
            (t.port_ip, t.ip): port_ip_ip,  # IP written with a port 91.222.204.175.23 -> 91.222.204.175
            (t.port_ip, t.port): port_ip_port,
            (t.url, t.hostname): url_hostname,
            (t.url, t.port): url_port,
            (t.hostname, t.ip): Checker.hostname_ips if config.comp.multiple_hostname_ip else Checker.hostname_ip,
            # (t.url, t.ip): Whois.url2ip,
            (t.ip, t.whois): Whois,
            (t.hostname, t.whoisdomain): lambda x: Whois(ip=None, hostname=x),
            # (t.asn, t.whois): Whois, # XX can be easily allowed, however Whois object will huff there is no IP prefix range
            (t.cidr, t.ip): Checker.cidr_ips if config.comp.multiple_cidr_ip else
            lambda x: str(ipaddress.ip_interface(x).ip),
            (t.whois, t.prefix): lambda x: str(x.get[0]),
            (t.whois, t.asn): lambda x: x.get[3],
            (t.whois, t.abusemail): lambda x: x.get[6],
            (t.whoisdomain, t.registrar_abusemail): lambda x: x.get[6],
            (t.whois, t.country): lambda x: x.get[5],
            (t.whois, t.netname): lambda x: x.get[4],
            (t.whois, t.csirt_contact):
                lambda x: Contacts.country2mail[x.get[5]] if x.get[5] in Contacts.country2mail else "",
            (t.whois, t.incident_contact): lambda x: x.get[2],
            (t.abusemail, t.cc_contact): lambda x: "; ".join(
                Contacts.mail2cc[domain] for domain in Contacts.get_domains(x) if domain in Contacts.mail2cc
            ),
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
            # X (t.ip, t.url): lambda x: "http://" + x,
            (t.ip, t.hostname): lambda x: socket.gethostbyaddr(x)[0],
            (t.url, t.web): Web,
            (t.web, t.http_status): lambda x: x.get[0],
            (t.web, t.text): lambda x: x.get[1],
            (t.web, t.html): lambda x: x.get[2],
            (t.web, t.redirects): lambda x: x.get[3],
            (t.web, t.x_frame_options): lambda x: x.get[4],
            (t.web, t.csp): lambda x: x.get[5],
            (t.web, t.form_names): lambda x: x.get[6],
            (t.hostname, t.ports): nmap,
            (t.ip, t.ports): nmap,
            (t.ports, t.port): True,
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
            (t.country, t.csirt_contact): lambda x: Contacts.country2mail[x] if x in Contacts.country2mail else "",
            (t.phone, t.country): phone_country,
            (t.hostname, t.tld): Checker.HostnameTld,
            (t.prefix, t.cidr): Checker.prefix_cidr,
            (t.redirects, t.url): True,
            (t.tld, t.country): True,
            (t.timestamp, t.formatted_time): Checker.time_format,
            (t.timestamp, t.isotimestamp): Checker.isotimestamp,
            (t.timestamp, t.date): Checker.date,
            (t.timestamp, t.time): lambda val: Checker.parse_timestamp(val).time(),
            (t.unit, t.plaintext): Checker.unit_expand,
            (t.plaintext, t.unit): Checker.unit_expand
        }


def get_module_from_path(path):
    if not Path(path).is_file():
        return False
    spec = importlib.util.spec_from_file_location("", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
