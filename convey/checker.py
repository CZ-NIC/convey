import ipaddress
import logging
import re
import socket
from base64 import b64decode
from datetime import datetime
from quopri import decodestring
from urllib.parse import unquote, urlparse

import dateutil.parser
from chardet import detect
from netaddr import IPNetwork, IPRange
from pint import UnitRegistry

from .convert import reFqdn, reUrl, wrong_url_2_url
from .decorators import PickInput, PickMethod
from .infodicts import phone_regex_match
from .utils import timeout

logger = logging.getLogger(__name__)
pint = UnitRegistry()


class Checker:
    """ To not pollute the namespace, we put the methods here """

    hostname_ips_cache = {}
    hostname_cache = {}

    @staticmethod
    def hostname_ips(val):
        if val not in Checker.hostname_ips_cache:
            try:
                Checker.hostname_ips_cache[val] = list(
                    {addr[4][0] for addr in timeout(15, socket.getaddrinfo, val, None)})
            except (TimeoutError, OSError, ValueError) as e:
                Checker.hostname_ips_cache[val] = []
        return Checker.hostname_ips_cache[val]

    @classmethod
    def hostname_ip(cls, val):
        if val not in cls.hostname_cache:
            try:
                cls.hostname_cache[val] = timeout(3, socket.gethostbyname, val)
            except (TimeoutError, OSError, ValueError) as e:
                logger.warning(f"Hostname {val}: {e}")
                cls.hostname_cache[val] = []
        return cls.hostname_cache[val]

    @staticmethod
    def check_cidr(cidr):
        try:
            ipaddress.ip_interface(cidr)
            try:
                ipaddress.ip_address(cidr)
            except ValueError:  # "1.2.3.4" fail, "1.2.3.4/24" pass
                return True
        except ValueError:
            return False

    @staticmethod
    def is_base64(x):
        """ We prefer as base64-encoded only such strings that could be decoded to UTF-8.
            Because otherwise nearly any ASCII input with the correct padding
            would be considered as base64 (ex: port number), even when well readable at first sight.
            If not UTF-8 decodable, we check the minimal length and penalize.
        """
        if not re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", x):
            return False

        try:
            s = b64decode(x).decode("UTF-8")
            if s:
                if len(re.sub(r"[^a-zA-Z0-9 ]", "", s)) / len(s) > 0.9:
                    # Majority of characters in the decoded string must be alphanumerical
                    # in order we think this might be a base64-encoded string.
                    # Imagine string 'ahojahoj' which is base64-decodable but gibberish.
                    return True
        except (UnicodeDecodeError, ValueError):
            try:
                if len(x) > 10 and b64decode(x):
                    # if the string is long enough, we admit it can be encoded in another charset
                    return -0.5
            except (UnicodeDecodeError, ValueError):
                pass

    @staticmethod
    def is_ip(ip):
        """ True, if IP is well formatted IPv4 or IPv6 """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_quopri(x):
        try:
            # When 'rmx1u2916Gv9IGv58iBw7Gwg7+FiZWxza+kg82R5Lg==' is decoded, only last '=' is stripped out.
            decoded = decodestring(x).decode("UTF-8").rstrip("=")
            return decoded and decoded != x.rstrip("=")
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
        if (reUrl.match(wrong) and "[.]" not in wrong) or reFqdn.match(wrong) or Checker.is_ip(wrong):
            # input "example[.]com" would be admitted as a valid URL)
            return False
        s = wrong_url_2_url(wrong, make=False)
        s2 = wrong_url_2_url(wrong, make=True)
        try:
            netloc = urlparse(s2).netloc
        except ValueError:
            # ex: s2='http://[07/Feb/2021:00:32:43 -0500] "GET /wp-json/wp/v2/posts HTTP/1.1" 200 1912'
            return False
        # Xm = reUrl.match(s2)
        # X(m and m.span(0)[1] == len(s2) and "." in s2):
        if reFqdn.match(s) or reFqdn.match(netloc) or Checker.is_ip(netloc):
            # Xwe impose full match
            # Xstring created from "x"*100 would be submitted for a valid URL
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

    # noinspection PyBroadException
    @staticmethod
    def is_unit(val):
        if len(val) == 1:
            # we want prevent "a" being considered a time unit ("a" == "1 year" according to pint 0.16.1)
            return False
        try:
            e = pint.parse_expression(val)
            return e and pint.get_compatible_units(e)
        except Exception:
            return False

    @staticmethod
    @PickInput
    def unit_expand(val, unit=None):
        try:
            e = pint.parse_expression(val)
            if unit:
                return str(e.to(unit))
            else:
                l = []
                for unit in pint.get_compatible_units(e):
                    l.append(str(e.to(unit)))
                return l
        except (ValueError, AttributeError):
            return ""

    @classmethod
    def is_phone(cls, val):
        return phone_regex_match(val) and not cls.is_timestamp(val)

    @staticmethod
    def is_timestamp(val):
        reference = datetime.now()

        # identify UNIX time
        try:
            o = datetime.fromtimestamp(float(val))
        except ValueError:
            pass  # val is not a number, try different methods
        else:
            # consider only nowadays timestamp a timestamp
            # prevent "12345" to be considered as a timestamp from the beginning of the Unix epoch (1970)
            return reference.year - 5 < o.year < reference.year + 1

        # identify straight textual representation (ex: 2021-02-12), easily parsable by not-fuzzy `dateutil`
        try:
            o = dateutil.parser.parse(val)
            if not (o.second == o.minute == o.hour == 0 and o.day == reference.day and o.month == reference.month):
                # if parser accepts a plain number, ex: 1920,
                # it thinks this is a year without time (assigns midnight) and without date (assigns current date)
                # -> 1920-05-05 00:00 (on 5th May) – we try to skip such result.
                # If does not match, it seems this is a valid timestamp and we hereby return True.
                return True
        except ValueError:
            pass  # val is a random textual representation or a UNIX time
        except OverflowError:
            return False

        # identify random textual representation of a timestamp
        try:
            o = Checker.parse_timestamp(val)
            if 2100 > o.year > 1900 and not (o.second == o.minute == o.hour == 0 and o.day == o.month == 1):
                # this year seems reasonable and it is not suspicious
                # fuzzy search often return crazy things like year from port number - these records have 1 Jan midnight
                return True
        except (ValueError, TypeError):
            pass
        return False

    default_datetime = datetime(1, 1, 1)

    @staticmethod
    def parse_timestamp(val):
        # UNIX time
        try:
            return datetime.fromtimestamp(float(val))
        except ValueError:
            pass  # val is not a number

        # random textual representation of a timestamp
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
        if "/" in val:
            # currently, we do not guarantee prefix will be in the form "... - ...",
            # it may has directly CIDR form if WHOIS tells us so
            return val
        return IPRange(*val.split("-")).cidrs()

    @staticmethod
    def cidr_ips(val):
        return [ip for ip in IPNetwork(val)]
