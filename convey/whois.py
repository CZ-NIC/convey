import logging
import re
import socket
import time
from collections import OrderedDict
from subprocess import PIPE, Popen
from urllib.parse import urlparse, urlsplit

from netaddr import IPRange, IPNetwork

from .config import Config

logger = logging.getLogger(__name__)

countries = {"andorra": "ad",
             "united arab emirates": "ae",
             "afghanistan": "af",
             "barbuda": "ag",
             "antigua": "ag",
             "anguilla": "ai",
             "albania": "al",
             "armenia": "am",
             "angola": "ao",
             "antarctica ": "aq",
             "argentine": "ar",
             "argentina": "ar",
             "american samoa": "as",
             "austria": "at",
             "australia": "au",
             "australia ": "au",
             "aruba": "aw",
             "aland": "ax",
             "azerbaijan": "az",
             "herzegovina": "ba",
             "bosnia": "ba",
             "barbados": "bb",
             "bangladesh": "bd",
             "belgium": "be",
             "burkina faso": "bf",
             "bulgaria": "bg",
             "bahrain": "bh",
             "burundi": "bi",
             "benin": "bj",
             "barthelemy": "bl",
             "bermuda": "bm",
             "brunei": "bn",
             "bolivia": "bo",
             "bonaire": "bq",
             "eustatius": "bq",
             "saba": "bq",
             "brazil": "br",
             "bahamas": "bs",
             "bahamas": "bs",
             "bhutan": "bt",
             "bouvet": "bv",
             "botswana": "bw",
             "belarus": "by",
             "belize": "bz",
             "canada": "ca",
             "keeling": "cc",
             "cocos": "cc",
             "democratic republic of the congo": "cd",
             "central african": "cf",
             "central african": "cf",
             "congo": "cg",
             "swiss": "ch",
             "switzerland": "ch",
             "côte d'ivoire": "ci",
             "ivory coast": "ci",
             "cook": "ck",
             "chile": "cl",
             "cameroon": "cm",
             "china": "cn",
             "colombia": "co",
             "costa rica": "cr",
             "cuba": "cu",
             "cabo verde": "cv",
             "cabo verde ": "cv",
             "cape verde": "cv",
             "curacao": "cw",
             "curaçao": "cw",
             "christmas island": "cx",
             "cyprus": "cy",
             "czech": "cz",
             "czech": "cz",
             "germany": "de",
             "djibouti": "dj",
             "denmark": "dk",
             "dominica": "dm",
             "dominican": "do",
             "dominican": "do",
             "algeria": "dz",
             "ecuador": "ec",
             "estonia": "ee",
             "egypt": "eg",
             "sahrawi": "eh",
             "western sahara": "eh",
             "eritrea": "er",
             "spain": "es",
             "ethiopia": "et",
             "finland": "fi",
             "fiji": "fj",
             "falkland": "fk",
             "falkland islands": "fk",
             "micronesia": "fm",
             "faroe": "fo",
             "french": "fr",
             "france ": "fr",
             "gabonese": "ga",
             "gabon": "ga",
             "northern ireland": "gb",
             "great britain": "gb",
             "united kingdom": "gb",
             "england": "gb",
             "grenada": "gd",
             "georgia": "ge",
             "guyane": "gf",
             "french guiana": "gf",
             "bailiwick of guernsey": "gg",
             "guernsey": "gg",
             "ghana": "gh",
             "gibraltar": "gi",
             "kalaallit nunaat": "gl",
             "greenland": "gl",
             "gambia": "gm",
             "gambia": "gm",
             "guinea": "gn",
             "guadeloupe": "gp",
             "equatorial guinea": "gq",
             "hellenic": "gr",
             "greece": "gr",
             "south sandwich": "gs",
             "south georgia": "gs",
             "guatemala": "gt",
             "guam": "gu",
             "guinea-bissau": "gw",
             "guyana": "gy",
             "hong kong": "hk",
             "mcdonald": "hm",
             "heard": "hm",
             "honduras": "hn",
             "croatia": "hr",
             "haiti": "ht",
             "hungary": "hu",
             "indonesia": "id",
             "ireland": "ie",
             "israel": "il",
             "isle of man": "im",
             "india": "in",
             "british indian ocean": "io",
             "iraq": "iq",
             "iran": "ir",
             "iceland": "is",
             "italian": "it",
             "italy": "it",
             "jersey": "je",
             "jamaica": "jm",
             "hashemite": "jo",
             "jordan": "jo",
             "japan": "jp",
             "kenya": "ke",
             "kyrgyz": "kg",
             "cambodia": "kh",
             "kiribati": "ki",
             "comoros": "km",
             "comoros": "km",
             "nevis": "kn",
             "saint kitts": "kn",
             "democratic people": "kp",
             "north korea": "kp",
             "korea": "kr",
             "kuwait": "kw",
             "cayman": "ky",
             "kazakhstan": "kz",
             "lao": "la",
             "lebanese": "lb",
             "lebanon": "lb",
             "lucia": "lc",
             "saint lucia": "lc",
             "liechtenstein": "li",
             "sri lanka": "lk",
             "liberia": "lr",
             "lesotho": "ls",
             "lithuania": "lt",
             "luxembourg": "lu",
             "latvia": "lv",
             "libya": "ly",
             "morocco": "ma",
             "monaco": "mc",
             "moldova": "md",
             "montenegro": "me",
             "saint-martin": "mf",
             "saint martin": "mf",
             "madagascar": "mg",
             "marshall islands": "mh",
             "north macedonia": "mk",
             "mali": "ml",
             "myanmar ": "mm",
             "mongolia": "mn",
             "macao": "mo",
             "macau": "mo",
             "norrn mariana islands": "mp",
             "martinique": "mq",
             "mauritania": "mr",
             "montserrat": "ms",
             "malta": "mt",
             "mauritius": "mu",
             "maldives": "mv",
             "malawi": "mw",
             "mexican": "mx",
             "mexico": "mx",
             "malaysia": "my",
             "mozambique": "mz",
             "namibia": "na",
             "new caledonia": "nc",
             "niger": "ne",
             "norfolk island": "nf",
             "federal nigeria": "ng",
             "nigeria": "ng",
             "nicaragua": "ni",
             "netherlands": "nl",
             "norway": "no",
             "nepal": "np",
             "nauru": "nr",
             "niue": "nu",
             "new zealand": "nz",
             "oman": "om",
             "panama": "pa",
             "peru": "pe",
             "french polynesia": "pf",
             "new guinea": "pg",
             "papua": "pg",
             "philippines": "ph",
             "philippines": "ph",
             "pakistan": "pk",
             "poland": "pl",
             "miquelon": "pm",
             "saint-pierre": "pm",
             "pitcairn": "pn",
             "henderson": "pn",
             "ducie": "pn",
             "oeno": "pn",
             "puerto rico": "pr",
             "palestine": "ps",
             "portuguese": "pt",
             "portugal": "pt",
             "palau": "pw",
             "paraguay": "py",
             "qatar": "qa",
             "reunion": "re",
             "réunion": "re",
             "romania": "ro",
             "serbia": "rs",
             "russia": "ru",
             "rwanda": "rw",
             "saudi arabia": "sa",
             "solomon islands": "sb",
             "seychelles": "sc",
             "sudan": "sd",
             "sweden": "se",
             "singapore": "sg",
             "helena": "sh",
             "ascension": "sh",
             "tristan": "sh",
             "cunha": "sh",
             "slovenia": "si",
             "jan mayen": "sj",
             "svalbard": "sj",
             "slovak": "sk",
             "slovakia": "sk",
             "sierra leone": "sl",
             "san marino": "sm",
             "senegal": "sn",
             "federal somalia": "so",
             "somalia": "so",
             "suriname": "sr",
             "south sudan": "ss",
             "príncipe": "st",
             "sao tome": "st",
             "principe": "st",
             "el salvador": "sv",
             "sint maarten": "sx",
             "syria": "sy",
             "eswatini": "sz",
             "eswatini ": "sz",
             "caicos islands": "tc",
             "turks": "tc",
             "chad": "td",
             "antarctic lands": "tf",
             "french southern": "tf",
             "togolese": "tg",
             "togo": "tg",
             "thailand": "th",
             "tajikistan": "tj",
             "tokelau": "tk",
             "timor-leste": "tl",
             "turkmenistan": "tm",
             "tunisia": "tn",
             "tonga": "to",
             "turkey": "tr",
             "tobago": "tt",
             "trinidad": "tt",
             "tuvalu": "tv",
             "taiwan": "tw",
             "tanzania": "tz",
             "ukraine": "ua",
             "uganda": "ug",
             "baker": "um",
             "howland": "um",
             "jarvis": "um",
             "johnston": "um",
             "kingman": "um",
             "midway": "um",
             "navassa": "um",
             "palmyra": "um",
             "wake": "um",
             "minor outlying islands  ": "um",
             "united states": "us",
             "uruguay": "uy",
             "uzbekistan": "uz",
             "holy see": "va",
             "grenadines": "vc",
             "saint vincent": "vc",
             "venezuela": "ve",
             "british virgin islands": "vg",
             "virgin islands of united states": "vi",
             "viet nam ": "vn",
             "vietnam": "vn",
             "vanuatu": "vu",
             "futuna": "wf",
             "wallis": "wf",
             "samoa": "ws",
             "yemen": "ye",
             "mayotte": "yt",
             "south africa": "za",
             "zambia": "zm",
             "zimbabwe": "zw"}
rirs = ["whois.ripe.netf", "whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.afrinic.net"]

class Whois:
    unknown_mode = False
    see = Config.verbosity <= logging.INFO

    @staticmethod
    def init(stats, ranges, ip_seen):
        Whois.stats = stats
        Whois.ranges = ranges
        Whois.ip_seen = ip_seen  # ip_seen[ip] = prefix
        Whois.servers = OrderedDict()
        Whois.unknown_mode = False  # if True, we use b flag in abusemails
        if Config.get("whois_mirror", "FIELDS"):  # try a fast local whois-mirror first
            Whois.servers["mirror"] = Config.get("whois_mirror", "FIELDS")
        Whois.servers["general"] = None
        # Algorithm for querying custom servers:
        # for name, val in zip(["ripe", "arin", "lacnic", "apnic", "afrinic"],
        #                      ["whois.ripe.net -r", "whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.afrinic.net"]):
        #     Whois.servers[name] = val

    def __init__(self, ip):
        """
         self.get stores tuple: prefix, location, mail, asn, netname, country
        """
        self.ip = ip
        self.whoisResponse = []
        if not Whois.unknown_mode:
            if self.ip in self.ip_seen:  # ip has been seen in the past
                prefix = self.ip_seen[self.ip]
                self.get = self.ranges[prefix]
                return

            for prefix in self.ranges:
                # search for prefix the slow way. I dont know how to make this shorter because IP can be in shortened form so that
                # in every case I had to put it in full form and then slowly compare strings with prefixes.
                if prefix and self.ip in prefix:
                    self.ip_seen[self.ip] = prefix
                    self.get = self.ranges[prefix]
                    return

        if self.see:
            print(f"Whois {self.ip}...", end="", flush=True)
        get = self.analyze()  # prefix, location, mail, asn, netname, country
        if self.see:
            print(get[2])

        prefix = get[0]
        self.ip_seen[self.ip] = prefix
        if not prefix:
            logger.info("No prefix found for IP {}".format(self.ip))
            # get = None, "foreign", "unknown", None, None, None, None
        # elif prefix in self.ranges:
        #    X not valid for unknown_mode # IP in ranges wasnt found and so that its prefix shouldnt be in ranges.
        #    raise AssertionError("The prefix " + prefix + " shouldn't be already present. Tell the programmer")
        self.get = self.ranges[prefix] = get

    @staticmethod
    def url2hostname(url):
        """ Covers both use cases "http://example.com..." and "example.com..." """
        s = urlsplit(url)
        return s.netloc or s.path.split("/")[:1][0]

    hostname_cache = {}

    @classmethod
    def hostname2ip(cls, hostname):
        if hostname not in cls.hostname_cache:
            try:
                cls.hostname_cache[hostname] = socket.gethostbyname(hostname)
            except OSError:
                cls.hostname_cache[hostname] = False
        return cls.hostname_cache[hostname]

    def resolve_unknown_mail(self):
        """ Forces to load abusemail for an IP.
        We try first omit -r flag and then add -B flag.

        XX Note that we try only RIPE server because it's the only one that has flags -r and -B.
        If ARIN abusemail is not found, we have no help yet. I dont know if that ever happens.
            XX We prefer general calling of whois program instead of asking him for different whois servers manually
            so I'm not sure if whois program calls RIPE with -r by default or not.
            If not, we should let here just -B flag.

        """
        self._exec(server="ripe (no -r)", server_url="whois.ripe.net")  # no -r flag
        self.get_abusemail(True)
        if self.abusemail == Config.UNKNOWN_NAME:
            self._exec(server="ripe (-B flag)", server_url="whois.ripe.net -B")  # with -B flag
            self.get_abusemail(True)

    def _str2prefix(self, s):
        """ Accepts formats:
            88.174.0.0 - 88.187.255.255, 216.245.0.0/18, 2000::/7 ...
        """
        sp = s.split(" - ")
        try:
            if len(sp) > 1:
                return IPRange(sp[0], sp[1])
            else:
                return IPNetwork(s)
        except Exception as e:
            logger.warning("Prefix {} cannot be parsed.".format(s))
            Config.error_caught()

    def url2ip(url):
        """ Shorten URL to domain, find out related IPs list. """
        url = urlparse(url.strip())  # "foo.cz/bar" -> "foo.cz", "http://foo.cz/bar" -> "foo.cz"
        uri = url.hostname if url.scheme else url.path
        try:
            return socket.gethostbyname(uri)  # returns 1 address only, we do not want all of them
        except socket.gaierror as e:
            # logger.warning("Socket gethostbyname error for URI {} .".format(uri))
            # Config.error_caught()
            return None
        # if we wanted all of the IPs:
        # recs = socket.getaddrinfo(uri, 0, 0, 0, socket.IPPROTO_TCP)
        # result = []
        # for ip in recs:
        #    result.append(ip[4][0])
        # return result

    def _match_response(self, patterns, last_word=False):
        """
        :param pattern: pattern string or list of strings Xcompiled regular expression
        :param last_word: returns only the last word of whole matched expression else last group (ex: the one in parentheses)

        # , take_nth=None, group=None
        # :param take_nth: if available, return n-th result instead of the first available
        #     I.E. `whois 131.72.138.234 | grep ountr` returns three countries: UY, CL, CL.
        #     ARIN registry informs us that this IP is a LACNIC resource and prints out LACNIC address in UY.
        #     However, CL is the country the IP is hosted in.
        # :param group: returned group - default: last group is returned (ex: the one in parentheses)
        :return:
        """
        if type(patterns) is str:
            patterns = [patterns]

        match = None
        for chunk in self.whoisResponse:
            for pattern in patterns:
                # it = re.finditer(pattern, self.whoisResponse) if type(pattern) is str else pattern(self.whoisResponse)
                match = re.search(pattern, chunk)
                # for i, match in enumerate(re.finditer(pattern, chunk)):
                #     if not take_nth or i + 1 == take_nth:
                #         break

                if match:
                    if last_word:  # returns only last word
                        return re.search(r'[^\s]*$', match[0]).group(0)
                    else:
                        return match[len(match.groups())]
        return ""  # no pattern result found

        # for line in self.whoisResponse.split("\n"):
        #     result = re.search(grep, line)
        #     if result:
        #         if lastWord:  # returns only last word
        #             return re.search('[^\s]*$', line).group(0)  # \w*
        #         else:  # returns whole line
        #             return line
        # return ""  # no grep result found

    def analyze(self):
        """
        :return: prefix, "local"|"foreign", incident-contact ( = abuse-mail|country), asn, netname, country, abuse-mail
        """
        prefix = country = ""

        for server in list(self.servers):
            self._exec(server=server)
            while True:
                # 154.48.234.95
                #   Found a referral to rwhois.cogentco.com:4321.
                #   network:IP-Network:154.48.224.0/19
                #   network:Country:DE
                # 82.175.175.231 'country: NL # BE GB DE LU' -> 'NL'
                country = self._match_response(r'country(-code)?:\s*([a-z]{2})')
                if country == "eu":
                    # "EU # Worldwide" (2a0d:f407:1003::/48)
                    # 'EU # Country is really world wide' (64.9.241.202)
                    # 'EU' (89.41.60.38) (RIPE returned this value)
                    country = ""

                if not country and server == "general":
                    if self._match_response("no match found for n +"):
                        # whois 141.138.197.0/24 ends with this phrase and does not try RIPE which works
                        self._exec(server="ripe", server_url="whois.ripe.net")
                        continue
                    if self._match_response(
                            "the whois is temporary unable to query arin for the requested resource. please try again later"):
                        # whois 154.48.234.95 sometimes ends up like this - when we ask ARIN, we can hang too
                        self._exec(server="arin", server_url="whois.arin.net")
                        continue
                    if self._match_response("block not managed by the ripe ncc"):
                        # whois 109.244.112.0 replies RIPE that they don't manage the block
                        self._exec(server="apnic", server_url="whois.apnic.net")
                        continue
                    if self._match_response("query rate limit exceeded"):  # LACNIC gave me this - seems 300 s needed
                        logger.warning(f"Whois server {self.last_server} query rate limit exceeded for: {self.ip}. Sleeping for 300 s...")
                        time.sleep(300)
                        self._exec(server=server)
                        continue
                    if self.last_server == "rwhois.gin.ntt.net":  # 204.2.250.0
                        self._exec(server="arin", server_url="whois.arin.net")
                        continue
                    if self.last_server in ["whois.twnic.net", "whois.nic.ad.jp", "whois.nic.or.kr"]:
                        # twnic
                        # 210.241.57.0
                        # whois 203.66.23.2 replies whois.twnic.net.tw with "The IP address not belong to TWNIC"
                        # jp: 185.243.43.0
                        # krnic: 125.129.170.2
                        self._exec(server="apnic", server_url="whois.apnic.net")
                        continue

                if not country:
                    country = self._load_country_from_addresses(country)
                break
            if not country:
                fail = None
                if self._match_response("network is unreachable") or self._match_response("name or service not known"):
                    fail = f"Whois server {self.servers[server]} is unreachable. Disabling for this session."
                if self._match_response("access denied"):  # RIPE gave me this
                    fail = f"Whois server {self.servers[server]} access denied. Disabling for this session."
                if self._match_response("invalid search key"):
                    logger.warning(f"Invalid search key for: {self.ip}")

                if fail:
                    logger.warning(fail)
                    Whois.servers.pop(server)
                    continue
            else:
                break

        # if not country:
        #    country = Config.UNKNOWN_NAME

        asn = self._match_response(r'\norigin(.*)\d+', last_word=True)
        netname = self._match_response([r'netname:\s*([^\s]*)', r'network:network-name:\s*([^\s]*)'])

        # loads prefix
        match = self._match_response(["% abuse contact for '([^']*)'",
                                      "% information related to '([^']*)'",
                                      # ip 151.80.121.243 needed this , % information related to \'151.80.121.224 - 151.80.121.255\'\n\n% no abuse contact registered for 151.80.121.224 - 151.80.121.255
                                      r"inetnum:\s*(.*)",  # inetnum:        151.80.121.224 - 151.80.121.255
                                      r"netrange:\s*(.*)",  # NetRange:       216.245.0.0 - 216.245.63.255
                                      r"cidr:\s*(.*)",  # CIDR:           216.245.0.0/18
                                      r"network:ip-network:\s*(.*)"  # whois 154.48.250.2 "network:IP-Network:154.48.224.0/19"
                                      ])
        if match:
            prefix = self._str2prefix(match)

        if country not in Config.get("local_country", "FIELDS"):
            return prefix, "foreign", country, asn, netname, country, self.get_abusemail()
        else:
            # print("Abusemail: ")
            # print("abusemail loaded {}".format(self.abusemail))
            if Whois.unknown_mode:
                self.resolve_unknown_mail()
            ab = self.get_abusemail()
            return prefix, "local", ab, asn, netname, country, ab

    def _load_country_from_addresses(self, country):
        # let's try to find country in the non-standardised address field
        for address in re.findall(r"address:\s+(.*)", "\n".join(self.whoisResponse)):
            for s in countries:
                if s in address:
                    logger.info(f"Found country in {address}")
                    country = countries[s]
                    return country
        return ""

    reAbuse = re.compile('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}')

    def get_abusemail(self, force_load=False):
        """ Loads abusemail from last whois response OR from whois json api. """
        if hasattr(self, "abusemail") and not force_load:
            return self.abusemail
        self.abusemail = ""
        match = self.reAbuse.search(self._match_response(['% abuse contact for.*',
                                                          'orgabuseemail.*',
                                                          'abuse-mailbox.*',
                                                          "e-mail:.*"  # whois 179.50.80.0/21
                                                          ]))
        if match:
            self.abusemail = match.group(0)

        # if not self.abusemail:
        #    self.abusemail = Config.UNKNOWN_NAME
        return self.abusemail

    regRe = re.compile(r"using server (.*)\.")

    def _exec(self, server, server_url=None):
        """ Query whois server """
        if server is "general":
            cmd = ["whois", "--verbose", self.ip]
        else:
            if not server_url:
                server_url = Whois.servers[server]
            cmd = ["whois", "--verbose", "-h", server_url, "--", self.ip]
        self.last_server = None  # check what registry whois asks - may use a strange LIR that returns non-senses
        try:
            p = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            response = p.stdout.read().decode("unicode_escape").strip().lower()  # .replace("\n", " ")
            response += p.stderr.read().decode("unicode_escape").strip().lower()
        except UnicodeDecodeError:  # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whoisResponse = []
            logger.warning("Whois response for IP {} on server {} cannot be parsed.".format(self.ip, server))
        except TypeError:  # could not resolve host
            self.whoisResponse = []
        else:
            try:
                self.last_server = Whois.regRe.search(response).groups()[0]
            except (IndexError, AttributeError):
                pass

            # Sometimes, a registry calls another registry for you. This may chain.
            # We prioritize by the most recent to the first.
            # So when whois 154.48.234.95 goes to AfriNIC that goes to ARIN that goes to rwhois.cogentco.com:4321,
            # we find country in Cogento, then in ARIN, then in AfriNIC.
            # This may lead to the behaviour when Country is from Cogento and Netname is from ARIN.
            # I don't know how to handle this better.
            # Another example is
            # whois 198.55.103.47 leads to "Found a referral to rwhois.quadranet.com:4321."
            # 154.48.234.95 goes to AfriNIC that goes to ARIN that says:
            #   CIDR:           154.48.0.0/16
            #   Country:        US
            #   Found a referral to rwhois.cogentco.com:4321.
            #   network:IP-Network:154.48.224.0/19
            #   network:Country:DE
            ref_s = "found a referral to "
            self.whoisResponse = response.split(ref_s)[::-1]

            # i = self.whoisResponse.find(ref_s)
            # # import ipdb; ipdb.set_trace()
            # if i > -1:
            #     self.whoisResponse = self.whoisResponse[i + len(ref_s):]
        finally:
            Whois.stats[self.last_server or server] += 1
