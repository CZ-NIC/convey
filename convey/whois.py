import logging
import re
import socket
from collections import OrderedDict
from subprocess import PIPE, Popen
from urllib.parse import urlparse, urlsplit

from netaddr import IPRange, IPNetwork

from .config import Config

logger = logging.getLogger(__name__)


class Whois:
    unknown_mode = False

    @staticmethod
    def init(stats, ranges, ip_seen):
        Whois.stats = stats
        Whois.ranges = ranges
        Whois.ip_seen = ip_seen  # ip_seen[ip] = prefix
        Whois.servers = OrderedDict()
        Whois.unknown_mode = False  # if True, we use b flag in abusemails
        if Config.get("whois_mirror"):  # try a fast local whois-mirror first
            Whois.servers["mirror"] = Config.get("whois_mirror")
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

        print(self.ip, "...", end="", flush=True)
        get = self.analyze()  # prefix, location, mail, asn, netname, country
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
        # print("IP: {}, Prefix: {}, Record: {}, Kind: {}".format(ip, prefix,record, location)) # XX put to logging

    @staticmethod
    def url2hostname(url):
        """ Covers both use cases "http://example.com..." and "example.com..." """
        s = urlsplit(url)
        return s.netloc or s.path.split("/")[:1][0]

    hostname_cache = {}

    @classmethod
    def hostname2ip(cls, hostname):
        if hostname not in cls.hostname_cache:
            cls.hostname_cache[hostname] = socket.gethostbyname(hostname)
        return cls.hostname_cache[hostname]

    def analyze(self):
        """
        :return: prefix, "local"|"foreign", incident-contact ( = abuse-mail|country), asn, netname, country, abuse-mail
        """
        country = self._loadCountry()
        # print("country loaded {}".format(self.country))
        prefix = self._loadPrefix()
        # print("prefix loaded {}".format(self.prefix))
        if country not in Config.get("local_country"):
            return prefix, "foreign", country, self.asn, self.netname, country, self.getAbusemail()
        else:
            # print("Abusemail: ")
            # print("abusemail loaded {}".format(self.abusemail))
            if Whois.unknown_mode:
                self.resolveUnknownMail()
            ab = self.getAbusemail()
            return prefix, "local", ab, self.asn, self.netname, country, ab

    def resolveUnknownMail(self):
        """ Forces to load abusemail for an IP.
        We try first omit -r flag and then add -B flag.

        XX Note that we tries only RIPE server because it's the only one that has flags -r and -B.
        If ARIN abusemail is not found, we have no help yet. I dont know if that ever happens.

        """
        self._exec(server="ripe (no -r)", server_url="whois.ripe.net")  # no -r flag
        self.getAbusemail(True)
        if self.abusemail == Config.UNKNOWN_NAME:
            self._exec(server="ripe (-B flag)", server_url="whois.ripe.net -B")  # with -B flag
            self.getAbusemail(True)
        return self.abusemail

    def _loadPrefix(self):
        """ Loads prefix from last whois response. """
        for grep, pattern in [('% abuse contact for.*', r"for '([^']*)'"),
                              ('% information related to.*', r"information related to '([^']*)'"),
                              # ip 151.80.121.243 needed this , % information related to \'151.80.121.224 - 151.80.121.255\'\n\n% no abuse contact registered for 151.80.121.224 - 151.80.121.255
                              ("inetnum.*", r"inetnum:\s*(.*)"),  # inetnum:        151.80.121.224 - 151.80.121.255
                              ("netrange.*", r"netrange:\s*(.*)"),  # NetRange:       216.245.0.0 - 216.245.63.255
                              ("cidr.*", r"cidr:\s*(.*)")  # CIDR:           216.245.0.0/18
                              ]:
            match = re.search(pattern, self._match_response(grep))
            if match:
                return self._str2prefix(match.group(1))

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
            Config.error_catched()

    def url2ip(url):
        """ Shorten URL to domain, find out related IPs list. """
        url = urlparse(url.strip())  # "foo.cz/bar" -> "foo.cz", "http://foo.cz/bar" -> "foo.cz"
        uri = url.hostname if url.scheme else url.path
        try:
            return socket.gethostbyname(uri)  # returns 1 address only, we do not want all of them
        except socket.gaierror as e:
            logger.warning("Socket gethostbyname error for URI {} .".format(uri))
            Config.error_catched()
        # if we wanted all of the IPs:
        # recs = socket.getaddrinfo(uri, 0, 0, 0, socket.IPPROTO_TCP)
        # result = []
        # for ip in recs:
        #    result.append(ip[4][0])
        # return result

    def _match_response(self, pattern, lastWord=False, takeNth=None, group=0):
        """
        :param pattern: pattern string Xcompiled regular expression
        :param lastWord: returns only the last word of whole matched expression Xgrepped line
        :param takeNth: if available, return n-th result instead of the first available
            I.E. `whois 131.72.138.234 | grep ountr` returns three countries: UY, CL, CL.
            ARIN registry informs us that this IP is a LACNIC resource and prints out LACNIC address in UY.
            However, CL is the country the IP is hosted in.
        :param group: returned group
        :return:
        """
        match = None
        # it = re.finditer(pattern, self.whoisResponse) if type(pattern) is str else pattern(self.whoisResponse)
        for i, match in enumerate(re.finditer(pattern, self.whoisResponse)):
            if not takeNth or i + 1 == takeNth:
                break

        if match:
            if lastWord:  # returns only last word
                return re.search('[^\s]*$', match[0]).group(0)
            else:
                return match[group]
        else:
            return ""  # no pattern result found

        # for line in self.whoisResponse.split("\n"):
        #     result = re.search(grep, line)
        #     if result:
        #         if lastWord:  # returns only last word
        #             return re.search('[^\s]*$', line).group(0)  # \w*
        #         else:  # returns whole line
        #             return line
        # return ""  # no grep result found

    def _loadCountry(self):
        country = ""

        for server in list(self.servers):
            self._exec(server=server)
            country = self._match_response('[c,C]ountry(.*)', lastWord=True, takeNth=2)
            self.asn = self._match_response('\n[o,O]rigin(.*)', lastWord=True)
            self.netname = self._match_response('\n[n,N]etname(.*)', lastWord=True)
            if not country:
                fail = None
                if self._match_response("network is unreachable") or (
                        self._match_response("name or service not known") and len(self.whoisResponse) < 150):
                    fail = "Whois server {} is unreachable. Disabling for this session.".format(self.servers[server])
                if self._match_response("access denied"):
                    fail = "Whois server {} access denied. Disabling for this session.".format(self.servers[server])
                if fail:
                    logger.warning(fail)
                    Whois.servers.pop(server)
            if country:
                # sanitize whois confusion
                if ":" in country:
                    # whois 198.55.103.47 leads to "Found a referral to rwhois.quadranet.com:4321."
                    # 154.48.234.95 goes to AfriNIC that goes to ARIN that says:
                    #   CIDR:           154.48.0.0/16
                    #   Country:        US
                    #   Found a referral to rwhois.cogentco.com:4321.
                    #   network:IP-Network:154.48.224.0/19
                    #   network:Country:DE
                    country = country.split(":")[1]
                if country[0:4].lower() == "wide":
                    # ex: 'EU # Country is really world wide' (the last word)
                    #  (64.9.241.202) (Our mirror returned this result sometimes)
                    country = ""
                    continue
                if country[0:2].lower() == "eu":  # ex: 'EU' (89.41.60.38) (RIPE returned this value)
                    country = ""
                    continue

                # sanitize multiple countries in one line
                #  ** Since we take only last word, only Country "LU" will be taken. **
                # if len(self.country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
                #    self.country = self.country.split("#")[0].strip(" ")
                break

        if not country:
            country = Config.UNKNOWN_NAME
        return country

    reAbuse = re.compile('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}')

    def getAbusemail(self, forceload=False):
        """ Loads abusemail from last whois response OR from whois json api. """
        if hasattr(self, "abusemail") and not forceload:
            return self.abusemail
        self.abusemail = ""
        for grep in [('% abuse contact for.*'), ('orgabuseemail.*'), ('abuse-mailbox.*')]:
            match = self.reAbuse.search(self._match_response(grep))
            # the last whois query was the most successful, it fetched country so that it may have abusemail inside as well
            if match:
                self.abusemail = match.group(0)

        if not self.abusemail:
            self.abusemail = Config.UNKNOWN_NAME
        return self.abusemail

    def _exec(self, server, server_url=None):
        """ Query whois server """
        if server is "general":
            cmd = ["whois", self.ip]
        else:
            if not server_url:
                server_url = Whois.servers[server]
            cmd = ["whois", "-h", server_url, "--", self.ip]
        Whois.stats[server] += 1
        p = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            self.whoisResponse = p.stdout.read().decode("unicode_escape").strip().lower()  # .replace("\n", " ")
            self.whoisResponse += p.stderr.read().decode("unicode_escape").strip().lower()
        except UnicodeDecodeError:  # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whoisResponse = ""
            logger.warning("Whois response for IP {} on server {} cannot be parsed.".format(self.ip, server))
