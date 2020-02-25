import logging
import re
from collections import OrderedDict
from datetime import datetime, timedelta
from subprocess import PIPE, Popen
from time import time, sleep

from netaddr import IPRange, IPNetwork

from .attachment import Contacts
from .config import Config, subprocess_env
from .infodicts import address_country_lowered

logger = logging.getLogger(__name__)

rirs = ["whois.ripe.netf", "whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.afrinic.net"]
whole_space = IPRange('0.0.0.0', '255.255.255.255')


class Quota:
    def __init__(self):
        self._time = None

    def try_start(self):
        if not self._time:
            self._time = datetime.now() + timedelta(seconds=300)

    def time(self):
        return self._time.strftime('%H:%M')

    def is_running(self):
        return self._time and self._time > datetime.now()

    def check_over(self):
        if self._time and self._time < datetime.now():
            self._time = None
            Whois.queued_ips = set()

    def remains(self):
        if self.is_running():
            return (self._time - datetime.now()).seconds

    class QuotaExceeded(IOError):
        pass


class UnknownValue(LookupError):
    pass


class Whois:
    slow_mode: bool
    unknown_mode: bool
    quota: Quota
    queued_ips: set
    see: int

    @classmethod
    def init(cls, stats, ranges, ip_seen, csvstats, slow_mode=False, unknown_mode=False):
        cls.quota = Quota()
        cls.csvstats = csvstats
        cls.stats = stats
        cls.ranges = ranges
        cls.ip_seen = ip_seen  # ip_seen[ip] = prefix
        cls.servers = OrderedDict()
        cls.unknown_mode = unknown_mode  # if True, we use b flag in abusemails
        cls.slow_mode = slow_mode  # due to LACNIC quota
        cls.queued_ips = set()
        cls.ttl = Config.get("whois_ttl", "FIELDS", int)
        cls.see = Config.verbosity <= logging.INFO
        if Config.get("whois_mirror", "FIELDS"):  # try a fast local whois-mirror first
            cls.servers["mirror"] = Config.get("whois_mirror", "FIELDS")
        cls.servers["general"] = None
        # Algorithm for querying custom servers:
        # for name, val in zip(["ripe", "arin", "lacnic", "apnic", "afrinic"],
        #                      ["whois.ripe.net -r", "whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.afrinic.net"]):
        #     Whois.servers[name] = val

    def __init__(self, ip):
        """
         self.get stores tuple: prefix, location, mail, asn, netname, country, ttl
        """
        self.ip = ip
        self.whois_response = []
        prefix = self.cache_load()  # try load prefix from earlier WHOIS responses
        if prefix:
            if (self.ttl != -1 and self.get[7] + self.ttl < time()) or (Whois.unknown_mode and not self.get[6]):
                # the TTL is too old, we cannot guarantee IP stayed in the same prefix, let's get rid of the old results
                # OR we are in unknown_mode which means we want abusemail. If not here, maybe another IP claimed
                # a range superset without abuse e-mail. Delete this possible superset
                # We do not have to call now `self.get = None; del self.ip_seen[ip]` if there is no need to be thread safe,
                #   these lines will be called at the function end.
                del self.ranges[prefix]
            else:
                self.count_stats()
                return

        if self.see:
            print(f"Whois {ip}... ", end="", flush=True)
        if Whois.slow_mode:
            if self.see:
                print("waiting 7 seconds... ", end="", flush=True)
            sleep(7)
        get = self.analyze()  # prefix, location, mail, asn, netname, country...
        if self.see:
            print(get[2] or "no incident contact.")
        prefix = get[0]
        if not prefix:
            logger.info(f"No prefix found for IP {ip}")
            prefix = IPRange(0, 0)  # make key consistent when saving into cache
        self.ip_seen[ip] = prefix
        self.get = self.ranges[prefix] = get
        self.count_stats()

    def cache_load(self):
        if self.ip in self.ip_seen:  # ip has been seen in the past
            prefix = self.ip_seen[self.ip]
            if prefix not in self.ranges:  # removed ex: due to TTL
                return
            self.get = self.ranges[prefix]
            return prefix
        elif self.ip in self.queued_ips:
            raise self.quota.QuotaExceeded
        for prefix in self.ranges:
            # search for prefix the slow way. I dont know how to make this shorter because IP can be in shortened form so that
            # in every case I had to put it in full form and then slowly compare strings with prefixes.
            if prefix and self.ip in prefix:
                self.get = self.ranges[prefix]
                self.ip_seen[self.ip] = prefix
                return prefix

    def count_stats(self):
        self.csvstats["ip_unique"].add(self.ip)
        mail = self.get[6]
        contact = self.get[2]
        reg = self.get[1]
        known = "known" if mail else "unknown"
        self.csvstats[f"ip_{reg}_{known}"].add(self.ip)
        self.csvstats[f"prefix_{reg}_{known}"].add(self.get[0])

        if mail:
            self.csvstats[f"abusemail_{reg}"].add(mail)

        if reg == "abroad":
            country = self.get[5]
            if country in Contacts.country2mail:
                known = "known"
            elif mail:
                known = "unofficial"
                self.csvstats[f"abusemail_{known}"].add(mail)  # subset of abusemail_abroad
                self.csvstats[f"prefix_csirtmail_{known}"].add(self.get[0])  # subset of prefix_abroad_un/known
            else:  # we do not track the amount of unknown IP addresses that should be delivered to countries
                known = None

            if known:
                self.csvstats[f"ip_csirtmail_{known}"].add(self.ip)
                self.csvstats[f"csirtmail_{known}"].add(country)

        if not mail and Config.get("whois_reprocessable_unknown", "FIELDS", get=bool):
            raise UnknownValue

    def resolve_unknown_mail(self):
        """ Forces to load abusemail for an IP.
        We try first omit -r flag and then add -B flag.

        XX -B flag disabled (at least temporarily). Document.

        XX Note that we try only RIPE server because it's the only one that has flags -r and -B.
        If ARIN abusemail is not found, we have no help yet. I dont know if that ever happens.
            XX We prefer general calling of whois program instead of asking him for different whois servers manually
            so I'm not sure if whois program calls RIPE with -r by default or not.
            If not, we should let here just -B flag.

        """
        self._exec(server="ripe (no -r)", server_url="whois.ripe.net")  # no -r flag
        return self.get_abusemail()
        # XX
        # if self.abusemail == Config.UNKNOWN_NAME:
        #     self._exec(server="ripe (-B flag)", server_url="whois.ripe.net -B")  # with -B flag
        #     self.get_abusemail(True)

    @staticmethod
    def _str2prefix(s):
        """ Accepts formats:
            88.174.0.0 - 88.187.255.255, 216.245.0.0/18, 2000::/7 ...
        """
        # We have to strip it because of
        #   whois 172.97.38.164
        #   network:netrange:172.97.36.0 -  172.97.39.255
        sp = [a.strip() for a in s.split(" - ")]
        try:
            if len(sp) > 1:
                return IPRange(*sp)
            else:
                return IPNetwork(s)
        except Exception as e:
            logger.warning("Prefix {} cannot be parsed.".format(s))
            Config.error_caught()

    def _match_response(self, patterns, last_word=False):
        """
        :param patterns: pattern string or list of strings
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

        for chunk in self.whois_response:
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
        :return: prefix, "local"|"abroad", incident-contact ( = abuse-mail|country), asn, netname, country, abuse-mail, TTL
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
                        self.quota.try_start()
                        if Config.get("lacnic_quota_skip_lines", "FIELDS") and not self.slow_mode:
                            if self.see:
                                print("LACNIC quota exceeded.")
                            self.queued_ips.add(self.ip)
                            raise self.quota.QuotaExceeded
                        else:
                            logger.warning(f"Whois server {self.last_server} query rate limit exceeded for: {self.ip}."
                                           f" Sleeping for 300 s till {self.quota.time()}... (you may howevec Ctrl-C to skip)")
                            sleep(300)
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

                # loads prefix
                match = self._match_response(["% abuse contact for '([^']*)'",
                                              "% information related to '([^']*)'",
                                              # ip 151.80.121.243 needed this , % information related to
                                              # \'151.80.121.224 - 151.80.121.255\'\n\n% no abuse contact registered
                                              # for 151.80.121.224 - 151.80.121.255
                                              r"inetnum:\s*(.*)",  # inetnum:        151.80.121.224 - 151.80.121.255
                                              r"netrange:\s*(.*)",  # NetRange:       216.245.0.0 - 216.245.63.255
                                              r"cidr:\s*(.*)",  # CIDR:           216.245.0.0/18
                                              r"network:ip-network:\s*(.*)"
                                              # whois 154.48.250.2 "network:IP-Network:154.48.224.0/19"
                                              ])
                if match:
                    prefix = self._str2prefix(match)
                    if prefix and prefix == whole_space:
                        # whois 104.224.36.20 asks -h whois.apnic.net
                        # inetnum:        0.0.0.0 - 255.255.255.255
                        # netname:        IANA-BLOCK
                        # descr:          General placeholder reference for all IPv4 addresses
                        # country:        AU
                        # RIPE if asked does provide at least prefix:
                        # % No abuse contact registered for 104.166.192.0 - 104.232.35.255
                        #
                        # inetnum:        104.166.192.0 - 104.232.35.255
                        # netname:        NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK
                        prefix = None
                        if server == "general":
                            self._exec(server="ripe", server_url="whois.ripe.net")
                            server = "disabled apnic"
                            continue

                if not country:
                    country = self._load_country_from_addresses()
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

        asn = self._match_response(r'\norigin(.*)\d+', last_word=True)
        netname = self._match_response([r'netname:\s*([^\s]*)', r'network:network-name:\s*([^\s]*)'])

        ab = self.get_abusemail()
        if Whois.unknown_mode and not ab:
            ab = self.resolve_unknown_mail()

        local = Config.get("local_country", "FIELDS")
        if local and country not in local:
            mail = Contacts.country2mail[country] if country in Contacts.country2mail else ab
            get1 = "abroad"
            get2 = f"{country}{Config.ABROAD_MARK}{mail}" if mail else ""
        else:
            get1 = "local"
            get2 = ab
        return prefix, get1, get2, asn, netname, country, ab, int(time())

    def _load_country_from_addresses(self):
        # let's try to find country in the non-standardised address field
        for address in re.findall(r"address:\s+(.*)", "\n".join(self.whois_response)):
            c = address_country_lowered(address)
            if c:
                logger.info(f"Found country in {address}")
                return c
        return ""

    reAbuse = re.compile('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}')

    def get_abusemail(self):
        """ Loads abusemail from last whois response OR from whois json api. """
        match = self.reAbuse.search(self._match_response(['% abuse contact for.*',
                                                          'orgabuseemail.*',
                                                          'abuse-mailbox.*',
                                                          "e-mail:.*"  # whois 179.50.80.0/21
                                                          ]))
        return match.group(0) if match else ""

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
            # in case wrong env is set to whois, we get `147.32.106.205` country NL and not CZ
            # because we will not find string "found a referral to " in the WHOIS response
            p = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=subprocess_env)
            response = p.stdout.read().decode("unicode_escape").strip().lower()  # .replace("\n", " ")
            response += p.stderr.read().decode("unicode_escape").strip().lower()
        except UnicodeDecodeError:
            # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whois_response = []
            logger.warning("Whois response for IP {} on server {} cannot be parsed.".format(self.ip, server))
        except TypeError:  # could not resolve host
            self.whois_response = []
        except FileNotFoundError:
            Config.missing_dependency("whois")
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
            self.whois_response = response.split(ref_s)[::-1]

            # i = self.whoisResponse.find(ref_s)
            # if i > -1:
            #     self.whoisResponse = self.whoisResponse[i + len(ref_s):]
        finally:
            Whois.stats[self.last_server or server] += 1
