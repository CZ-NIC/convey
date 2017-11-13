# Work with Whoisem
from collections import OrderedDict, defaultdict
import ipaddress
from lib.config import Config
import logging
from netaddr import *
import re
import socket
from subprocess import PIPE
from subprocess import Popen
from urllib.parse import urlparse
#logging.FileHandler('whois.log', 'a')

class Whois:

    stats = defaultdict(int)
    ranges = {}
    ipSeen = {} # ipSeen[ip] = prefix
    servers = OrderedDict()
    if Config.get("whois_mirror"):  # try our fast whois-mirror in cz.nic first
        servers["mirror"] = Config.get("whois_mirror")
    for name, val in zip(["ripe", "arin", "lacnic", "apnic", "afrinic"],
                         ["whois.ripe.net -r", "whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.afrinic.net"]):
        servers[name] = val


    def __init__(self, ip):
        self.ip = ip #

    def get(self):
        """ returns mail, location, asn, netname, country
        """
        if self.ip in self.ipSeen: # ip has been seen in the past
            prefix = self.ipSeen[self.ip]
            return self.ranges[prefix]
        else:
            for prefix, o in self.ranges.items(): # search for prefix the slow way. I dont know how to make this shorter because IP can be in shortened form so that in every case I had to put it in full form and then slowly compare strings with prefixes.
                if self.ip in prefix:
                    mail, location, asn, netname, country = o
                    self.ipSeen[self.ip] = prefix
                    return self.ranges[prefix]

            prefix, location, mail, asn, netname, country = Whois(self.ip).analyze()
            self.ipSeen[self.ip] = prefix
            if not prefix:
                logging.info("No prefix found for IP {}".format(self.ip))
                return False
            elif prefix in self.ranges:
                # IP in ranges wasnt found and so that its prefix shouldnt be in ranges.
                raise AssertionError("The prefix " + prefix + " shouldn't be already present. Tell the programmer")
            self.ranges[prefix] = mail, location, asn, netname, country
            return self.ranges[prefix]
            #print("IP: {}, Prefix: {}, Record: {}, Kind: {}".format(ip, prefix,record, location)) # XX put to logging

    def url2hostname(self):
        print("XXX TBImplemented")
        return False

    def hostname2ip(self):
        print("XXX TBImplemented")
        return False

    ##
    # returns prefix, local|foreign, country|abusemail, asn
    def analyze(self):
        self._loadCountry()
        #print("country loaded {}".format(self.country))
        self._loadPrefix()
        #print("prefix loaded {}".format(self.prefix))
        if not self.country in Config.get("local_country"):
            return self.prefix, "foreign", self.country, self.asn, self.netname,  self.country
        else:
            #print("Abusemail: ")
            self._loadAbusemail()
            #print("abusemail loaded {}".format(self.abusemail))
            return self.prefix, "local", self.abusemail, self.asn, self.netname, self.country

    def resolveUnknownMail(self):
        """ Forces to load abusemail for an IP.
        We try first omit -r flag and then add -B flag.

        XX Note that we tries only RIPE server because it's the only one that has flags -r and -B.
        If ARIN abusemail is not found, we have no help yet. I dont know if that ever happens.

        """
        self._exec(server="ripe (no -r)", serverUrl="whois.ripe.net") # no -r flag
        self._loadAbusemail()
        if self.abusemail == "unknown":
            self._exec(server="ripe (-B flag)", serverUrl="whois.ripe.net -B") # with -B flag
            self._loadAbusemail()
        return self.abusemail


    def _loadPrefix(self):
        """ Loads prefix from last whois response. """
        self.prefix = ""
        for grep, pattern in [('% abuse contact for', r"for '([^']*)'"),
            ('% information related to', r"information related to '([^']*)'"), # ip 151.80.121.243 needed this , % information related to \'151.80.121.224 - 151.80.121.255\'\n\n% no abuse contact registered for 151.80.121.224 - 151.80.121.255
            ("inetnum", r"inetnum:\s*(.*)"), # inetnum:        151.80.121.224 - 151.80.121.255
            ("netrange", r"netrange:\s*(.*)"), #NetRange:       216.245.0.0 - 216.245.63.255
            ("cidr", r"cidr:\s*(.*)")#CIDR:           216.245.0.0/18
            ]:
            match = re.search(pattern, self._grepResponse(grep))
            if match:
                self._str2prefix(match.group(1))
                return

    def _str2prefix(self, s):
        """ Accepts formats:
            88.174.0.0 - 88.187.255.255, 216.245.0.0/18, 2000::/7 ...
        """
        sp = s.split(" - ")
        try:
            if len(sp) > 1:
                self.prefix = IPRange(sp[0], sp[1])
            else:
                self.prefix = IPNetwork(s)
        except Exception as e:
            logging.warning("Prefix {} cannot be parsed.".format(s))
            Config.errorCatched()

    def url2ip(url):
        """ Shorten URL to domain, find out related IPs list. """
        url = urlparse(url.strip()) # "foo.cz/bar" -> "foo.cz", "http://foo.cz/bar" -> "foo.cz"
        uri = url.hostname if url.scheme else url.path
        try:
            return socket.gethostbyname(uri) # returns 1 adress only, we dont want all of them
        except socket.gaierror as e:
            logging.warning("Socket gethostbyname error for URI {} .".format(uri))
            Config.errorCatched()
        # if we wanted all of the IPs:
        #recs = socket.getaddrinfo(uri, 0, 0, 0, socket.IPPROTO_TCP)
        #result = []
        #for ip in recs:
        #    result.append(ip[4][0])
        #return result


    def checkIp(ip):
        """ True, if IP is well formated IPv4 or IPv6 """
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def _grepResponse(self, grep, lastWord=False):
        """
        # grep - returns grep for line
        # lastWord - returns only last word of grepped line
        """
        for line in self.whoisResponse.split("\n"):
            result = re.search(grep, line)
            if result:
                if lastWord: # returns only last word
                    return re.search('[^\s]*$', line).group(0) # \w*
                else: # returns whole line
                    return line
        return "" # no grep result found

    def _loadCountry(self):
        self.country = ""

        for server in list(self.servers):
            self._exec(server=server)
            self.country = self._grepResponse('(.*)[c,C]ountry(.*)', lastWord=True)
            self.asn = self._grepResponse('^origin(.*)', lastWord=True)
            self.netname = self._grepResponse('^netname(.*)', lastWord=True)
            if not self.country:
                if self._grepResponse("network is unreachable"):
                    logging.warning("Whois server {} is unreachable. Disabling for this session.".format(self.servers[server]))
                    Whois.servers.pop(server)
                if self._grepResponse("access denied"):
                    logging.warning("Whois server {} access denied. Disabling for this session.".format(self.servers[server]))
                    Whois.servers.pop(server)
            if self.country:
                # sanitize whois confusion
                if self.country[0:4].lower() == "wide": #ex: 'EU # Country is really world wide' (the last word) (64.9.241.202) (Our mirror returned this result sometimes)
                    self.country = ""
                    continue
                if self.country[0:2].lower() == "eu": #ex: 'EU' (89.41.60.38) (RIPE returned this value)
                    self.country = ""
                    continue

                # sanitize multiple countries in one line
                #  ** Since we take only last word, only Country "LU" will be taken. **
                #if len(self.country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
                #    self.country = self.country.split("#")[0].strip(" ")
                break

        if not self.country:
            self.country = "unknown"

    def _loadAbusemail(self):
        """ Loads abusemail from last whois response OR from whois json api. """
        self.abusemail = ""
        pattern = '[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}'
        for grep in [('% abuse contact for'), ('orgabuseemail'), ('abuse-mailbox')]:
            match = re.search(pattern, self._grepResponse(grep)) # the last whois query was the most successful, it fetched country so that it may have abusemail inside as well
            if match:
                self.abusemail = match.group(0)
                return

        # call whois json api
        # ** I think its for nothing, no new results. What about to delete it? Did it help something? **
#        if not self.abusemail: # slower method, without limits
#            url = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=" + self.ip
#            jsonp = urllib.request.urlopen(url).read().decode("unicode_escape").replace("\n", "")
#            self.stats["ripejson"] += 1
#            response = json.loads(jsonp)
#            if response["status"] == "ok": # we may fetch: authorities: ripe. Do we want it?
#                try:
#                    self.abusemail = response["data"]["anti_abuse_contacts"]["abuse_c"][0]["email"]
#                    if not self.prefix:
#                        self._str2prefix(response["data"]["holder_info"]["resource"]) # "resource": "88.174.0.0 - 88.187.255.255"
#                except IndexError: # 74.221.223.179 doesnt have the contact, "abuse_c": []
#                    pass"""


        if not self.abusemail:
            #self.stats["ripejson (didnt work, debug)"] += 1
            #logging.info("whois-json didnt work for " + self.ip)
            self.abusemail = "unknown"

    def _exec(self, server, serverUrl=None):
        """ Query whois server """
        if not serverUrl:
            serverUrl = Whois.servers[server]
        self.stats[server] += 1
        p = Popen(["whois -h " + serverUrl + " -- " + self.ip], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            self.whoisResponse = p.stdout.read().decode("unicode_escape").strip().lower() #.replace("\n", " ")
            self.whoisResponse += p.stderr.read().decode("unicode_escape").strip().lower()
        except UnicodeDecodeError: # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whoisResponse = ""
            logging.warning("Whois response for IP {} on server {} cannot be parsed.".format(ip, server))