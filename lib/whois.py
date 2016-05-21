# Work with Whoisem
import ipaddress
import ipdb
import json
from lib.config import Config
import logging
from netaddr import *
import re
import socket
from subprocess import PIPE
from subprocess import Popen
import sys
from urllib.parse import urlparse
import urllib.request
from collections import defaultdict
logging.FileHandler('whois.log', 'a')

class Whois:

    stats = defaultdict(int)

    def __init__(self, ip):
        self.ip = ip #

    ## 
    # returns prefix, local|foreign, country|abusemail
    def analyze(self):
        #print("anal starts {}".format(self.ip))
        self._loadCountry()
        print("country loaded {}".format(self.country))
        self._loadPrefix()
        print("prefix loaded {}".format(self.prefix))
        if not self.country in Config.get("local_country"):
            return self.prefix, "foreign", self.country
        else:
            #print("Abusemail: ")
            self._loadAbusemail()
            print("abusemail loaded {}".format(self.abusemail))
            return self.prefix, "local", self.abusemail

    def _loadPrefix(self):
        """ Loads prefix from last whois response. """
        self.prefix = ""
        for grep, pattern in [('% abuse contact for', r"for '([^']*)'"),
                            ('% information related to', r"information related to '([^']*)'"), # ip 151.80.121.243 needed this , % information related to \'151.80.121.224 - 151.80.121.255\'\n\n% no abuse contact registered for 151.80.121.224 - 151.80.121.255
                            ("inetnum", r"inetnum:\s*(.*)"), # inetnum:        151.80.121.224 - 151.80.121.255
                            ("netrange", r"netrange:\s*(.*)"),#NetRange:       216.245.0.0 - 216.245.63.255
                            ("cidr", r"cidr:\s*(.*)")#CIDR:           216.245.0.0/18
                            ]:
            match = re.search(pattern, self._grepResponse(grep))
            if match:
                self._str2prefix(match.group(1))
                return

    def _str2prefix(self, s):
        """ Accepts formats:
            88.174.0.0 - 88.187.255.255
            216.245.0.0/18
            xxx (ipv6 by melo taky, ne?)
        """
        sp = s.split(" - ")
        try:
            if len(sp) > 1:
                self.prefix = IPRange(sp[0], sp[1])
            else:
                self.prefix = IPNetwork(s)
        except Exception as e:
            print("Prefix {} cannot be parsed.".format(s))
            Config.errorCatched()

    def url2ip(url):
        """ Shorten URL to domain, find out related IPs list. """
        recs = socket.getaddrinfo(urlparse(url.strip()).hostname, 0, 0, 0, socket.IPPROTO_TCP)
        result = []
        for ip in recs:
            result.append(ip[4][0])
        return result
        # X socket.gethostbyname returns 1 adress only, we want all of them

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
        query = self.ip
        self.country = ""
        #cmd = query + " | strings | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"        
        def getCountry(cmd, server):
            self.stats[server] += 1
            self._exec(cmd)
            return self._grepResponse('(.*)[c,C]ountry(.*)', lastWord=True)

        if Config.get("whois_mirror"):
            self.country = getCountry("whois -r -h {} -- {}".format(Config.get("whois_mirror"), query),"mirror") # try our fast whois-mirror in cz.nic
            if self._grepResponse("network is unreachable"):
                print("Whois mirror {} is unreachable. Disabling for this session.".format(Config.get("whois_mirror")))
                Config.set("whois_mirror", "")

        # sanitize whois mirror failure
        if not self.country or self.country[0:2].lower() == "eu": #ex: 'EU # Country is really world wide' (64.9.241.202) (Our mirror returned this result sometimes)
            self.country = getCountry("whois -r " + query, "default") # try worldwide whois, not CZ.NIC-mirror. The default is RIPE, right?
        
        # sanitize multiple countries in one line
        if self.country and len(self.country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
            self.country = self.country.split("#")[0].strip(" ")

        # in the case of 10_16_Honeypot it happened that whois asked we dont know who. We thought it asked ARIN, but it didnt seem to.
        if not self.country:
            self.country = getCountry("whois -r -h whois.arin.net " + query, "arin") # I think i dont have to ask ripe because ARIN directly links to it (whois -h whois.arin.net 109.123.209.188 returned RIPE result)
        if not self.country:
            self.country = getCountry("whois -r -h whois.lacnic.net " + query, "lacnic")
        if not self.country:
            self.country = getCountry("whois -r -h whois.apnic.net " + query, "apnic")
        if not self.country:
            self.country = getCountry("whois -r -h whois.afrinic.net " + query, "afrinic")

        if not self.country:
            self.country = "unknown"
        
    def _loadAbusemail(self):
        """ Loads abusemail from last whois response OR from whois json api. """
        self.abusemail = ""
        pattern = '[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}'
        for grep in [('% abuse contact for'),('orgabuseemail'),('abuse-mailbox')]:
            match = re.search(pattern, self._grepResponse(grep)) # the last whois query was the most successful, it fetched country so that it may have abusemail inside as well
            if match:
                self.abusemail = match.group(0)
                return
        # self.abusemail = self._grepResponse(grep='abuse-mailbox', lastWord=True)

        # call whois json api
        if not self.abusemail: # slower method, without limits
            url = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=" + self.ip
            jsonp = urllib.request.urlopen(url).read().decode("utf-8").replace("\n", "")
            self.stats["ripejson"] += 1
            response = json.loads(jsonp)
            if response["status"] == "ok": # we may fetch: authorities: ripe. Do we want it?
                try:
                    self.abusemail = response["data"]["anti_abuse_contacts"]["abuse_c"][0]["email"]
                    if not self.prefix:
                        self._str2prefix(response["data"]["holder_info"]["resource"]) # "resource": "88.174.0.0 - 88.187.255.255"
                except IndexError: # 74.221.223.179 doesnt have the contact, "abuse_c": []
                    pass                                                                            
        if not self.abusemail:
            logging.info("whois-json didnt work for " + self.ip)
            self.abusemail = "unknown"
            
    def _exec(self, cmd):
        #if cmd not in Whois._cache:
        #testing: print("exec: {}".format(cmd))
        sys.stdout.write('.') # let the user see something is happening (may wont look good)
        # XXX test: sys.stdout.flush()
        p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        #print(cmd)
        try:
            self.whoisResponse = p.stdout.read().decode("utf-8").strip().lower() #.replace("\n", " ")
            self.whoisResponse += p.stderr.read().decode("utf-8").strip().lower()
        except UnicodeDecodeError: # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whoisResponse = ""
        #print("resuls {}".format(str)) #print(ip,str) when multithreaded db ripedb2.nic.cz returned empty plac#
    


### XXX BELOW ARE OLD METHODS

    bCount = 0 # count of queries that used limited flag B

    # XXX OLD PARAMS OF _EXEC!
    # We query whoisu with -B flag (it's use is limited to cca 1500 / day)
    # returns mail OR "" (if mail not available)
    def queryMailForced(query):
        Whois.bCount += 1 # we use additional B-flag
        self.abusemail = Whois._exec("whois -B -- " + query, grep='e-mail', lastWord=True)

        # XXX: Koukat se i na radek '%  Abuse ...'.
        #  starsi: XX tady bych mohl vystup whois -B ulozit a zkouset greppovat radek Abuse contact for, stejne jako se dela v queryMail. Netusim, proc se to nedeje, bud jsem to z puvodnich skriptu spatne opsaal, nebo tenkrat radek Abuse contact jeste moc neexistoval.
        #cmd = "whois -B -- " + query + " | strings | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        #self.abusemail = Whois._exec(cmd)

        if self.abusemail == "":
            self.abusemail = "unknown"
        return self.abusemail, False # False means we used queryMailForced method, we didn't spare flag -B

    # XXX OLD PARAMS OF _EXEC!
    def getAsn(ip):
        #cmd = ip + " | strings | grep ^[o,O]rigin | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        #asn = Whois._exec("whois -h ripedb.nic.cz -- " + cmd) # zeptat se rychleho whois-mirroru cz.nic
        #return asn
        return Whois._exec("whois -h ripedb.nic.cz -- " + ip, grep="^[o,O]rigin", lastWord=True)
