# Work with Whoisem
import ipaddress
import json
import re
import socket
from subprocess import PIPE
from subprocess import Popen
import sys
from urllib.parse import urlparse
import urllib.request
from netaddr import *
import logging


__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Mar 24, 2015 6:08:16 PM$"
logging.basicConfig(filename='whois.log',level=logging.DEBUG)

class Whois:

    ipDict = {} # set present IP adresses [ip] = object
    _cache = {}
    _ranges = {} # ["IPRange" => abusemail]

    def __init__(self, ip):
        self.ip = ip #
        pass

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

    def queryCountry(query):
        #cmd = query + " | strings | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        def getCountry(cmd):
            return Whois._exec(cmd, grep = '(.*)[c,C]ountry(.*)', lastWord = True)

        
        country = getCountry("whois -h ripedb.nic.cz -- " + query) # try our fast whois-mirroru in cz.nic

        # sanitize whois failure
        if country[0:2].lower() == "eu": #ex: 'EU # Country is really world wide' (64.9.241.202)
            country = getCountry("whois " + query) # try worldwide whois, not CZ.NIC-mirror

        # sanitize multiple countries in one line
        if len(country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
            country = country.split("#")[0].strip(" ")

        # in the case of 10_16_Honeypot it happened that whois asked we dont know who. We thought it asked ARIN, but it didnt seem to.
        if country == "":
            country = getCountry("whois -h whois.arin.net " + query) # I think i dont have to ask ripe because ARIN directly links to it (whois -h whois.arin.net 109.123.209.188 returned RIPE result)
        if country == "":
            country = getCountry("whois -h whois.lacnic.net " + query)
        if country == "":
            country = getCountry("whois -h whois.apnic.net " + query)
        if country == "":
            country = getCountry("whois -h whois.afrinic.net " + query)

        if country == "":
            country = "unknown"
        return country

    def getAsn(ip):
        #cmd = ip + " | strings | grep ^[o,O]rigin | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        #asn = Whois._exec("whois -h ripedb.nic.cz -- " + cmd) # zeptat se rychleho whois-mirroru cz.nic
        #return asn
        return Whois._exec("whois -h ripedb.nic.cz -- " + ip, grep = "^[o,O]rigin", lastWord = True)
        
    

    def _exec(cmd, grep = "", lastWord = False):
        """
        # grep - returns grep for line
        # lastWord - returns only last word of grepped line
        """
        if cmd not in self._cache:
            #debug: print("exec: {}".format(cmd))
            sys.stdout.write('.') # let the user see something is happening (may wont look good)
            sys.stdout.flush() # XX: tohle zkusit zakomentovat, jestli se preci jen neco vypise...
            p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            s = p.stdout.read().decode("utf-8").strip().lower().replace("\n", " ")
            #print("resuls {}".format(str)) #print(ip,str) when multithreaded db ripedb2.nic.cz returned empty place
            self._cache[cmd] = s

        if grep:
            for line in self._cache[cmd]:
                result = re.match(grep, line)
                if result:
                    if lastWord: # returns only last word
                        return re.search('\w*$',result)
                    else: # returns whole line
                        return result

        return self._cache[cmd]

    # Returns abusemail for query (ip ci asn).
    # If force = True and no mail available, we ll try use another request with flag B.
    # If abusemail not found, returns "".
    def queryMail(query, force=False):
        #cmd = "whois -- " + query + " | strings | grep '\\% Abuse contact for' | grep -E -o '\\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z0-9.-]+\\b' || whois -- " + query + " | strings | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\\s*//' -e 's/\\s*$//' | sort -nr | uniq | tr '\\n' ',' | sed -e 's/,$//' -e 's/,/\\,/g'"
        #abuseMail = Whois._exec(cmd)
        for rng in Whois._ranges: # weve already seen abuseMail in this range
            if query in rng:
                return Whois._ranges[rng]
        
        text = Whois._exec("whois -- " + query, grep = '% abuse contact for')
        abuseMail = re.search('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}', text)

        if abuseMail == "":
            abuseMail = Whois._exec("whois -- " + query, grep = 'abuse-mailbox', lastWord = True)

        # JSON, prefixes
        if abuseMail == "": # slower method, without limits
            url = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=" + query
            jsonp = urllib.request.urlopen(url).read().decode("utf-8").replace("\n", "")
            response = json.loads(jsonp)
            if response["status"] == "ok":
                abuseMail = response["data"]["anti_abuse_contacts"]["abuse_c"][0]["email"]
                if abuseMail:
                    r = response["data"]["holder_info"]["resource"].split(" - ") # "resource": "88.174.0.0 - 88.187.255.255"
                    rng = IPRange(r[0],r[1])
                    Whois._ranges[rng] = abuseMail
                    if IPAddress(query) not in rng:
                        raise Exception("Given IP " + query + " is not in IPRange " + str(r) + ". This should never happen. Tell the programmer, please.")
                    # we may fetch: authorities: ripe. Do we want it?
                else: # we have to debug if whois-json is working at all...
                    logging.info("whois-json didnt work for " + query)                                                                                

        if abuseMail == "":
            if force == False:
                return "unknown", False # we rather not use flag
            else:
                return Whois.queryMailForced(query) # use flag B
        else:
            return abuseMail, True # True means we found mail at first try, we spared flag -B

    bCount = 0 # count of queries that used limited flag B

    # We query whoisu with -B flag (it's use is limited to cca 1500 / day)
    # returns mail OR "" (if mail not available)
    def queryMailForced(query):
        Whois.bCount += 1 # we use additional B-flag
        abuseMail = Whois._exec("whois -B -- " + query, grep = 'e-mail', lastWord = True)

        # XXX: Koukat se i na radek '%  Abuse ...'.
        #  starsi: XX tady bych mohl vystup whois -B ulozit a zkouset greppovat radek Abuse contact for, stejne jako se dela v queryMail. Netusim, proc se to nedeje, bud jsem to z puvodnich skriptu spatne opsaal, nebo tenkrat radek Abuse contact jeste moc neexistoval.
        #cmd = "whois -B -- " + query + " | strings | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        #abuseMail = Whois._exec(cmd)

        if abuseMail == "":
            abuseMail = "unknown"
        return abuseMail, False # False means we used queryMailForced method, we didn't spare flag -B
