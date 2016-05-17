# Work with Whoisem
import ipaddress
import json
import re
import socket
from subprocess import PIPE
from subprocess import Popen
from lib.config import Config
import sys
from urllib.parse import urlparse
import urllib.request
from netaddr import *
import logging
import pdb;
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Mar 24, 2015 6:08:16 PM$"
logging.FileHandler('whois.log', 'a')

class Whois:    
    def __init__(self, ip):
        self.ip = ip #

    ## 
    # returns prefix, local|foreign, country|abuseMail
    def analyze(self):
        self._loadCountry()
        self._loadPrefix()
        if not self.country in Config.get("local_country"):
            return self.prefix, "foreign", self.country
        else:
            self._loadAbusemail()
            return self.prefix, "local", self.abuseMail

    def _loadPrefix(self):
        self.prefix = ""
        match = re.search(r"for '([^']*)'", self._grepResponse('% abuse contact for'))
        if match:
            self.prefix = match.group(1)

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

    def _grepResponse(self, grep, lastWord = False):
        """
        # grep - returns grep for line
        # lastWord - returns only last word of grepped line
        """
        for line in self.whois_response.split("\n"):
            result = re.match(grep, line)
            if result:
                if lastWord: # returns only last word
                    return re.search('[^\s]*$', line).group(0) # \w*
                else: # returns whole line
                    return result.group(0)
        return "" # no grep result found

    def _loadCountry(self):
        query = self.ip
        #cmd = query + " | strings | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"        
        def getCountry(cmd):
            self._exec(cmd)
            return self._grepResponse('(.*)[c,C]ountry(.*)', lastWord = True)
        
        self.country = getCountry("whois -h ripedb.nic.cz -- " + query) # try our fast whois-mirror in cz.nic

        # sanitize whois failure
        if self.country and self.country[0:2].lower() == "eu": #ex: 'EU # Country is really world wide' (64.9.241.202)
            self.country = getCountry("whois " + query) # try worldwide whois, not CZ.NIC-mirror

        # sanitize multiple countries in one line
        if self.country and len(self.country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
            self.country = self.country.split("#")[0].strip(" ")

        # in the case of 10_16_Honeypot it happened that whois asked we dont know who. We thought it asked ARIN, but it didnt seem to.
        if not self.country:
            self.country = getCountry("whois -h whois.arin.net " + query) # I think i dont have to ask ripe because ARIN directly links to it (whois -h whois.arin.net 109.123.209.188 returned RIPE result)
        if not self.country:
            self.country = getCountry("whois -h whois.lacnic.net " + query)
        if not self.country:
            self.country = getCountry("whois -h whois.apnic.net " + query)
        if not self.country:
            self.country = getCountry("whois -h whois.afrinic.net " + query)

        if not self.country:
            self.country = "unknown"
        
    def _loadAbusemail(self):                
        self.abuseMail = ""
        text = self._grepResponse('% abuse contact for') # the last whois query was the most successful, it fetched country so that it may have abusemail inside as well
        match = re.search('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}', text)
        if match:
            self.abuseMail = match.group(0)
    
        if not self.abuseMail:
            self.abuseMail = self._grepResponse(grep = 'abuse-mailbox', lastWord = True)

        # call whois json api
        if not self.abuseMail: # slower method, without limits
            url = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=" + self.ip
            jsonp = urllib.request.urlopen(url).read().decode("utf-8").replace("\n", "")
            response = json.loads(jsonp)
            if response["status"] == "ok":                
                self.abuseMail = response["data"]["anti_abuse_contacts"]["abuse_c"][0]["email"]
                if self.abuseMail:
                    if not self.prefix:
                        prefix = response["data"]["holder_info"]["resource"] # "resource": "88.174.0.0 - 88.187.255.255"
                    # we may fetch: authorities: ripe. Do we want it?
                else: # we have to debug if whois-json is working at all...
                    logging.info("whois-json didnt work for " + self.ip)
        if not self.abuseMail:
            self.abuseMail = ""
            
    def _exec(self, cmd):
        #if cmd not in Whois._cache:
        #testing: print("exec: {}".format(cmd))
        sys.stdout.write('.') # let the user see something is happening (may wont look good)
        sys.stdout.flush()
        p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            self.whois_response = p.stdout.read().decode("utf-8").strip().lower() #.replace("\n", " ")
        except UnicodeDecodeError: # ip address 94.230.155.109 had this string 'Jan Krivsky Hl\xc3\x83\x83\xc3\x82\xc2\xa1dkov' and everything failed
            self.whois_response = ""
        #print("resuls {}".format(str)) #print(ip,str) when multithreaded db ripedb2.nic.cz returned empty plac#
    


### XXX BELOW ARE OLD METHODS

    bCount = 0 # count of queries that used limited flag B

    # XXX OLD PARAMS OF _EXEC!
    # We query whoisu with -B flag (it's use is limited to cca 1500 / day)
    # returns mail OR "" (if mail not available)
    def queryMailForced(query):
        Whois.bCount += 1 # we use additional B-flag
        self.abuseMail = Whois._exec("whois -B -- " + query, grep = 'e-mail', lastWord = True)

        # XXX: Koukat se i na radek '%  Abuse ...'.
        #  starsi: XX tady bych mohl vystup whois -B ulozit a zkouset greppovat radek Abuse contact for, stejne jako se dela v queryMail. Netusim, proc se to nedeje, bud jsem to z puvodnich skriptu spatne opsaal, nebo tenkrat radek Abuse contact jeste moc neexistoval.
        #cmd = "whois -B -- " + query + " | strings | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        #self.abuseMail = Whois._exec(cmd)

        if self.abuseMail == "":
            self.abuseMail = "unknown"
        return self.abuseMail, False # False means we used queryMailForced method, we didn't spare flag -B

    # XXX OLD PARAMS OF _EXEC!
    def getAsn(ip):
        #cmd = ip + " | strings | grep ^[o,O]rigin | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        #asn = Whois._exec("whois -h ripedb.nic.cz -- " + cmd) # zeptat se rychleho whois-mirroru cz.nic
        #return asn
        return Whois._exec("whois -h ripedb.nic.cz -- " + ip, grep = "^[o,O]rigin", lastWord = True)
