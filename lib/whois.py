# Prace s Whoisem
import ipaddress
import json
import re
import socket
from subprocess import PIPE
from subprocess import Popen
import sys
from urllib.parse import urlparse
import urllib.request


__author__ = "edvard"
__date__ = "$Mar 24, 2015 6:08:16 PM$"

class Whois:

    ipDict = {} # set pritomnych IP adres [ip] = object

    def __init__(self, ip):
        self.ip = ip #
        pass

    def url2ip(url):
        """ Oseká URL na doménu, zjistí list ip, které jí odpovídají. """
        recs = socket.getaddrinfo(urlparse(url.strip()).hostname, 0, 0, 0, socket.IPPROTO_TCP)
        result = []
        for ip in recs:
            result.append(ip[4][0])
        return result
        # X socket.gethostbyname vraci jen 1 adresu, my chcem vsechny



    def checkIp(ip):
        """ True, pokud je ip dobre formovana IPv4 nebo IPv6 """
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def queryCountry(query):
        #cmd = query + " | strings | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        def getCountry(cmd):
            return Whois._exec(cmd, grep = '(.*)[c,C]ountry(.*)', lastWord = true)

        
        country = getCountry("whois -h ripedb.nic.cz -- " + query) # zeptat se rychleho whois-mirroru cz.nic

        # osetrit pripad, kdy whois selhal
        if country[0:2].lower() == "eu": #ex: 'EU # Country is really world wide' (64.9.241.202)
            country = getCountry("whois " + query) # zeptame se whois celosvětově, nikoli cz.nic-mirroru

        # osetrit pripad, kdy je vice zemi na jednom radku
        if len(country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
            country = country.split("#")[0].strip(" ")

        #v pripade 10_16_Honeypot se nam stalo, ze se whois ptal kdovi ceho. Prestoze si myslime, ze se pta ripe ARINu, nevypadalo to.
        if country == "":
            country = getCountry("whois -h whois.arin.net " + query) # myslim, ze ripe se ptat nemusim, protoze ARIN na nej primo odkazuje (whois -h whois.arin.net 109.123.209.188 mi proste vratilo i vysledek RIPE)
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
        return Whois._exec("whois -h ripedb.nic.cz -- " + ip, grep = "^[o,O]rigin", lastWord = true)
        

    _cache = {}

    def _exec(cmd, grep = "", lastWord = false):
        """
        # grep - returns grep for line
        # lastWord - returns only last word of grepped line
        """
        if cmd not in self._cache:
            #debug: print("exec: {}".format(cmd))
            sys.stdout.write('.') # at uzivatel vidi, ze se neco deje - (mozna nebude vypadat dobre)
            sys.stdout.flush() # XX: tohle zkusit zakomentovat, jestli se preci jen neco vypise...
            p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            s = p.stdout.read().decode("utf-8").strip().lower().replace("\n", " ")
            #print("vysledek {}".format(str)) #print(ip,str) pri multithreadingu db ripedb2.nic.cz vracela prazdne misto
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

    # Vrati abusemail pro query (ip ci asn).
    # Pokud je force = True a mail neni k dispozici, zkusi pouzit jeste druhy request s flagem B.
    # Pokud neni abusemail nalezen, vraci "".
    def queryMail(query, force=False):
        #cmd = "whois -- " + query + " | strings | grep '\\% Abuse contact for' | grep -E -o '\\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z0-9.-]+\\b' || whois -- " + query + " | strings | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\\s*//' -e 's/\\s*$//' | sort -nr | uniq | tr '\\n' ',' | sed -e 's/,$//' -e 's/,/\\,/g'"
        #abuseMail = Whois._exec(cmd)
        
        text = Whois._exec("whois -- " + query, grep = '% abuse contact for')
        abuseMail = re.search('[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}', text)

        if abuseMail == "":
            abuseMail = Whois._exec("whois -- " + query, grep = 'abuse-mailbox', lastWord = true)

        # XXX #6
        #if abuseMail == "": # slower method, without limits
        #    url = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=" + query
        #    jsonp = urllib.request.urlopen(url).read().decode("utf-8").replace("\n", "")
        #    response = json.loads(jsonp)
        #    if response["status"] == "ok":
        #        #data
        #        #holder_info resource (prefix)
        #        #authorities: ripe
        #        #anti_abuse_contacts->abuse_c->email
        #        pass


        if abuseMail == "":
            if force == False:
                return "unknown", False # radeji nechceme pouzit flag
            else:
                return Whois.queryMailForced(query) # pouzi flag B
        else:
            return abuseMail, True # True znamena, ze jsme mail nasli napoprve, usetrili jsme flag -B

    bCount = 0 # pocet dotazu, u nichz jsme se whoisu ptali s limitovanym flagem B

    # Tazeme se whoisu s -B flagem (jehoz pouziti je limitovano na cca 1500 / den)
    # return mail, nebo "" (pokud mail neni k dispozici)
    def queryMailForced(query):
        Whois.bCount += 1 # pouzivame dalsi B-flag
        abuseMail = Whois._exec("whois -B -- " + query, grep = 'e-mail', lastWord = true)

        # XXX: Koukat se i na radek '%  Abuse ...'.
        #  starsi: XX tady bych mohl vystup whois -B ulozit a zkouset greppovat radek Abuse contact for, stejne jako se dela v queryMail. Netusim, proc se to nedeje, bud jsem to z puvodnich skriptu spatne opsaal, nebo tenkrat radek Abuse contact jeste moc neexistoval.
        #cmd = "whois -B -- " + query + " | strings | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        #abuseMail = Whois._exec(cmd)

        if abuseMail == "":
            abuseMail = "unknown"
        return abuseMail, False # False znamena, ze jsme pouzili metodu queryMailForced, neusetrili jsme flag -B
