# Prace s Whoisem
from subprocess import PIPE
from subprocess import Popen
from urllib.parse import urlparse
import ipaddress
import socket
import sys


__author__ = "edvard"
__date__ = "$Mar 24, 2015 6:08:16 PM$"

class Whois:

    ipDict = {} # set pritomnych IP adres [ip] = object

    def __init__(self, ip):
        self.ip = ip #
        pass

    def url2ip(url):
        """ Oseká URL na doménu, zjistí list ip, které jí odpovídají. """
        recs = socket.getaddrinfo(urlparse(url.strip()).hostname,0,0,0,socket.IPPROTO_TCP)
        result = []
        for ip in recs:
            result.append(ip[4][0])
        return result
        # X socket.gethostbyname vraci jen 1 adresu, my chcem vsechny



    def checkIp(ip):
        """ True, pokud je ip dobře formovaná IPv4 nebo IPv6 """
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def queryCountry(query):
        cmd = query + " | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        country = Whois._exec("whois -h ripedb2.nic.cz -- " + cmd) # zeptat se rychleho whois-mirroru cz.nic

        # osetrit pripad, kdy whois selhal
        if country[0:2].lower() == "eu": #ex: 'EU # Country is really world wide' (64.9.241.202)
            country = Whois._exec("whois " + cmd) # zeptame se whois celosvětově, nikoli cz.nic-mirroru

        # osetrit pripad, kdy je vice zemi na jednom radku
        if len(country.split("#")) > 1: # ex: 'NL # BE GB DE LU' -> 'NL' (82.175.175.231)
            country = country.split("#")[0].strip(" ")


        if country == "":
            country = "unknown"
        return country

    def getAsn(ip):
        cmd = ip + " | grep ^[o,O]rigin | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        asn = Whois._exec("whois -h ripedb2.nic.cz -- " + cmd) # zeptat se rychleho whois-mirroru cz.nic
        return asn


    def _exec(cmd):
        #debug: print("exec: {}".format(cmd))
        sys.stdout.write('.') # at uzivatel vidi, ze se neco deje - (mozna nebude vypadat dobre)
        sys.stdout.flush() # XX: tohle zkusit zakomentovat, jestli se preci jen neco vypise...
        p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        str = p.stdout.read()
        #print("vysledek {}".format(str))
        #print(ip,str) pri multithreadingu db ripedb2.nic.cz vracela prazdne misto
        return str.decode("utf-8").strip().lower().replace("\n", " ")

    # Vrati abusemail pro query (ip ci asn).
    # Pokud je force = True a mail neni k dispozici, zkusi pouzit jeste druhy request s flagem B.
    # Pokud neni abusemail nalezen, vraci "".
    def queryMail(query, force = False):
        cmd = "whois -- " + query + " | grep '\\% Abuse contact for' | grep -E -o '\\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z0-9.-]+\\b' || whois -- " + query + " | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\\s*//' -e 's/\\s*$//' | sort -nr | uniq | tr '\\n' ',' | sed -e 's/,$//' -e 's/,/\\,/g'"
        abuseMail = Whois._exec(cmd)
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
        cmd = "whois -B -- " + query + " | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        # XX tady bych mohl vystup whois -B ulozit a zkouset greppovat radek Abuse contact for, stejne jako se dela v queryMail. Netusim, proc se to nedeje, bud jsem to z puvodnich skriptu spatne opsaal, nebo tenkrat radek Abuse contact jeste moc neexistoval.
        abuseMail = Whois._exec(cmd)
        if abuseMail == "":
            abuseMail = "unknown"
        return abuseMail, False # False znamena, ze jsme pouzili metodu queryMailForced, neusetrili jsme flag -B
