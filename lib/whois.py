# Prace s Whoisem
from subprocess import PIPE
from subprocess import Popen
import sys


__author__ = "edvard"
__date__ = "$Mar 24, 2015 6:08:16 PM$"

class Whois:

    ipDict = {} # set pritomnych IP adres [ip] = object

    def __init__(self, ip):
        self.ip = ip #
        pass


    def queryCountry(query):
        cmd = "whois -h ripedb2.nic.cz -- " + query + " | grep ^[c,C]ountry | head -1 | cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        country = Whois._whois(cmd)



        if country == "":
            country = "unknown"
        return country

    def _whois(cmd):
        sys.stdout.write('.') # at uzivatel vidi, ze se neco deje - (mozna nebude vypadat dobre)
        sys.stdout.flush() # XXX tohle zkusit zakomentovat, jestli se preci jen neco vypise...
        p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        str = p.stdout.read()
        #print(ip,str) pri multithreadingu db ripedb2.nic.cz vracela prazdne misto
        return str.decode("utf-8").strip().lower().replace("\n", " ")

    # Vrati abusemail pro query (ip ci asn).
    # Pokud je force = True a mail neni k dispozici, zkusi pouzit jeste druhy request s flagem B.
    # Pokud neni abusemail nalezen, vraci "".
    def queryMail(query, force = False):
        cmd = "whois -- " + query + " | grep '\% Abuse contact for' | grep -E -o '\b[a-zA-Z0-9.-] + @[a-zA-Z0-9.-] + \.[a-zA-Z0-9.-] + \b' || whois -- " + query + " | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        abuseMail = Whois._whois(cmd)
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
        abuseMail = Whois._whois(cmd)
        if abuseMail == "":
            abuseMail = "unknown"
        return abuseMail, False # False znamena, ze jsme pouzili metodu queryMailForced, neusetrili jsme flag -B
