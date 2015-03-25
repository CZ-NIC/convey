# Prace s Whoisem

__author__ = "edvard"
__date__ = "$Mar 24, 2015 6:08:16 PM$"

class Whois:

    ipDict = {} # set pritomnych IP adres [ip] = object

    def __init__(self, ip):
        self.ip = ip #
        pass


    def queryCountry(query):
        cmd = "whois -h ripedb2.nic.cz -- " + query + " | grep country |cut -d: -f2 | sed 's/^ *//;s/ *$//'"
        country = Whois._whois(cmd)
        if country == "":
            country = "unknown"
        return country

    def _whois(cmd):
        p = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        str = p.stdout.read()
        #print(ip,str) pri multithreadingu db ripedb2.nic.cz vracela prazdne misto
        return str.decode("utf-8").strip().lower().replace("\n", " ")

    def queryMail(query, force = False):
        cmd = "whois -- " + query + " | grep '\ % Abuse contact for' | grep -E -o '\b[a-zA-Z0-9.-] + @[a-zA-Z0-9.-] + \.[a-zA-Z0-9.-] + \b' || whois -- $line | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        abuseMail = Whois._whois(cmd)
        if abuseMail == "":
            if force == False:
                return False # radeji nechceme pouzit flag
            else:
                return Whois.queryMailForced(query) # pouzi flag B
        else:
            return abuseMail, True # True znamena, ze jsme mail nasli napoprve, usetrili jsme flag -B

    #tazeme se whoisu s omezenym -B flagem
    def queryMailForced(query):
        cmd = "whois -B -- " + query + " | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g'"
        abuseMail = Whois._whois(cmd)
        return abuseMail, False # False znamena, ze jsme pouzili metodu queryMailForced, neusetrili jsme flag -B

    pass
