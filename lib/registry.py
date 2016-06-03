from lib.config import Config
from lib.mailDraft import MailDraft
from collections import defaultdict
import os
import csv
import re
import pdb, ipdb

class _RegistryRecord(set):
    def __init__(self):
        """
        :param:mail If record is not mail, it's stored here.
        mail = None = no mail specified (take a look to the name of the record)
        mail = False = we have no mail available
        mail = mail@example.com
        """
        self.cc = ""
        self.mail = None
        self.counter = set()

class _Registry:
    
    def __init__(self):
        self._missing = {"records": 0, "ips": 0}
        self.records = defaultdict(_RegistryRecord)
        self.unknowns = set()
        self.knowns = set()
        self.total = 0
        self.mailDraft = MailDraft(self.name)

    def count(self, record, ip):
        """ Add IPs to this record and returns if it existed before. """
        existed = record in self.records
        if record and record is not "unknown":
            self.records[record].counter.add(ip)
            self.knowns.add(ip)
        else:
            self.unknowns.add(ip)
        return existed


    def getMails(self):
        for key, val in self.records.items():
            if val.mail is None:
                yield key
            elif val.mail is False:
                continue
            else:
                return val.mail

    def soutInfo(self):
        #print (', '.join(key + " ( " + value + ")") for key, value in itertools.chain(self.counters["foreign"],self.counters["local"]))
        l = []
        if len(self.records) < 100:
            for key, o in self.records.items():
                s = [str(len(o.counter))]
                o.mail is False and s.append("no mail")
                o.cc and s.append("cc " + o.cc)
                l.append(key + " (" + ", ".join(s) + ")")
        else:# too much of results, print just the count
            l.append(str(len(self.records)) + " " + self.name)
        if self.unknowns:
            l.append("unknown {} ({})".format(self.name, len(self.unknowns)))
        print(", ".join(l))

    def stat(self, kind, found):
        """
        :param:kind "records"|"ips"
        :param:found Bool. Returns count of found or not found objects.
        """
        if kind == "ips" and found == "both":
            return len(self.knowns) + len(self.unknowns)
        elif kind == "records" and found == "both":
            return len(self.records) + int(bool(self.unknowns))
        elif kind == "ips" and found:
            return len(self.knowns) - self._missing["ips"]
        elif kind == "records" and found:
            return len(self.records) - self._missing["records"]
        elif kind == "ips" and not found:
            return len(self.unknowns) + self._missing["ips"]
        elif kind == "records" and not found: # unknown country, unknown csirtmail or unknown abusemail for cz
            return int(bool(self.unknowns)) + self._missing["records"]
        else:
            ipdb.set_trace()
            raise Error("Statistics key error. Tell the programmer.")

    def _update(self, key):
        file = Config.get(key)
        if os.path.isfile(file) == False: # file with contacts
            print("(Contacts file {} not found on path {}.) ".format(key, file))
            return False
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                rows = {rows[0]:rows[1] for rows in reader}
                return rows


class AbusemailsRegistry(_Registry):

    name = "abusemails"

    ##
    # mail = mail@example.com;mail2@example2.com -> [example.com, example2.com]
    def getDomains(mail):
        try:
            #return set(re.findall("@([\w.]+)", mail))
            return set([x[0] for x in re.findall("@(([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6})", mail)])
        except AttributeError:
            return []

    def update(self):
        """ Refreshes Cc of the mails in the results """
        count = 0
        abusemails = self._update("contacts_local")
        if abusemails:
            for mail, record in self.records.items(): #check domain mail
                record.cc = ""
                for domain in AbusemailsRegistry.getDomains(mail):
                    if domain in abusemails:
                        record.cc += abusemails[domain] + ";"
                        count += 1

            if count:
                print("Included {} cc contacts into local mails.".format(count))
            else:
                print("No intersection with local cc contacts, ok.")

class CountriesRegistry(_Registry):

    name = "csirtmails"

    def update(self):
        """ Search for country contact – from CSV file Config.get("contacts") """
        self._missing = {"records": 0, "ips": 0}
        missingCountries = set()
        csirtmails = self._update("contacts_foreign")
        if csirtmails:
            for country, record in self.records.items(): #check domain mail
                record.mail = False
                if country in csirtmails:
                    record.mail = csirtmails[country]
                else:
                    missingCountries.add(country)
                    self._missing["records"] += 1
                    self._missing["ips"] += len(record.counter)

            if self._missing["records"]:
                print("Missing csirtmails for {} countries: {}".format(self._missing["records"], ", ".join(missingCountries)))
                print("Add csirtmails to the foreign contacts file (see config.ini) and relaunch whois! \n")
            else:
                print("Foreign whois OK!")

#"""
#class Registries:
#     Public access to both local and foreign registries
#    local = AbusemailsRegistry()
#    foreign = CountriesRegistry()"""
#"""