# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
### XXXXXXX TENTO SOUBOR VYKOTLAT XXXXXXXXX


for rngs in Whois._ranges: # weve already seen abuseMail in this range
			if query in rngs and Whois._ranges[rngs] != "":
				return Whois._ranges[rngs], True

		if not self.abuseMail:
			if force == False:
				return "unknown", False # we rather not use flag
			else:
				return Whois.queryMailForced(query) # use flag B
		else:
			if self.prefix: # stores IPRange for the next time, so we may be quicker
				Whois._addRange(prefix, ip = query, self.abuseMail = self.abuseMail)
			return self.abuseMail, True # True means we found mail at first try, we spared flag -B

	bCount = 0 # count of queries that used limited flag B
		pass

	##
	# s = "88.174.0.0 - 88.187.255.255"
	# ip Validity check only.
	def _addRange(s, self.abuseMail = None, ip = None):
		r = s.split(" - ")
		prefix = IPRange(r[0],r[1])
		Whois._ranges[prefix] = self.abuseMail
		if IPAddress(ip) not in prefix:
			raise Exception("Given IP " + ip + " is not in IPRange " + s + ". This should never happen. Tell the programmer, please.")
		return prefix


##
# Seek out abusemail contact for local IPs.
#
# Loads set of IPs with the same abusemail into self.mailLocal[mail].
# Set of IPs without abusemail goes to self.mailLocal[""].
# Depending to the config.ini (spare_b_flag, b_flag_threshold) it searches abusemails for every IP apart,
# or searches abusemails for ASN. This spares whois-flag B, that is limited to cca 1500 / day.
#
# XX I am ready (I think) with the possibility when different IPs from ASN goes under diffent countries.
#    If this happens, only local CZ IP logs will be sent to ASN abuse mail
#
def _buildListCz(self, ips):
    self.mailLocal.resetMails()
    print("Querying whois for mails.")
    if Config.getboolean('spare_b_flag') == False: # do not spare B flag (directly use queryMail force = True)
        # asks every IP for abusemail
        for ip in ips:
            mail, bSpared = Whois.queryMail(ip, True)
            self.mailLocal.mails[mail].add(ip) # add to local maillist
    else:  # try to spare B flag
        doAsn = False
        threshold = int(Config.get('b_flag_threshold'))
        if threshold == -1: # search for ASN abusemail, not IP (we spares)
            self._buildListCzByAsn(ips)
        else:
            # tries, how much -b request would be needed for individual IPs (queryMail force = false)
            ipsRedo = set() # IP where B flag is needed
            try:
                for ip in ips:
                    mail, bSpared = Whois.queryMail(ip, False)
                    #print("QUERY: " + ip)
                    #pdb.set_trace()
                    if mail and mail != "unknown": # mail not found, B flag not needed
                        self.mailLocal.mails[mail].add(ip)
                    if bSpared == False: # we would need B flag
                        ipsRedo.add(ip) # redo IP again
            except:
                pdb.set_trace()

            if len(ipsRedo) > threshold: # we would need more B flags than threshold
                # asks user if we use -B flags or ASN
                print(("Without B-flags we found {} of local abusemails. " +
                      "We need to find abusemails for {} IPs. " +
                      "(Threshold for using ASN is {} addresses.)").format(len(self.mailLocal.mails), len(ipsRedo), threshold))
                print("Do we use ASN and spare B-flags? y,[n]: ")
                doAsn = False if input().lower() in ("", "n") else True

            if doAsn == False: # do not spare B-flag
                for ip in ipsRedo:
                    mail = Whois.queryMailForced(ip)[0]
                    self.mailLocal.mails[mail].add(ip)
            else:# do spare B-flag and use ASN
                self._buildListCzByAsn(ipsRedo)


    # stats
    if Whois.bCount > 0:
        print("Whois -B flag used: {} times".format(str(Whois.bCount)))
    count = len(self.mailLocal.mails)
    orphL = len(self.mailLocal.getOrphans())
    if orphL:
        count -= 1
        print("Count of local IPs without abusemails: {}".format(orphL))
    else:
        print("Local whois OK!")
    print("Totally found {} abusemails. " .format(count))

## XXX tohle v nove verzi jeste treba neni!


# find out abuseMail for ASN
def _buildListCzByAsn(self, ips):
    if self.asnColumn == -1:
        print("Looking up AS numbers from whois")
        for ip in ips:
            self.ip2asn[ip] = Whois.getAsn(ip)
    else:
        print("Country CZ detected -> ASN usage.")


    # XXX ASN may be broken, it may return lot of unknowns
    asnSet = defaultdict(set)
    for ip in ips:
        asnSet[self.ip2asn[ip]].add(ip)
    for asn in asnSet:
        mail, forced = Whois.queryMailForced(asn) # XXX why directly forced?
        self.mailLocal.mails[mail].update(asnSet[asn]) # connect all IP of ASN to its mail
    print("ASN count: {}".format(len(asnSet)))



def missingFilesInfo(self):
    return "({} files, {} foreign and {} local contacts)".format(
                                                                 len(self.countriesMissing) + (1 if len(self.mailLocal.getOrphans()) else 0),
                                                                 len(self.countriesMissing),
                                                                 len(self.mailLocal.getOrphans()))


## Writes log files, divided by countries
# dir - directory without ending slash
def generateFiles(self, dir, missingOnly=False):
    if missingOnly:
        extension = "-missing.tmp"
        files = self.countriesMissing.copy()
        files["cz_unknown"] = self.mailLocal.getOrphans().copy() # local IP without abusemails will be in the 'cz' file
    else: #all files
        extension = ".tmp"
        files = self.countries.copy()
        files.update(self.mailLocal.mails.copy()) # CZ IP will be in files, divided by abusemails

    dir += "/"
    count = 0
    # write files from countries and abusemails
    for file in files:
        if len(files[file]) > 0: # if we have an IP for this country
            with open(dir + file + extension, 'w') as f:
                count += 1
                f.write(self.ips2logfile(files[file]))

    print("Generated {} files to directory {} .".format(count, dir))

def ips2logfile(self, ips):
    result = []
    if self.header != "": # include header to every file
        result.append(self.header)
    for ip in ips:
        for log in self.logs[ip]:
            result.append(log)
    return "\n".join(result)



    #write local files – by ASN
    #for asn in self.isp:
    #    with open(dir + asn, 'w') as f:
    #        count += 1
    #        if self.header != "":
    #            f.write(self.header + "\n")
    #        for ip in self.isp[asn]['ips']:
    #            for log in self.logs[ip]:
    #                f.write(log + "\n")

    print("Generated {} files.".format(count))

def soutDetails(self):
    print("**************************")
    print("Internal variables state:")
    print("\nLocal\n" + str(self.mailLocal))
    print("\nForeign\n" + str(self.mailForeign))
    print("\nMissing foreign mails\n" + str(self.countriesMissing) if len(self.countriesMissing) else "All foreign IP are OK linked.")

def __exit__(self):
    pass

