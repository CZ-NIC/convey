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