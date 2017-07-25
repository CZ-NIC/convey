from lib.informer import Informer
import datetime
from math import log, sqrt, ceil
import re

class Processer:
    """ Processes the csv lines.
        For every line, it contants whois and sends it to registry.
    """

    reIpWithPort = re.compile("((\d{1,3}\.){4})(\d+)")
    reAnyIp = re.compile("\"?((\d{1,3}\.){3}(\d{1,3}))")

    def __init__(self, csv):
        self.csv = csv

    def processFile(self, file, reprocessing=False):
        csv = self.csv
        with open(file, "r") as sourceF:
            for row in sourceF:
                 # skip blanks and header
                row = row.strip()
                if(row == ""):
                    continue
                csv.lineCount += 1
                if csv.lineCount == 1 and csv.hasHeader:
                    continue
                # display infopanel
                if csv.lineCount == csv.lineSout:
                    now = datetime.datetime.now()
                    delta = (now - csv.timeLast).total_seconds()
                    csv.timeLast = now
                    if delta < 1 or delta > 2:
                        newVel = ceil(csv.velocity / delta) +1
                        if abs(newVel - csv.velocity) > 100 and csv.velocity < newVel: # smaller accelerating of velocity (decelerating is alright)
                            csv.velocity += 100
                        else:
                            csv.velocity = newVel
                    csv.lineSout = csv.lineCount + 1 +csv.velocity
                    csv.informer.soutInfo()
                # process the line (IP, ASN, ...)
                try:
                    if False:
                        Processer.processLine(csv, row, reprocessing=reprocessing)
                    else: # XXX Varianta pro posilani CMS
                        csv.reg["local"].count(row, row.split(csv.delimiter)[csv.urlColumn])
                except Exception as e: # FileNotExist
                    print("ROW fault" + row)
                    print("This should not happen. CSV is wrong or tell programmer to repair this.")
                    Config.errorCatched()
                except KeyboardInterrupt:
                    print("CATCHED")
                    try:
                        print("{} line number, {} ip".format(csv.lineCount, ip))
                    except:
                        pass
                    o = Dialogue.ask("Catched keyboard interrupt. Options: continue (default, do the line again), [s]kip the line, [d]ebug, [q]uit: ")
                    if o == "d":
                        print("Maybe you should hit n multiple times because pdb takes you to the wrong scope.") # I dont know why.
                        import ipdb;ipdb.set_trace()
                    elif o == "s":
                        return # skip to the next line
                    elif o == "q":
                        quit()
                    else:  # continue from last row
                        csv.lineCount -= 1 # let's pretend we didnt just do this row before
                        return Processer.processLine(csv, row, reprocessing=reprocessing)


    def processLine(csv, row, reprocessing=False):
        """ Link every line to IP
            self.ranges[prefix] = mail, location (it is foreign; abuse@mail.com is local), asn, netname

            Arguments:
                row - current line
                reprocessing - True, if we just want to force abusemail fetching. The line has been processed before and prefix should be present.
        """
        ######
        # Row processing
        ######
        # obtain IP from the line. (Or more IPs, if theres url column).
        records = row.split(csv.delimiter)
        if not reprocessing and csv.urlColumn is not None: # if CSV has DOMAIN column that has to be translated to IP column
            ip = Whois.url2ip(records[csv.urlColumn])
            #if len(ips) > 1:
            #    self.extendCount += len(ips) -1 # count of new lines in logs
            #    print("Url {} has {} IP addresses: {}".format(records[self.urlColumn], len(ips), ips))
        else: # only one record
            try:
                ip = records[csv.ipColumn].strip() # key taken from IP column
            except IndexError:
                csv.invalidReg.count(row)
                return
            if not Whois.checkIp(ip):
                # format 1.2.3.4.port
                # XX maybe it would be a good idea to count it as invalidReg directly. In case of huge files. Would it be much quicker?
                # This is 2 times quicker than regulars (but regulars can be cached). if(ip.count(".") == 5): ip = ip[:ip.rfind(".")]
                #
                #print(ip)
                #import ipdb;ipdb.set_trace()
                print("ip:", ip) # XX
                m = Processer.reIpWithPort.match(ip)
                if m:
                    # 91.222.204.175.23 -> 91.222.204.175
                    ip = m.group(1).rstrip(".")
                else:
                    m = Processer.reAnyIp.match(ip)
                    if m:
                        # "91.222.204.175 93.171.205.34" -> "91.222.204.175", '"1.2.3.4"' -> 1.2.3.4
                        ip = m.group(1)
                    else:
                        #except AttributeError:
                        csv.invalidReg.count(row)
                        return

        #print(ip)
        #import ipdb;ipdb.set_trace()

        ######
        # PREFIX REMEMBERING
        ######
        if ip in csv.ipSeen:
            # ip has been seen in the past
            if csv.conveying == "unique_row" or csv.conveying == "unique_ip":
                return
            else:
                found = True
                prefix = csv.ipSeen[ip]
                mail, location, asn, netname = csv.ranges[prefix]
        else:
            found = False
            for prefix, o in csv.ranges.items(): # search for prefix the slow way. I dont know how to make this shorter because IP can be in shortened form so that in every case I had to put it in full form and then slowly compare strings with prefixes.
                if ip in prefix:
                    found = True
                    mail, location, asn, netname = o
                    csv.ipSeen[ip] = prefix
                    break
            if csv.conveying == "unique_row" and found:
                return

        ######
        # ASSURING THE EXISTENCE OF PREFIX (abusemail)
        ######
        if not reprocessing: # (in 'reprocessing unknown' mode, this was already done)
            if csv.urlColumn is not None:
                row += csv.delimiter + ip # append determined IP to the last col

            if found == False:
                prefix, location, mail, asn, netname = Whois(ip).analyze()
                csv.ipSeen[ip] = prefix
                if not prefix:
                    logging.info("No prefix found for IP {}".format(ip))
                elif prefix in csv.ranges:
                    # IP in ranges wasnt found and so that its prefix shouldnt be in ranges.
                    raise AssertionError("The prefix " + prefix + " shouldn't be already present. Tell the programmer")
                csv.ranges[prefix] = mail, location, asn, netname
                #print("IP: {}, Prefix: {}, Record: {}, Kind: {}".format(ip, prefix,record, location)) # XX put to logging

        else: # force to obtain abusemail
            if not found:
                raise AssertionError("The prefix for ip " + ip + " should be already present. Tell the programmer.")
            if mail == "unknown": # prefix is still unknown
                mail = Whois(ip).resolveUnknownMail()
                if mail != "unknown": # update prefix
                    csv.ranges[prefix] = mail, location, asn, netname
                else: # the row will be moved to unknown.local file again
                    print("No success for prefix {}.".format(prefix))

        ######
        # WRITE THE ROW TO THE APPROPRIATE FILE
        ######
        if csv.appendFields["asn"]:
            row += csv.delimiter + asn
        if csv.appendFields["netname"]:
            row += csv.delimiter + netname
        csv.reg[location].count(row, mail, ip, prefix)