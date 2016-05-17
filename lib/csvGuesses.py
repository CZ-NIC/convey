from lib.dialogue import Dialogue

class CsvGuesses:
    def getSample(sourceFile):
        sample = ""
        with open(sourceFile, 'r') as csvfile:        
            for i, row in enumerate(csvfile):
                if(i == 0):
                    firstLine = row
                sample += row
                if(i == 8): #sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                    break
        return firstLine, sample
        #csvfile.seek(0)
        #csvfile.close()


    def guessDelimiter(sniffer, sample):
        try:
            delimiter = sniffer.sniff(sample).delimiter
            hasHeader = sniffer.has_header(sample)
        except csv.Error: # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            hasHeader = False # lets just guess the value
            s = sample.split("\n")[1] # we dont take header (there is no empty column for sure)
            for dl in (",", ";", "|"): # lets suppose the double sign is delimiter
                if s.find(dl + dl) > -1:
                    delimiter = dl
                    break        
        return delimiter, hasHeader

    def guessCol(o, colName, checkFn, names):
        """
        :param o current object of SourceParser
        :param colName "ASN" or "IP"
        :param checkFn auto-checker function so that it knows it guessed right
        :param names - possible IP column names – no space
        """
        if o.isRepeating == False: # dialog goes for first time -> autodetect
            found = False            
            for colI, fieldname in enumerate(o.fields):
                field = fieldname.replace(" ", "").replace("'", "").replace('"', "").lower()
                if o.hasHeader == True: # file has header, crawl it
                    if field in names: # this may be IP column name
                        found = True
                else: # CSV dont have header -> pgrep IP, or ask user
                    if checkFn(field): # no IP -> error. May want all different shortened version of IP (notably IPv6).
                        found = True
                        break
            if found == True:                
                found = Dialogue.isYes("Is " + colName + " field column: {}?".format(fieldname.strip()))            
        else:
            found = False

        if found == False: # col not found automatically -> ask user
            print("What is " + colName + " column:\n[0]. no " + colName + " column")
            for i2, fieldname in enumerate(o.fields):# print columns
                print(str(i2+1) + ". " + fieldname)
            colI = Dialogue.askNumber(colName + " column: ") - 1

        return colI