# Cachuje zdrojove soubory
from lib.sourceParser import SourceParser
from lib.mailList import MailList
import os
import pickle
import sys
import ntpath
import webbrowser

__author__ = "edvard"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


class SourceWrapper:
    def __init__(self, file):
        self.file = file
        info = os.stat(self.file)
        self.hash = str(hash(info.st_size + info.st_mtime))

        MailList.setHash(self.hash)
        MailList.setDir(os.path.dirname(file) + "/")

        # cache-file s metadaty zdrojoveho souboru
        self.cacheFile = os.path.dirname(file) +"/"+ ntpath.basename(self.file) + self.hash + ".tmp" #"cache/" +        
        if os.path.isfile(self.cacheFile):
            print("Soubor {} již byl zpracován.".format(self.file))            
            self.csv = pickle.load( open( self.cacheFile, "rb" ) )
            self.csv.soutInfo()
        else:
            self._treat() #zpracuje soubor

    def save(self):
        with open( self.cacheFile, "wb" ) as output: #ulozit cache
            pickle.dump(self.csv,output,-1)

    def _treat(self): # zpracuje zdroj 
        self.csv = SourceParser(self.file)
        self.save()
        
        
    def clear(self): #smaze mezivysledky a zpracuje soubor znovu
        self._treat()