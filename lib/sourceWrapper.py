# Cachuje zdrojove soubory
from lib.sourceParser import SourceParser
import os
import pickle
import sys
import ntpath

__author__ = "edvard"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


class SourceWrapper:
    def __init__(self, file):
        self.file = file
        info = os.stat(self.file)
        self.cacheFile = "cache/" + ntpath.basename(self.file) + str(hash(info.st_size + info.st_mtime)) + ".tmp"

        if os.path.isfile(self.cacheFile):
            print("Soubor {} již byl zpracován.".format(self.file))
            self.csv = pickle.load( open( self.cacheFile, "rb" ) )
            self.csv.soutInfo()
        else:
            self.__treat() #zpracuje soubor

    def __treat(self): # zpracuje zdroj
        self.csv = SourceParser(self.file)
        with open( self.cacheFile, "wb" ) as output: #ulozit cache
            pickle.dump(self.csv,output,-1)
        
    def clear(self): #smaze mezivysledky a zpracuje soubor znovu
        self.__treat()