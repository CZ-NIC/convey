# Cachuje zdrojove soubory
from lib.sourceParser import SourceParser
from lib.mailList import MailList
import os
import pickle
import yaml # from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import sys
import ntpath
import webbrowser
from lib.config import Config

__author__ = "edvard"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


class SourceWrapper:
    def __init__(self, file):
        self.file = file
        info = os.stat(self.file)
        self.hash = str(hash(info.st_size + round(info.st_mtime))) # Proc round: pri zkopirovani souboru se mozna odriznul mikrosekundovy kus za desetinnou carkou.

        #MailList.setHash(self.hash)
        #MailList.setDir(os.path.dirname(file) + "/")

        # cache-file s metadaty zdrojoveho souboru
        Config.setCacheDir(os.path.dirname(file) +"/"+ ntpath.basename(self.file) + self.hash + "/")
        self.cacheFile = Config.getCacheDir() + ntpath.basename(self.file) + ".cache" #"cache/" +
        if os.path.isfile(self.cacheFile):
            print("Soubor {} již byl zpracován.".format(self.file))
            try: # zkousime rozpicklovat
                self.csv = pickle.load( open( self.cacheFile, "rb" ) )
            except:
                try: # mozna byl pouzit pro caching yaml
                    with open(self.cacheFile, 'r') as f:
                        print("Loading slow yaml format...")
                        self.csv = yaml.load(f.read(), Loader=Loader)
                except:
                    print("Selhalo načtení cache souboru z minula, zpracujeme ho znovu. Pokud budete pokračovat, cache se přemaže.")
                    self._treat()
            self.csv.soutInfo()
        else:
            if not os.path.exists(Config.getCacheDir()):
                os.makedirs(Config.getCacheDir())
            self._treat() #zpracuje soubor
    
    ##
    # Ulozime v YAML nebo picklu.
    def save(self):
        if Config.getboolean("yaml_cache"):
            with open( self.cacheFile, "w" ) as output: #ulozit cache
                print("Saving in slow yaml format...")
                output.write(yaml.dump(self.csv, Dumper=Dumper))
        else:
            with open( self.cacheFile, "wb" ) as output: #ulozit cache
                pickle.dump(self.csv,output,-1)
        

    def _treat(self): # zpracuje zdroj 
        self.csv = SourceParser(self.file)
        self.csv.cookie = Config.get("cookie")
        self.csv.token = Config.get("token")
        self.save()
        
        
    def clear(self): #smaze mezivysledky a zpracuje soubor znovu
        self._treat()