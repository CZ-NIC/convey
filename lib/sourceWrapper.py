# Source file caching
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
        self.hash = str(hash(info.st_size + round(info.st_mtime))) # Why round: during file copying we may cut mikrosecond part behind mantisa.

        #MailList.setHash(self.hash)
        #MailList.setDir(os.path.dirname(file) + "/")

        # cache-file s metadaty zdrojoveho souboru
        Config.setCacheDir(os.path.dirname(file) +"/"+ ntpath.basename(self.file) + self.hash + "/")
        self.cacheFile = Config.getCacheDir() + ntpath.basename(self.file) + ".cache" #"cache/" +
        if os.path.isfile(self.cacheFile):
            print("File {} has been already processed.".format(self.file))
            try: # try to depickle
                self.csv = pickle.load( open( self.cacheFile, "rb" ) )
            except:
                try: # maybe yaml was used for caching
                    with open(self.cacheFile, 'r') as f:
                        print("Loading slow yaml format...")
                        self.csv = yaml.load(f.read(), Loader=Loader)
                except:
                    print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                    self._treat()
            self.csv.soutInfo()
        else:
            if not os.path.exists(Config.getCacheDir()):
                os.makedirs(Config.getCacheDir())
            self._treat() # process file
    
    ##
    # Store in YAML or pickle.
    def save(self):
        if Config.getboolean("yaml_cache"):
            with open( self.cacheFile, "w" ) as output: #save cache
                print("Saving in slow yaml format...")
                output.write(yaml.dump(self.csv, Dumper=Dumper))
        else:
            with open( self.cacheFile, "wb" ) as output: #save cache
                pickle.dump(self.csv,output,-1)
        

    def _treat(self): # process source
        self.csv = SourceParser(self.file)
        self.csv.cookie = Config.get("cookie")
        self.csv.token = Config.get("token")
        self.save()
        
        
    def clear(self): # clear mezivysledky and processes file again
        self._treat()