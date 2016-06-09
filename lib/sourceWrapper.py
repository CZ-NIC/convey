# Source file caching
from lib.mailDraft import MailDraft
from lib.sourceParser import SourceParser
from lib.dialogue import Dialogue
import os
import jsonpickle
from bdb import BdbQuit
#import pickle
#import yaml
    # from yaml import load, dump
#try:
#    from yaml import CLoader as Loader, CDumper as Dumper
#except ImportError:
#    from yaml import Loader, Dumper
import sys
import ntpath
import webbrowser
from lib.config import Config
import ipdb

__author__ = "edvard"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


class SourceWrapper:
    def __init__(self, file):
        self.file = file
        info = os.stat(self.file)
        self.hash = str(hash(info.st_size + round(info.st_mtime))) # Why round: during file copying we may cut mikrosecond part behind mantisa.

        #MailDraft.setHash(self.hash)
        #MailDraft.setDir(os.path.dirname(file) + "/")

        # cache-file s metadaty zdrojoveho souboru
        Config.setCacheDir(os.path.dirname(file) + "/" + ntpath.basename(self.file) + self.hash + "/")
        self.cacheFile = Config.getCacheDir() + ntpath.basename(self.file) + ".cache" #"cache/" +
        
        if os.path.isfile(self.cacheFile):
            print("File {} has already been processed.".format(self.file))
            #import pdb;pdb.set_trace()
            try: # try to depickle
                #self.csv = pickle.load(open(self.cacheFile, "rb"))
                self.csv = jsonpickle.decode(open(self.cacheFile, "r").read(), keys = True)
            except:
                #try: # maybe yaml was used for caching
                #    with open(self.cacheFile, 'r') as f:
                #        print("Loading slow yaml format...")
                #        self.csv = yaml.load(f.read(), Loader=Loader)
                #except Exception as e:
                #    print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                #    self._treat()
                print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                ipdb.set_trace()
                self._treat()
            if self.csv:
                try:
                    if self.csv.isAnalyzed():
                        self.csv.soutInfo()
                    elif self.csv.isFormatted():
                        self.csv.soutInfo()
                        s = "It seems the file has been formatted. Continue to analysis (or you'll be asked to do format again)?"
                        if Dialogue.isYes(s):
                            self.csv.runAnalysis()
                        else:
                            self._treat()
                except BdbQuit: # we do not want to catch quit() signal from ipdb
                    print("Stopping.")
                    quit()
                except Exception as e:
                    #ipdb.set_trace()
                    print(e)
                    print("Format of the file may have changed since last time. Let's process it all again. If you continue, cache gets deleted.")                    
                    self._treat()
            else:
                self._treat() # process file
        else:
            if not os.path.exists(Config.getCacheDir()):
                os.makedirs(Config.getCacheDir())
            self._treat() # process file
    
    ##
    # Store in YAML or pickle.
    def save(self):        
        with open(self.cacheFile, "w") as output: #save cache
            output.write(jsonpickle.encode(self.csv, keys = True))

    def _treat(self): # process source        
        self.csv = SourceParser(self.file)
        self.save()
        self.csv.runAnalysis()
        self.csv.cookie = Config.get("cookie","OTRS")
        self.csv.token = Config.get("token","OTRS")
        self.save()
        
        
    def clear(self): # clear mezivysledky and processes file again
        self._treat()