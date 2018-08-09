"""
    Source file caching - load, save
"""
import ntpath
import os
from bdb import BdbQuit

import jsonpickle

from .config import Config
from .sourceParser import SourceParser

__author__ = "Edvard Rejthar"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


class SourceWrapper:
    def __init__(self, file, fresh=False):
        self.file = file
        info = os.stat(self.file)
        self.hash = str(
            hash(info.st_size + round(info.st_mtime)))  # Why round: during file copying we may cut mikrosecond part behind mantisa.

        # MailDraft.setHash(self.hash)
        # MailDraft.setDir(os.path.dirname(file) + "/")

        # cache-file s metadaty zdrojoveho souboru
        Config.set_cache_dir(os.path.dirname(file) + "/" + ntpath.basename(self.file) + "_convey" + self.hash + "/")
        self.cacheFile = Config.get_cache_dir() + ntpath.basename(self.file) + ".cache"  # "cache/" +
        if os.path.isfile(self.cacheFile) and not fresh:
            print("File {} has already been processed.".format(self.file))
            # import pdb;pdb.set_trace()
            try:  # try to depickle
                self.csv = jsonpickle.decode(open(self.cacheFile, "r").read(), keys=True)
                if hasattr(self.csv, "ranges") and type(next(iter(self.csv.ranges.values()))[0]) is jsonpickle.unpickler._IDProxy:
                    # this is wrongly depickled: instead of {IPNetwork('...'): (IPNetwork('...'),
                    # we see {IPNetwork('...'): (<jsonpickle.unpickler._IDProxy object at 0x...>,
                    for prefix, o in self.csv.ranges.items():
                        l = list(o)
                        l[0] = prefix
                        self.csv.ranges[prefix] = tuple(l)
            except:
                import traceback
                print(traceback.format_exc())
                print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                input()
                if Config.is_debug():
                    ipdb.set_trace()
                self._treat()
            if self.csv:
                try:
                    if self.csv.is_analyzed:
                        self.csv.informer.sout_info()
                    elif self.csv.is_formatted:
                        self.csv.informer.sout_info()
                        s = "It seems the file has already been formatted."  # X Continue to analysis (or you'll be asked to do format again)?"
                        print(s)
                        # if Dialogue.isYes(s):
                        #    self.csv.run_analysis()
                        # else:
                        #    self._treat()
                except BdbQuit:  # we do not want to catch quit() signal from ipdb
                    print("Stopping.")
                    quit()
                except Exception as e:
                    # ipdb.set_trace()
                    print(e)
                    print(
                        "Format of the file may have changed since last time. Let's process it all again. If you continue, cache gets deleted.")
                    self._treat()
            else:
                self._treat()  # process file
        else:
            if not os.path.exists(Config.get_cache_dir()):
                os.makedirs(Config.get_cache_dir())
            self._treat()  # process file

    ##
    # Store
    def save(self):
        string = jsonpickle.encode(self.csv, keys=True)
        try:
            jsonpickle.decode(string, keys=True)
        except Exception:
            print("The program state is not picklable by 'jsonpickle' module. "
                  "Continuing will provide a file that will have to be reanalysed. "
                  "You may post this as a bug to the project issue tracker.")
            input("Continue...")
        with open(self.cacheFile, "w") as output:  # save cache
            output.write(string)

    def _treat(self):  # process source
        self.csv = SourceParser(self.file)
        # self.save()
        # self.csv.run_analysis()
        self.csv.cookie = Config.get("cookie", "OTRS")
        self.csv.token = Config.get("token", "OTRS")
        self.save()

    def clear(self):  # clear mezivysledky and processes file again
        self._treat()
