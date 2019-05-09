"""
    Source file caching - load, save
"""
import ntpath
import os
import sys
from bdb import BdbQuit
from os.path import join

import ipdb
import jsonpickle

from .config import Config
from .dialogue import is_yes
from .sourceParser import SourceParser

__author__ = "Edvard Rejthar"
__date__ = "$Mar 23, 2015 8:33:24 PM$"


def choose_file():
    print("Set path to the source log file.")
    print("? ", end="")

    # XX in the future, let's get rid of Tkinter. And don't impose it now if not really needed
    try:
        import tkinter as tk
        from tkinter.filedialog import askopenfilename
        root = tk.Tk()
        root.withdraw()  # show askopenfilename dialog without the Tkinter window
        file = askopenfilename()  # default is all file types
        print(file)
        return file
    except ImportError:
        print("Error importing Tkinter. Please specify the file name in the parameter.")
        return None


def read_stdin():
    print("Write something to stdin. (End of transmission 3× <Ctrl>+d or <Enter>+<Ctrl>+d.)")
    return sys.stdin.readlines()


class SourceWrapper:
    def __init__(self, file_or_input, force_file=False, force_input=False, fresh=False):
        self.file = file = None
        self.stdin = stdin = None
        try:
            case = int(Config.get("file_or_input"))
        except ValueError:
            case = 0

        if case == 5:
            force_file = True
        elif case == 6:
            force_input = True

        if force_input:
            stdin = file_or_input.split("\n") if file_or_input else read_stdin()
        elif force_file:
            file = file_or_input if file_or_input else choose_file()
        elif file_or_input and os.path.isfile(file_or_input):
            file = file_or_input
        elif file_or_input:
            stdin = file_or_input.split("\n")
        elif not sys.stdin.isatty():  # we're already receiving something through a pipe
            stdin = read_stdin()
        else:  # choosing the file or input text
            if case == 0:
                case = int(is_yes("Do you want to input text (otherwise you'll be asked to choose a file name)?"))
            if case == 1:
                stdin = read_stdin()
            elif case == 2:
                file = choose_file()
            elif case == 3:
                stdin = read_stdin()
                if not stdin:
                    file = choose_file()
            elif case == 4:
                file = choose_file()
                if not file:
                    stdin = read_stdin()

        if not file and not stdin:
            print("No input. Program exit.")
            quit()
        elif stdin:
            self.stdin = stdin
            self.csv = SourceParser(stdin=stdin)
            self.cache_file = None
            Config.set_cache_dir(os.getcwd())
            return

        if not os.path.isfile(file):
            print(f"File '{file}' not found.")
            quit()

        self.file = os.path.abspath(file)
        info = os.stat(self.file)
        self.hash = str(
            hash(info.st_size + round(info.st_mtime)))  # why round: during file copying we may cut microsecond part behind mantissa
        # cache-file with source file metadata
        Config.set_cache_dir(join(os.path.dirname(self.file), ntpath.basename(self.file) + "_convey" + self.hash))
        self.cache_file = join(Config.get_cache_dir(), ntpath.basename(self.file) + ".cache")  # "cache/" +
        if os.path.isfile(self.cache_file) and not fresh:
            print("File {} has already been processed.".format(self.file))
            # import pdb;pdb.set_trace()
            try:  # try to depickle
                self.csv = jsonpickle.decode(open(self.cache_file, "r").read(), keys=True)
                # correction of a wrongly pickling: instead of {IPNetwork('...'): (IPNetwork('...'),
                # we see {IPNetwork('...'): (<jsonpickle.unpickler._IDProxy object at 0x...>,
                # Note that IPRange is pickled correctly.
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
                self.csv = None
            if self.csv:
                if self.csv.source_file != self.file:  # file might have been moved to another location
                    self.csv.source_file = self.file
                try:
                    if self.csv.is_analyzed:
                        self.csv.informer.sout_info()
                    elif self.csv.is_formatted:
                        self.csv.informer.sout_info()
                        print("It seems the file has already been formatted.")
                    return
                except BdbQuit:  # we do not want to catch quit() signal from ipdb
                    print("Stopping.")
                    quit()
                except Exception as e:
                    print(e)
                    print("Format of the file may have changed since last time. "
                          "Let's process it all again. If you continue, cache gets deleted.")
        else:
            if not os.path.exists(Config.get_cache_dir()):
                os.makedirs(Config.get_cache_dir())
        self.clear()

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
        if self.cache_file:
            with open(self.cache_file, "w") as output:  # save cache
                output.write(string)

    def clear(self):
        self.csv = SourceParser(self.file, self.stdin)
        self.save()
