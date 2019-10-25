"""
    Source file caching - load, save
"""
import re
import sys
from bdb import BdbQuit
from pathlib import Path

import jsonpickle

from .config import Config
from .dialogue import is_yes
from .identifier import Identifier
# from .informer import mute_info
from .parser import Parser

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
        print("Error importing Tkinter. Please specify the file name in the parameter or install `apt install python3-tk`.")
        return None


def read_stdin():
    print("Write something to stdin. (End of transmission 3× <Ctrl>+d or <Enter>+<Ctrl>+d.)")
    return sys.stdin.readlines()


class SourceWrapper:
    def __init__(self, file_or_input, force_file=False, force_input=False, fresh=False):
        self.parser: Parser
        self.file = file = None
        self.stdin = stdin = None
        try:
            case = int(Config.get("file_or_input"))
        except (ValueError, TypeError):
            case = 0

        if case == 5:
            force_file = True
        elif case == 6:
            force_input = True

        if force_input:
            stdin = file_or_input.split("\n") if file_or_input else read_stdin()
        elif force_file:
            file = file_or_input if file_or_input else choose_file()
        elif file_or_input and Path(file_or_input).is_file():
            file = file_or_input
        elif file_or_input:
            stdin = file_or_input.split("\n")
        elif not sys.stdin.isatty():  # we're already receiving something through a pipe
            stdin = read_stdin()
        else:  # choosing the file or input text
            if case == 0:
                case = 1 if is_yes("Do you want to input text (otherwise you'll be asked to choose a file name)?") else 2
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
            Config.set_cache_dir(Path.cwd())
            self.cache_file = None
            self.stdin = stdin
            self.parser: Parser = Parser(stdin=stdin)
            return

        if not Path(file).is_file():
            print(f"File '{file}' not found.")
            quit()

        self.file = Path(file).resolve()
        info = Path(self.file).stat()
        self.hash = str(hash(info.st_size + round(info.st_mtime)))
        # cache-file with source file metadata
        Config.set_cache_dir(Path(Path(self.file).parent, Path(self.file).name + "_convey" + self.hash))
        self.cache_file = Path(Config.get_cache_dir(), Path(self.file).name + ".cache")
        if Path(self.cache_file).is_file() and not fresh:
            print("File {} has already been processed.".format(self.file))
            try:  # try to depickle
                self.parser = jsonpickle.decode(open(self.cache_file, "r").read(), keys=True)
                self.parser.refresh()
                self.parser.reset_whois(assure_init=True)
                # correction of a wrongly pickling: instead of {IPNetwork('...'): (IPNetwork('...'),
                # we see {IPNetwork('...'): (<jsonpickle.unpickler._IDProxy object at 0x...>,
                # Note that IPRange is pickled correctly.
                for prefix, o in self.parser.ranges.items():
                    l = list(o)
                    l[0] = prefix
                    self.parser.ranges[prefix] = tuple(l)
            except:
                import traceback
                print(traceback.format_exc())
                Config.error_caught()
                print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                input()
                self.parser = None
            if self.parser:
                if self.parser.source_file != self.file:  # file might have been moved to another location
                    self.parser.source_file = self.file
                try:
                    if self.parser.is_analyzed:
                        self.parser.informer.sout_info()
                    elif self.parser.is_formatted:
                        self.parser.informer.sout_info()
                        print("It seems the file has already been formatted.")
                    return
                except BdbQuit:  # we do not want to catch quit() signal from ipdb
                    print("Stopping.")
                    quit()
                except Exception as e:
                    print(e)
                    print("Format of the file may have changed since last time. "
                          "Let's process it all again. If you continue, cache gets deleted.")
                    Config.error_caught()
        else:
            if not Path(Config.get_cache_dir()).exists():
                Path(Config.get_cache_dir()).mkdir()
        self.clear()

    ##
    # Store
    def save(self):
        string = jsonpickle.encode(self.parser, keys=True)
        try:
            jsonpickle.decode(string, keys=True)
        except Exception:
            print("The program state is not picklable by 'jsonpickle' module. "
                  "Continuing will provide a file that will have to be reanalysed. "
                  "You may post this as a bug to the project issue tracker.")
            Config.error_caught()
            input("Continue...")
        if self.cache_file:
            with open(self.cache_file, "w") as output:  # save cache
                output.write(string)

    def clear(self):
        # Check if the contents is a CSV and not just a log
        # ex: "06:25:13.378767 IP 142.234.39.36.51354 > 195.250.148.86.80: Flags [S], seq 1852455482, win 29200, length 0"
        re_ip_with_port = re.compile("((\d{1,3}\.){4})(\d+)")
        re_log_line = re.compile(r"([^\s]*)\sIP\s([^\s]*)\s>\s([^\s:]*)")
        _, sample = Identifier(None).get_sample(self.file)
        if sample and re_log_line.match(sample[0]) and is_yes(
                "\nThis seems like a log file. Do you wish to transform it to CSV first?"):
            parser = Parser(self.file, prepare=False)
            parser.prepare_target_file()
            with open(parser.target_file, "w") as target:
                target.write(",".join(["time", "source", "src_port", "dst", "dst_port"]) + "\n")
                with open(parser.source_file) as f:
                    for line in f.readlines():
                        try:
                            res = re_log_line.search(line).groups()
                        except AttributeError:
                            print("Error", line)
                            break
                        else:
                            def parse_ip(val):
                                m = re_ip_with_port.match(val)
                                if m:
                                    return m[1][:-1], m[3]
                                else:
                                    return "", ""

                            timestamp = res[0]
                            source, src_port = parse_ip(res[1])
                            dst, dst_port = parse_ip(res[2])

                            target.write(",".join([timestamp, source, src_port, dst, dst_port]) + "\n")
                input(f"Successfully written to {parser.target_file}. Hit any key.")
                self.file = parser.target_file

        self.parser = Parser(self.file, self.stdin)
        self.save()
