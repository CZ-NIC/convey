"""
    Source file caching - load, save
"""
import logging
import re
import sys
import traceback
from bdb import BdbQuit
from contextlib import contextmanager
from csv import writer
from os import linesep
from pathlib import Path

import ezodf
import jsonpickle
import xlrd
from xlrd import XLRDError

from .config import Config, config_dir
from .dialogue import is_yes
from .identifier import Identifier
from .parser import Parser

logger = logging.getLogger(__name__)

__author__ = "Edvard Rejthar"
__date__ = "$Mar 23, 2015 8:33:24 PM$"

WHOIS_CACHE = ".convey-whois-cache.json"


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
    if Config.get("daemon", get=bool):
        raise ConnectionRefusedError("STDIN missing")
    print("Write something to stdin. (End of transmission 2× <Ctrl>+d or <Enter>+<Ctrl>+d.)")
    return sys.stdin.read().rstrip().split("\n")  # rstrip \n at the end of the input


class Wrapper:
    def __init__(self, file_or_input, force_file=False, force_input=False,
                 types=None, fresh=False, reprocess=False, delete_cache=False):
        if delete_cache:
            Path(config_dir, WHOIS_CACHE).unlink()

        self.parser: Parser = None
        self.file = file = None
        self.stdin = stdin = None
        self.types = types
        self.fresh = fresh
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
            self.parser: Parser = Parser(stdin=stdin, types=self.types)
            return

        if not Path(file).is_file():
            print(f"File '{file}' not found.")
            quit()

        self.assure_cache_file(file)
        if Path(self.cache_file).is_file() and not (fresh or reprocess):
            logger.info("File {} has already been processed.".format(self.file))
            try:  # try to depickle
                self.parser = jsonpickle.decode(open(self.cache_file, "r").read(), keys=True)
            except:
                print(traceback.format_exc())
                if not Config.error_caught():
                    input()
                else:
                    print("Cache file loading failed, let's process it all again. If you continue, cache gets deleted.")
                self.parser = None

        if self.parser:  # we have successfully loaded a parser
            if self.parser.source_file != self.file:  # file might have been moved to another location
                self.parser.source_file = self.file
            try:
                if self.parser.is_analyzed or self.parser.is_formatted:
                    self.parser.informer.sout_info()
                    logger.info("It seems the file has already been formatted.")
            except BdbQuit:  # we do not want to catch quit() signal from pdb
                print("Stopping.")
                quit()
            except Exception as e:
                print(e)
                import ipdb;
                ipdb.post_mortem()
                print("Format of the file may have changed since last time. "
                      "Let's process it all again. If you continue, cache gets deleted.")
                if not Config.error_caught():
                    input()
                self.parser = None

        if not self.parser:
            self.clear()

        if not fresh:
            self.parser.ip_seen, self.parser.ranges = self.load_whois_cache()
            self.parser.refresh()
            self.parser.reset_whois(assure_init=True)
            # correction of a wrongly pickling: instead of {IPNetwork('...'): (IPNetwork('...'),
            # we see {IPNetwork('...'): (<jsonpickle.unpickler._IDProxy object at 0x...>,
            # Note that IPRange is pickled correctly.
            for prefix, o in self.parser.ranges.items():
                l = list(o)
                l[0] = prefix
                self.parser.ranges[prefix] = tuple(l)

    def assure_cache_file(self, file):
        self.file = Path(file).resolve()
        info = Path(self.file).stat()
        hash_ = str(hash(info.st_size + round(info.st_mtime)))
        # cache-file with source file metadata
        Config.set_cache_dir(Path(Path(self.file).parent, Path(self.file).name + "_convey" + hash_))
        self.cache_file = Path(Config.get_cache_dir(), Path(self.file).name + ".cache")

    @staticmethod
    def load_whois_cache():
        p = Path(config_dir, WHOIS_CACHE)  # restore whois cache
        if p.exists():
            return jsonpickle.decode(p.read_text(), keys=True)
        return {}, {}

    ##
    # Store
    def save(self, last_chance=False):
        # chance to save the original file to the disk if reading from STDIN
        if not self.cache_file and ((self.parser.stdout is not True and self.parser.stdout) or self.parser.is_formatted):
            # * cache_file does not exist = we have not written anything on the disk
            # * target_file exist = there is a destination to write (when splitting, no target_file specified)
            #       XX which may be changed because it is usual to preserve file
            # * stdout or is_formatted - there is something valuable to be saved
            target_file = self.parser.target_file or self.parser.source_file
            if not target_file:  # we were splitting so no target file exist
                target_file = self.parser.invent_file_str()
            if Config.get("output") is None:
                i = Config.get("save_stdin_output", get=int)
                save = False
                if i == 4 or (i == 3 and self.parser.is_analyzed):
                    save = True
                elif i == 2 or (i == 1 and self.parser.is_analyzed) and last_chance:
                    save = is_yes(f"Save to an output file {target_file}?")
            else:
                save = bool(Config.get("output"))
            if save:
                if not self.parser.target_file:
                    # if a split files were generated, we lost the connection because cache dir will change right now
                    # so we forget we've already split and make the file processable again (because split settings remained)
                    self.parser.is_split = False
                    self.parser.is_analyzed = False
                self.parser.source_file = target_file
                if self.parser.stdout is True:
                    # case: input has been processed and returned an empty result, ex: all rows filtered out
                    target_file.write_text("")
                else:  # XX I do not understand when we save self.parser.stdin
                    target_file.write_text(self.parser.stdout or linesep.join(self.parser.stdin))
                self.parser.stdin = None
                self.assure_cache_file(target_file)
            if self.parser.target_file:
                self.parser.saved_to_disk = bool(save)

        # serialize
        string = jsonpickle.encode(self.parser, keys=True)
        try:
            # Sometimes jsonpickling fails. But even if it does not fail, we are not sure everything is alright.
            # Once jsonpickle shuffled keys and values of self.parser.ip_seen dict (when this dict was yet part of self.parser).
            # There must be problem with a bad reference.
            # – once I encountered "get[7] datetime" instead of "get[0] prefix" as the value.
            # I narrowed the case to a CSV of 3 lines: any IPs to whom I added a netname col. When decoded, values were shuffled.
            # Unfortunately, I have not been able to simulate this behaviour with another simpler object than self.parser
            # so that I could raise an official issue.
            jsonpickle.decode(string, keys=True)
        except Exception:
            print("The program state is not picklable by 'jsonpickle' module. "
                  "Continuing will provide a file that will have to be reanalysed. "
                  "You may post this as a bug to the project issue tracker.")
            Config.error_caught()
            input("Continue...")

        # save cache file
        if self.cache_file:  # cache_file does not exist typically if reading from STDIN
            if self.parser.ranges:
                # we extract whois info from self.parser and save it apart for every convey instance
                if self.fresh:  # if we wanted a fresh result, global whois cache was not used and we have to merge it
                    ip_seen, ranges = self.load_whois_cache()
                    ip_seen = {**ip_seen, **self.parser.ip_seen}
                    ranges = {**ranges, **self.parser.ranges}
                else:
                    ip_seen, ranges = self.parser.ip_seen, self.parser.ranges
                # note that ip_seen MUST be placed before ranges due to https://github.com/jsonpickle/jsonpickle/issues/280
                # That way, a netaddr object (IPNetwork, IPRange) are defined as value in ip_seen and not as key in range.
                encoded = jsonpickle.encode([ip_seen, ranges], keys=True)
                # noinspection PyBroadException
                try:
                    jsonpickle.decode(encoded, keys=True)
                except:  # again, I met a strangely formed JSON
                    type_, value, tb = sys.exc_info()
                    body = f"```bash\n{traceback.format_exc()}```\n\n```json5\n{tb.tb_next.tb_frame.f_locals}\n```\n\n```json5\n{ip_seen}```\n\n```json5\n{ranges}```"
                    print("The program will recover but without saving WHOIS cache.")
                    Config.github_issue("Cannot jsonpickle whois", body)
                else:
                    Path(config_dir, WHOIS_CACHE).write_text(encoded)
            with open(self.cache_file, "w") as output:  # save cache
                output.write(string)

    def clear(self):
        self.check_xls() or self.check_ods() or self.check_log()

        self.parser = Parser(self.file, self.stdin, self.types)
        self.save()

    def check_log(self):
        """ Check if the contents is a CSV and not just a log
         ex: "06:25:13.378767 IP 142.234.39.36.51354 > 195.250.148.86.80: Flags [S], seq 1852455482, win 29200, length 0"
         """
        re_ip_with_port = re.compile("((\d{1,3}\.){4})(\d+)")
        re_log_line = re.compile(r"([^\s]*)\sIP\s([^\s]*)\s>\s([^\s:]*)")
        _, sample = Identifier(None).get_sample(self.file)
        if sample and re_log_line.match(sample[0]):

            if is_yes("This seems like a log file. Do you wish to transform it to CSV first?"):
                with self.rework() as target:
                    target.writerow(["time", "source", "src_port", "dst", "dst_port"])
                    with open(self.file) as f:
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
                                target.writerow([timestamp, source, src_port, dst, dst_port])
            return True

    def check_ods(self):
        """ Check if the contents is an ODS file """
        try:
            doc = ezodf.opendoc(self.file)
        except KeyError:
            pass
        else:
            if is_yes("This seems like an ODS file. Do you wish to transform it to CSV first?"):
                sheet = doc.sheets[0]
                with self.rework() as target:
                    for i, row in enumerate(sheet.rows()):
                        r = []
                        for j, cell in enumerate(row):
                            r.append(cell.value)
                        target.writerow(r)
            return True

    def check_xls(self):
        """ Check if the contents is a XLS file """
        try:
            wb = xlrd.open_workbook(self.file)
            sh = wb.sheet_by_name('Sheet1')
        except XLRDError:
            pass
        else:
            if is_yes("This seems like a XLS file. Do you wish to transform it to CSV first?"):
                with self.rework() as target:
                    for row in range(sh.nrows):
                        target.writerow(sh.row_values(row))
            return True

    @contextmanager
    def rework(self):
        target = Path(str(self.file) + ".csv")
        if target.exists():
            if is_yes(f"It seems the file {target.absolute()} already exists. Do you wish to process it?"):
                try:
                    yield None
                except AttributeError:
                    pass
                finally:
                    # XXX however, this resets the cache of the file because we continue in the clear() method
                    #   We rather do want to directly go to the file.
                    self.assure_cache_file(target.absolute())  # changes self.file
                    return
            else:
                print(f"The file {target} already exist, cannot be recreated.")
                quit()
        # noinspection PyBroadException
        try:
            with target.open("w") as f:
                yield writer(f)
        except Exception as e:
            print(e)
            input(f"Could not convert. Hit any key.")
        else:
            input(f"Successfully written to {target.absolute()}. Hit any key.")
            # XX remove old cache directory if empty
            self.assure_cache_file(target.absolute())  # changes self.file
