# Env config file connection
import configparser
import glob
import logging
import os
import re
import sys
import webbrowser
from pathlib import Path
from shutil import copy
from subprocess import Popen, PIPE

from appdirs import user_config_dir

# setup logging
fileHandler = logging.FileHandler("convey.log")
fileHandler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
fileHandler.setLevel(logging.WARNING)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logging.Formatter('%(message)s'))
consoleHandler.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO, handlers=[fileHandler, consoleHandler])

logger = logging.getLogger(__name__)
Path.lexists = lambda self: self.is_symlink() or self.exists()  # not yet exist https://bugs.python.org/issue34137
default_path = Path(Path(__file__).resolve().parent, "defaults")  # path to the 'defaults' folder with templates


def get_path(file):
    """ Assures the file is ready, or creates a new one from a default. """
    config_dir = user_config_dir("convey")
    exists = True
    if Path(file).lexists():
        # check the .ini file is at current location
        file = Path(Path.cwd(), file)
    elif Path(Path(sys.argv[0]).parent, file).lexists():
        # file at program folder (I.E. at downloaded github folder)
        file = Path(Path(sys.argv[0]).parent, file)
    elif Path(config_dir, file).lexists():
        # INIT file at user config folder
        file = Path(config_dir, file)
    else:
        exists = False

    if exists:
        while not Path(file).exists():
            i = input(f"File on the path {file} may be a broken symlink. "
                      f"Mount it and press any key / 'q' for program exit / 'c' for recreating files / 'i' temporarily ignore: ")
            if i == "q":
                print("Exiting.")
                exit()
            elif i == "c":
                exists = False
                break
            elif i == 'i':
                return file

    if not exists or not Path(file).exists():
        # create INI file at user config folder or at program directory
        program_path = Path(sys.argv[0]).parent.resolve()
        if input("It seems this is a first run, since file {} haven't been found."
                 "\nShould we create a default config files at user config folder ({})? "
                 "Otherwise, they'll be created at program folder: {} [Y/n] ".format(file, config_dir, program_path)) \
                in ["", "Y", "y"]:
            Path(config_dir).mkdir(exist_ok=True)
        else:
            config_dir = program_path
        try:
            for filename in glob.glob(str(Path(default_path, '*.*'))):
                copy(filename, config_dir)
            file = "{}/{}".format(config_dir, file)
        except Exception as e:
            print(e)
            print("Error creating program file {}. Exiting.".format(file))
            exit()

    return file


class Config:
    path = get_path("config.ini")
    cache = {}

    config = configparser.ConfigParser()
    config.read(path)

    # muted = False  # silence info text

    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"
    verbosity: int = logging.INFO  # standard python3 logging level int

    @staticmethod
    def init(yes=False, verbosity=None):
        from .dialogue import is_yes  # since Config should be the very first package file to be loaded, we postpone this import
        # Config file integrity check (we may upgrade Convey from but some new parameters needs to be added manually)
        default_config = configparser.ConfigParser()
        default_ini = Path(default_path, "config.ini")
        default_config.read(default_ini)
        passed = True
        section_missing = []
        section_superfluous = []
        key_missing = {}  # [key] => section
        key_superfluous = []
        for section in default_config:
            missing_section = False
            if section not in Config.config:
                print(f"Missing section: {section}")
                section_missing.append(section)
                passed = False
                missing_section = True
                # continue
            for key in default_config[section]:
                if missing_section or key not in Config.config[section]:
                    print(f"Missing key {key} (defaulting to {repr(default_config[section][key])}) in section: {section}")
                    key_missing[key] = section
                    passed = False
        for section in Config.config:
            if section not in default_config:
                print(f"(Config has an unused section: {section})")
                section_superfluous.append(section)
                continue
            for key in Config.config[section]:
                if key not in default_config[section]:
                    print(f"Config has an unused key {key} in section: {section}")
                    key_superfluous.append(key)
        if not passed:
            # analyze current config file and get its section start line numbers
            config_lines = Config.path.read_text().splitlines(keepends=True)
            section_lines = {}  # [section name] = section start line number
            for i, line in enumerate(config_lines):
                try:
                    section = re.match("\[([^]]*)\]", line).group(1)
                except AttributeError:
                    pass
                else:
                    section_lines[section] = i

            # analyze the default config file
            default_lines = default_ini.read_text().splitlines(keepends=True)
            anchors = tuple(key_missing.keys())

            def get_key(iterable, match):
                """
                :rtype: yields tuple of (key name, slice start-stop line of the iterable)
                """
                comment = None
                for i, line in enumerate(iterable):  # add missing keys and sections
                    if line.startswith("#"):
                        if not comment:
                            comment = i
                        continue
                    if line.startswith(anchors):
                        key = re.match("[a-zA-Z0-9_]*", line).group(0)
                        if key in match:  # we have found one of the matching keys
                            yield key, slice(comment or i, i + 1)
                    comment = None

            # remove unused keys
            for key, slice_ in get_key(config_lines, key_superfluous):
                for i in range(slice_.start, slice_.stop):
                    config_lines[i] = ""
            # insert missing keys and sections
            for key, slice_ in get_key(default_lines, key_missing):
                block = default_lines[slice_]
                try:
                    start_line = section_lines[key_missing[key]]
                except KeyError:  # insert missing section
                    section_lines[key_missing[key]] = start_line = len(config_lines)
                    config_lines.append(f"\n[{key_missing[key]}]")
                config_lines[start_line] += "\n" + "".join(block)  # insert missing key
            if is_yes("Should I add the missing keys (and remove the unused) from your config file?"):
                Config.path.write_text("".join(config_lines))
                print("Config file has been successfully modified. Restarting Convey.")
            else:
                print("Please write missing items into the config file before continuing.\nOpening", Config.path, "...")
                p = Popen(["xdg-open", Config.path], shell=False)
            quit()

        # Set up logging and verbosity
        from .dialogue import assume_yes
        if yes:
            assume_yes()
            Config.set("yes", True)
        if verbosity:
            Config.verbosity = verbosity
        if Config.is_debug():
            if not verbosity:  # if user has not say the verbosity level, make it the most verbose
                Config.verbosity = logging.DEBUG
            logging.root.handlers[0].setLevel(logging.INFO)  # file handler to info level

        logging.root.handlers[1].setLevel(Config.verbosity)  # stream handler to debug level
        logging.getLogger().setLevel(min(Config.verbosity, logging.INFO))  # system sensitivity at least at INFO level

        logger.debug("Config file loaded from: {}".format(Config.path))

    @staticmethod
    def get_debugger():
        try:
            import pudb as mod
        except ImportError:
            try:
                import ipdb as mod
            except ImportError:
                import pdb as mod
        return mod

    @staticmethod
    def error_caught(force=False):
        if Config.is_debug() or force:
            import traceback
            import sys

            mod = Config.get_debugger()
            type_, value, tb = sys.exc_info()
            traceback.print_exc()
            if tb:
                print("Post mortem")
                mod.post_mortem(tb)
            else:
                print("Lets debug. Hit n to get to the previous scope.")
                mod.set_trace()
            return True
        return False

    @staticmethod
    def is_debug():
        return Config.get('debug')

    @staticmethod
    def is_quiet():
        return Config.verbosity >= logging.WARNING

    @staticmethod
    def is_testing():
        return Config.get('testing')

    @staticmethod
    def get(key, section='CONVEY', get=None):
        """

        :type get: type
                * if str, return value will always be str (ex: no conversion '1/true/on' to boolean happens)
                * if list, value tries to be splitted by l
        :rtype: * boolean for text 0/off/false 1/on/true
                * None for text = '' or non-inserted value
                * or any inserted value if non-conforming to previous possibilities
        """
        if key not in Config.cache:
            try:
                val = Config.config.getboolean(section, key)
            except ValueError:
                val = Config.config[section][key]
                if val == '':
                    val = None
            except (configparser.NoOptionError, KeyError):
                val = None
            finally:
                Config.cache[key] = val
        val = Config.cache[key]
        if get is str and type(val) is not str:
            try:
                return str(Config.config[section][key])
            except KeyError:
                return ''
        if get is list:
            if val:
                return [x.strip() for x in val.split(",")]
            return []
        return val

    @staticmethod
    def github_issue(title, body):
        url = f"https://github.com/CZ-NIC/convey/issues/new?" \
              f"title={title}&body={body}"
        webbrowser.open(url)
        input("\nPlease submit a Github issue at https://github.com/CZ-NIC/convey/issues/new"
              "\nTrying to open issue tracker in a browser...")

    @staticmethod
    def set(key, val, section='CONVEY'):
        if val is None:
            Config.config.remove_option(section, key)
        else:
            Config.cache[key] = val
            # XX Config.config.set(section, key, str(val))

    cache_dir = ""
    output = None  # True, False, None or str (path)

    @staticmethod
    def set_cache_dir(dir_):
        Config.cache_dir = dir_

    @staticmethod
    def get_cache_dir():
        """ Cache dir with ending slash. """
        return Config.cache_dir

    @staticmethod
    def edit_configuration():
        Popen(['xdg-open', Config.path], stdout=PIPE, stderr=PIPE)


def get_terminal_size():
    try:
        height, width = (int(s) for s in os.popen('stty size', 'r').read().split())
        return height, width
    except (OSError, ValueError):
        return 0, 0
