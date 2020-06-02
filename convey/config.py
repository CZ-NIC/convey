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
from subprocess import Popen, PIPE, call, run
from time import sleep
from urllib.parse import quote

from appdirs import user_config_dir

# setup logging
# This cannot be in __init__.py so that we cannot reliably use logger in __init__.py, __main__.py and decorators.py.
# The reason is __init__.py gets launched when generic Python autocompletion searches for includable modules.
# If user would hit tab when writing `python3 -m [LETTER].[TAB]` into terminal, empty convey.log would have been created in the dir.
handlers = []
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))
console_handler.setLevel(logging.INFO)
handlers.append(console_handler)
try:
    file_handler = logging.FileHandler("convey.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    file_handler.setLevel(logging.WARNING)
    handlers.append(file_handler)
except PermissionError:
    file_handler = None
    print("Cannot create convey.log here at " + str(os.path.abspath(".")) + " – change directory please.")
    quit()
except FileNotFoundError:  # FileNotFoundError emitted when we are in a directory whose inode exists no more
    print("Current working directory doesn't exist.")
    quit()
logging.basicConfig(level=logging.INFO, handlers=handlers)

# class init
logger = logging.getLogger(__name__)
Path.lexists = lambda self: self.is_symlink() or self.exists()  # not yet exist https://bugs.python.org/issue34137
default_path = Path(Path(__file__).resolve().parent, "defaults")  # path to the 'defaults' folder with templates

config_dir = user_config_dir("convey")
BOOLEAN_STATES = configparser.RawConfigParser.BOOLEAN_STATES
console_handler, file_handler, *_ = *logging.root.handlers, None


def get_path(file):
    """ Assures the file is ready, or creates a new one from a default. """
    global config_dir
    exists = True
    try:
        b = Path(file).lexists()
    except PermissionError as e:
        b = False  # ex we run program from /root under another user
    finally:
        if b:
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
        # this is before Config file is load, we have to parse sys.argv directly
        yes = any(x in sys.argv for x in ['-y', '--yes', '-H', '--headless'])
        if not yes:
            yes = input(f"It seems this is a first run, since file {file} haven't been found."
                        f"\nShould we create default config files at user config folder ({config_dir})?"
                        f" Otherwise, they'll be created at program folder: {program_path} [Y/n] ") in ["", "Y", "y"]
        if yes:
            Path(config_dir).mkdir(parents=True, exist_ok=True)
        else:
            config_dir = program_path
        try:
            for filename in glob.glob(str(Path(default_path, '*.*'))):
                # do not overwrite existing files
                #  – user just might have deleted EML templates and they would not be happy to see their config.ini wiped
                if not Path(config_dir, Path(filename).name).exists():
                    copy(str(filename), config_dir)
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

    QUEUED_NAME = ".queues_lines.tmp"
    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    ABROAD_MARK = "@@"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"
    verbosity: int = logging.INFO  # standard python3 logging level int

    @staticmethod
    def missing_dependency(library):
        logger.warning(f"Install {library} by `sudo apt install {library}` first or disable `--{library}` in config")
        input("Press any key...")
        raise KeyboardInterrupt

    @staticmethod
    def integrity_check():
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

            def get_key(iterable, match):
                """
                :rtype: yields tuple of (key name, slice start-stop line of the iterable)
                """
                comment = None
                anchors = tuple(iterable)
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
                print("Config file has been successfully modified. Restart Convey.")
            else:
                print("Please write missing items into the config file before continuing.\nOpening", Config.path, "...")
                p = Popen(["xdg-open", Config.path], shell=False)
            quit()

    @staticmethod
    def init_verbosity(yes=False, verbosity=None, daemon=None):
        # Set up logging and verbosity
        if daemon:
            Config.set("daemon", True)
        if yes:
            Config.set("yes", True)
        if verbosity:
            Config.verbosity = verbosity
        else:
            # we reset the verbosity to the default value
            # usecase: client could ask the daemon for logging.DEBUG.
            # In the next request, they does not specify the verbosity. If not reset, the verbosity would still be logging.DEBUG.
            Config.verbosity = logging.INFO
        if Config.is_debug():
            if not verbosity:  # if user has not say the verbosity level, make it the most verbose
                Config.verbosity = logging.DEBUG
            if file_handler:
                file_handler.setLevel(logging.INFO)  # file handler to info level
            logging.getLogger("chardet").setLevel(logging.WARNING)  # we are not interested in chardet debug logs

        console_handler.setLevel(Config.verbosity)  # stream handler to debug level
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
    def is_verbose():
        return Config.verbosity <= logging.DEBUG

    @staticmethod
    def is_testing():
        return Config.get('testing')

    @staticmethod
    def get(key, section='CONVEY', get=None):
        """

        :type get: type
                * if str, return value will always be str (ex: no conversion '1/true/on' to boolean happens)
                * if list, value tries to be split by a comma
                * if bool, it tries to convert to True/False from values 0/off/false 1/on/true
                * if int, you get integer or 0 on error (which means 0 for on/true)
                * if None
                    * bool for text 0/off/false 1/on/true
                    * None for text = '' or non-inserted value
                    * or any inserted value if non-conforming to previous possibilities
        """
        if key not in Config.cache:
            try:
                val = Config.config[section][key]
                if (get is None or get is bool) and val.lower() in BOOLEAN_STATES:
                    val = BOOLEAN_STATES[val.lower()]
                elif val == '':
                    val = get() if get else None
            except (configparser.Error, KeyError):
                return get() if get else None
            Config.cache[key] = val
        val = Config.cache[key]
        if get is str and type(val) is not str:
            try:
                return str(Config.config[section][key])
            except KeyError:
                return ''
        elif get is list:
            if val:
                return [x.strip() for x in val.split(",")]
            return []
        elif get is int:
            try:
                return int(val)
            except ValueError:
                return 0
        return val

    @staticmethod
    def github_issue(title, body):
        url = f"https://github.com/CZ-NIC/convey/issues/new?title={quote(title)}&body={quote(body)}"
        if len(url) > 2000:
            # strip possible ending percent (because double percent would not work)
            url = url[:1987].rstrip("%") + "%7D%60%60%60"  # add newline and 3× backtick
        webbrowser.open(url)
        input(f"\nPlease submit a Github issue at {url}"
              "\nTrying to open issue tracker in a browser...")

    @staticmethod
    def set(key, val, section='CONVEY'):
        # XX was this needed? if val is None:
        #    Config.config.remove_option(section, key)
        # else:
        Config.cache[key] = val
        # XX Config.config.set(section, key, str(val))

    cache_dir = ""
    output = None  # True, False, None or str (path)

    @staticmethod
    def set_cache_dir(path):
        Config.cache_dir = path
        if not path.exists():
            path.mkdir()

    @staticmethod
    def get_cache_dir():
        """ Cache dir with ending slash. """
        return Config.cache_dir


def edit(path="config", mode=3, restart_when_done=False, blocking=False):
    """

    @param path: One of the keywords to edit default files in config folder or any pathlib.Path.
    @param mode: 1 text, 2 gui, 3 gui or text
    @param restart_when_done: If True, user is told to restart Convey when done.
    @type blocking: If True and GUI used, user is told to Hit Enter before continuing.
    """
    if type(mode) is str:  # from CLI
        mode = int(mode)
    d = {"template": Config.get("mail_template"), "template_abroad": Config.get("mail_template_abroad"),
         "uwsgi": "uwsgi.ini", "config": "config.ini"}
    if path in d:
        path = get_path(d[path])
    elif not isinstance(path, Path):
        input(f"Not found: {path}. Hit Enter...")
        return

    if restart_when_done:
        print(f"Opening {path}... restart Convey when done.")

    gui = True
    if mode & 2:
        # we cannot use xdg-open because template.eml would probably launch an e-mail client
        # app = Popen(['xdg-open', path], stdout=PIPE, stderr=PIPE)
        try:
            editor = run(["xdg-mime", "query", "default", "text/plain"], stdout=PIPE).stdout.split()[0]  # run: blocking, output
            app = Popen(["gtk-launch", editor, path], stdout=PIPE, stderr=PIPE)  # Popen: non blocking
        except FileNotFoundError:
            library = "xdg-mime"
            input(f"Install {library} by `sudo apt install {library}`. Hit Enter to launch CLI editor.")
            call(["editor", path])  # call: blocking, no output
    elif mode & 1:
        call(["editor", path])  # call: blocking, no output
        gui = False

    if mode & 3 == 3:
        for _ in range(10):  # lets wait a second to be sure GUI app started
            sleep(0.1)
            p = app.poll()
            if p is not None:
                if p != 0:
                    # a GUI app have not started, let's launch a CLI terminal
                    call(["editor", path])
                    gui = False
                break

    if gui and blocking:
        input("Press Enter to continue...")


def get_terminal_size():
    try:
        # XX when piping the input IN, it writes
        # echo "434" | convey -f base64  --debug
        # stty: 'standard input': Inappropriate ioctl for device
        # I do not know how to suppress this warning.
        height, width = (int(s) for s in os.popen('stty size', 'r').read().split())
        return height, width
    except (OSError, ValueError):
        return 0, 0


# we are awaiting english replies in the subprocess application
subprocess_env = dict(os.environ)
subprocess_env["LANG"] = "en_US.UTF-8"
