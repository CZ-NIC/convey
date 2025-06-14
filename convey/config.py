# Env config file connection
import configparser
import glob
import logging
import os
import re
import sys
from typing import TYPE_CHECKING
import webbrowser
from pathlib import Path
from shutil import copy
from subprocess import Popen, PIPE, call, run
from sys import exit
from time import sleep
from urllib.parse import quote

from appdirs import user_config_dir

if TYPE_CHECKING:
    from .args_controller import Env

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
    exit()
except FileNotFoundError:  # FileNotFoundError emitted when we are in a directory whose inode exists no more
    print("Current working directory doesn't exist.")
    exit()
logging.basicConfig(level=logging.INFO, handlers=handlers)

# mute noisy module (prints warning every time a validation fails which fails permanently when determining data type)
logging.getLogger('validate_email').setLevel(logging.ERROR)
logging.getLogger('filelock').setLevel(logging.WARNING)

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
            file = Path(f"{config_dir}/{file}")
        except Exception as e:
            print(e)
            print("Error creating program file {}. Exiting.".format(file))
            exit()

    return file


class Config:
    # path = get_path("config.ini")
    # cache = {}

    # config = configparser.ConfigParser()
    # config.read(path)
    config_file: Path | bool | None = None

    QUEUED_NAME = ".queues_lines.tmp"
    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    ABROAD_MARK = "@@"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"
    verbosity: int = logging.INFO  # standard python3 logging level int

    cache_dir: str = ""

    env: "Env"

    @staticmethod
    def missing_dependency(library):
        logger.warning(f"Install {library} by `sudo apt install {library}` first or disable `--{library}` in config")
        input("Press any key...")
        raise KeyboardInterrupt

    # In the past, we had an integrity check here.
    # Convey checked the integrity of the config.ini to update it with new keys and remove the old ones.
    # With the mininterface, the user is not obliged anymore to store the configuration in a file as it is more integrated.

    @staticmethod
    def init_verbosity(yes=False, verbosity=None, daemon=None):
        # Set up logging and verbosity
        if daemon:
            Config.get_env().process.daemon = True
        if yes:
            Config.get_env().cli.yes = True
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

        if Config.config_file:
            logger.debug("Config file loaded from %s", Config.config_file)
        else:
            logger.debug("Config file not found at %s", Config.config_file)

    @staticmethod
    def get_debugger():
        try:
            import ipdb as mod
        except ImportError:
            try:  # pudb not preffered as it wrote "NoneType: None" instead of exceptions
                import pudb as mod
            except ImportError:
                import pdb as mod
        return mod

    @staticmethod
    def error_caught(force=False):
        """ Return True if the user got the prompt (and possibly clean the error up then). """
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
        return Config.get_env().cli.debug

    @staticmethod
    def is_quiet():
        return Config.verbosity >= logging.WARNING

    @staticmethod
    def is_verbose():
        return Config.verbosity <= logging.DEBUG

    @staticmethod
    def is_testing():
        return Config.get_env().sending.testing

    @staticmethod
    def set_env(env: "Env"):
        Config.env = env

    @staticmethod
    def get_env() -> "Env":
        """ Allow migration from old configparser to the typed Env dataclass """
        # This is due to migration from static config.ini. In the future, get rid of the static in favour of objects.
        return Config.env

    @staticmethod
    def github_issue(title, body):
        url = f"https://github.com/CZ-NIC/convey/issues/new?title={quote(title)}&body={quote(body)}"
        if len(url) > 2000:
            # strip ending url-encoded character (because things like "%2" instead of "%20" would break the URL)
            url = re.sub(r'%(\d{1,2})?$', '', url[:1987]) + "%7D%60%60%60"  # add newline and 3× backtick
        webbrowser.open(url)
        input(f"\nPlease submit a Github issue at {url}"
              "\nTrying to open issue tracker in a browser...")

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
    d = {"template": Config.get_env().sending.mail_template, "template_abroad": Config.get_env().sending.mail_template_abroad,
         "uwsgi": "uwsgi.ini", "config": "convey.yaml"}
    if path in d:
        path = get_path(d[path])
    elif not isinstance(path, Path):
        input(f"Not found: {path}. Use one of {list(d)}. Hit Enter...")
        return

    if restart_when_done:
        print(f"Opening {path}... restart Convey when done.")

    gui = True
    if mode & 2:
        # we cannot use xdg-open because template.eml would probably launch an e-mail client
        # app = Popen(['xdg-open', path], stdout=PIPE, stderr=PIPE)
        try:
            editor = run(["xdg-mime", "query", "default", "text/plain"],
                         stdout=PIPE).stdout.split()[0]  # run: blocking, output
            app = Popen(["gtk-launch", editor, path], stdout=PIPE, stderr=PIPE)  # Popen: non blocking
        except FileNotFoundError:
            library = "xdg-utils libgtk-3-bin"
            input(f"Install {library} by `sudo apt install {library}`. Hit Enter to launch CLI editor.")
            gui = False
    elif mode & 1:
        gui = False

    if not gui:
        call(["editor", path])  # call: blocking, no output
    elif mode & 3 == 3:
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
