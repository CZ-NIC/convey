# Env config file connection
import configparser
import glob
import logging
import sys
from pathlib import Path
from shutil import copy
from subprocess import Popen, PIPE

from appdirs import user_config_dir

Path.lexists = lambda self: self.is_symlink() or self.exists()  # not yet exist https://bugs.python.org/issue34137
default_path = Path(Path(__file__).resolve().parent, "defaults")


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

    # Config file integrity check (we may upgrade Convey from but some new parameters needs to be added manually)
    default_config = configparser.ConfigParser()
    default_config.read(Path(default_path, "config.ini"))
    passed = True
    for section in default_config:
        if section not in config:
            print(f"Missing section: {section}")
            passed = False
            continue
        for key in default_config[section]:
            if key not in config[section]:
                print(f"Missing key {key} (defaulting to {repr(default_config[section][key])}) in section: {section}")
                passed = False
    for section in config:
        if section not in default_config:
            print(f"(Config has an unused section: {section})")
            continue
        for key in config[section]:
            if key not in default_config[section]:
                print(f"Config has an unused key {key} in section: {section}")
    if not passed:
        print("Please write missing items into the config file before continuing.\nOpening", path, "...")
        p = Popen(["xdg-open", path], shell=False)
        quit()

    # set by SourceParser and used by Registry
    has_header = False
    header = ""
    # conveying = "all" # quick access to the property
    # redo_invalids = True # quick access to the property

    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"

    @staticmethod
    def init(yes=False):  # , mute=False
        # from .informer import mute_info
        from .dialogue import assume_yes
        if yes:
            assume_yes()
        # Config.muted = mute
        # if mute:
        #     mute_info()
        #
        # if not Config.muted:
        print("Config file loaded from: {}".format(Config.path))
        if Config.is_debug():
            if 1 in logging.root.handlers:
                logging.root.handlers[1].setLevel(logging.INFO)  # stream handler to debug level

    @staticmethod
    def error_catched():
        if Config.is_debug():
            import ipdb
            import traceback
            import sys
            _, value, tb = sys.exc_info()
            traceback.print_exc()
            if tb:
                print("Post mortem")
                ipdb.post_mortem(tb)
            else:
                print("Lets debug. Hit n to get to the previous scope.")
                ipdb.set_trace()

    @staticmethod
    def is_debug():
        return Config.get('debug')

    @staticmethod
    def is_testing():
        return Config.get('testing')

    @staticmethod
    def get(key, section='CONVEY', get=None):
        """

        :type get: type If str, return value will always be str (ex: no conversion '1/true/on' to boolean happens)
        :rtype: * boolean for text 0/off/false 1/on/true
                * None for text = '' or non-inserted value
                * or any inserted value if non-conforming to previous possibilities
        """
        if key not in Config.cache:
            try:
                val = Config.config.getboolean('CONVEY', key)
            except ValueError:
                val = Config.config[section][key]
                if val == '':
                    val = None
            except (configparser.NoOptionError, KeyError):
                val = None
            finally:
                Config.cache[key] = val
            # try:
            #     Config.cache[key] = Config.config[section][key]
            # except KeyError:
            #     input(f"The key {key} is not in the config file {Config.path} – integrity failed."
            #           " This should not happen. The program ends now."
            #           "\nPlease submit a Github issue at https://github.com/CZ-NIC/convey/issues/new")
            #     url = f"https://github.com/CZ-NIC/convey/issues/new?" \
            #           f"title=integrity failed for key `{key}`&body=issue generated automatically"
            #     webbrowser.open(url)
            #     quit()
        val = Config.cache[key]
        if get is str and type(val) is not str:
            try:
                return str(Config.config[section][key])
            except KeyError:
                return ''
        return val

    # @staticmethod
    # def getboolean(key, true_boolean=True):
    #     """
    #     :param key: Key
    #     :type true_boolean: True: returns configparser.getboolean or raise ValueError
    #                         False: returns * boolean (text 0/off/false 1/on/true)
    #                                        * None for text = '' or not inserted value
    #                                        * or any inserted value if non-conforming to previous possibilities
    #     """
    #     if true_boolean:
    #         return Config.config.getboolean('CONVEY', key)
    #     else:
    #         try:
    #             return Config.config.getboolean('CONVEY', key)
    #         except ValueError:
    #             val = Config.get(key)
    #             if val == '':
    #                 return None
    #             else:
    #                 return val
    #         except configparser.NoOptionError:
    #             return None

    @staticmethod
    def set(key, val, section='CONVEY'):
        if val is None:
            Config.config.remove_option(section, key)
        else:
            Config.config.set(section, key, str(val))

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
