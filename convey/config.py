# Env config file connection
import configparser
import csv
import glob
import logging
import sys
from os import path, getcwd, makedirs
from shutil import copy

from appdirs import user_config_dir


def get_path(file):
    """ Assures the file is ready, or creates a new one from a default. """
    config_dir = user_config_dir("convey")
    if path.exists(file):
        # check the .ini file is at current location
        file = path.join(getcwd(), file)
    elif path.exists(path.join(path.dirname(sys.argv[0]), file)):
        # file at program folder (I.E. at downloaded github folder)
        file = path.join(path.dirname(sys.argv[0]), file)
    elif path.exists(path.join(config_dir, file)):
        # INIT file at user config folder
        file = path.join(config_dir, file)
    else:
        # create INI file at user config folder or at program directory
        default_path = "{}/defaults/".format(path.dirname(path.realpath(__file__)))
        if input("It seems this is a first run, since file {} haven't been found."
                 "\nShould we create a default config files at user config folder ({})? "
                 "Otherwise, they'll be created at program folder: {} [Y/n] ".format(file, config_dir, path.dirname(sys.argv[0]))) \
                in ["", "Y", "y"]:
            makedirs(config_dir, exist_ok=True)
        else:
            config_dir = path.dirname(sys.argv[0])
        try:
            for filename in glob.glob(path.join(default_path, '*.*')):
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

    # set by SourceParser and used by Registry
    has_header = False
    header = ""
    # conveying = "all" # quick access to the property
    # redo_invalids = True # quick access to the property

    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"

    def init():
        if Config.is_debug():
            logging.root.handlers[1].setLevel(logging.INFO)  # stream handler to debug level

    def error_catched():
        if Config.is_debug():
            import ipdb
            import traceback
            import sys
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            if tb:
                print("Post mortem")
                ipdb.post_mortem(tb)
            else:
                print("Lets debug. Hit n to get to the previous scope.")
                ipdb.set_trace()

    def is_debug():
        return True if Config.get('debug') == "True" else False

    def is_testing():
        return True if Config.get('testing') == "True" else False

    def get(key, section='CONVEY'):
        if key not in Config.cache:
            try:
                Config.cache[key] = Config.config[section][key]
            except:
                input("The key {} is not in the config file {}. The program ends now.".format(key, Config.path))
                quit()
        return Config.cache[key]
        # return Config.config[section][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY', key)

    # def setTemp(key,val):
    #    Config.tempCache[key] = val

    def set(key, val, section='CONVEY'):
        Config.config.set(section, key, str(val))
        # Can't update the file now, it would kill comments in config.ini :(
        # XAnd I dont want to can do the update because Whois may set whois_mirror value and this change is meant to be temporary only (for the single run of program)
        # with open(Config.file,"w") as f:
        # Config.config.write(f)

    cache_dir = ""

    def set_cache_dir(dir):
        Config.cache_dir = dir

    def get_cache_dir():
        """ Cache dir with ending slash. """
        return Config.cache_dir

    def update():
        """
         * Refreshes Cc of the mails in the results (config key contacts_local)
         * Search for country contact (config key contacts_foreign) """
        Config.abusemails = Config._update("contacts_local")
        Config.csirtmails = Config._update("contacts_foreign")

    def _update(key):
        """ Update info from external CSV file. """
        file = Config.get(key)
        if not path.isfile(file):  # file with contacts
            print("(Contacts file {} not found on path {}/{}.) ".format(key, getcwd(), file))
            return {}
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                rows = {rows[0]: rows[1] for rows in reader}
                return rows
