# Env config file connection
import configparser
import csv
import logging
import os

class Config:
    os.chdir(os.path.dirname(__file__) + "/../")
    file = "config.ini"
    cache = {}
    if not os.path.isfile(file):
        if os.path.isfile(file + ".default"):
            if input("Config file missing. Should we create a default config.ini file? [Y/n] ") in ["", "Y", "y"]:
                from shutil import copyfile
                copyfile(file + ".default", file)
                print("This may be your first launch. Note you may want to run ./install.sh before using Convey.")
                input()
            else:
                print("Okay, then.")
                exit(0)
        else:
            print("Missing config.ini")
            exit(1)
    config = configparser.ConfigParser()
    config.read(file)
    # tempCache = {}

    # set by SourceParser and used by Registry
    has_header = False
    header = ""
    # conveying = "all" # quick access to the property
    # redo_invalids = True # quick access to the property

    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"

    def init():
        if Config.isDebug():
            logging.root.handlers[1].setLevel(logging.INFO)  # stream handler to debug level

    def errorCatched():
        if Config.isDebug():
            import ipdb;
            import traceback;
            import sys
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            if tb:
                print("Post mortem")
                ipdb.post_mortem(tb)
            else:
                print("Lets debug. Hit n to get to the previous scope.")
                ipdb.set_trace()

    def isDebug():
        return True if Config.get('debug') == "True" else False

    def isTesting():
        return True if Config.get('testing') == "True" else False

    def get(key, section='CONVEY'):
        if key not in Config.cache:
            Config.cache[key] = Config.config[section][key]
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

    cacheDir = ""

    def setCacheDir(dir):
        Config.cacheDir = dir

    def getCacheDir():
        """ Cache dir with ending slash. """
        return Config.cacheDir

    def update():
        """
         * Refreshes Cc of the mails in the results (config key contacts_local)
         * Search for country contact (config key contacts_foreign) """
        Config.abusemails = Config._update("contacts_local")
        Config.csirtmails = Config._update("contacts_foreign")

    def _update(key):
        """ Update info from external CSV file. """
        file = Config.get(key)
        if not os.path.isfile(file):  # file with contacts
            print("(Contacts file {} not found on path {}.) ".format(key, file))
            return {}
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                rows = {rows[0]: rows[1] for rows in reader}
                return rows
