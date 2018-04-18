# Env config file connection
import configparser
import os
import csv

class Config:
    os.chdir(os.path.dirname(__file__)+"/../")
    file = "config.ini"
    cache = {}
    config = configparser.ConfigParser()
    config.read(file)
    #tempCache = {}

    # set by SourceParser and used by Registry
    hasHeader = False
    header = ""
    #conveying = "all" # quick access to the property
    #redo_invalids = True # quick access to the property

    INVALID_NAME = ".invalidlines.tmp"
    UNKNOWN_NAME = "unknown"
    PROJECT_SITE = "https://github.com/CZ-NIC/convey/"


    def errorCatched():
        if Config.isDebug():
            import ipdb; import traceback; import sys
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

    def get(key, section = 'CONVEY'):
        if key not in Config.cache:
            Config.cache[key] = Config.config[section][key]
        return Config.cache[key]
        #return Config.config[section][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY',key)

    #def setTemp(key,val):
    #    Config.tempCache[key] = val

    def set(key, val, section = 'CONVEY'):
        Config.config.set(section,key,str(val))
        # Can't update the file now, it would kill comments in config.ini :(
        # XAnd I dont want to can do the update because Whois may set whois_mirror value and this change is meant to be temporary only (for the single run of program)
        #with open(Config.file,"w") as f:
            #Config.config.write(f)

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
        if os.path.isfile(file) == False: # file with contacts
            print("(Contacts file {} not found on path {}.) ".format(key, file))
            return False
        else:
            with open(file, 'r') as csvfile:
                reader = csv.reader(csvfile)
                rows = {rows[0]:rows[1] for rows in reader}
                return rows
