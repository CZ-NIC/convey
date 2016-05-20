# Env config file connection
import configparser
import ipdb

class Config:
    file = 'config.ini'
    config = configparser.ConfigParser()
    config.read(file)
    #tempCache = {}

    def errorCatched():
        if Config.isDebug():
            ipdb.set_trace()

    def isDebug():
        return True if Config.get('debug') == "True" else False

    def isTesting():
        return True if Config.get('testing') == "True" else False

    def get(key, section = 'CONVEY'):
        return Config.config[section][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY',key)

    #def setTemp(key,val):
    #    Config.tempCache[key] = val
    
    def set(key, val):
        Config.config.set('CONVEY',key,val)
        # Can't update the file now, it would kill comments in config.ini :(
        # And I dont want to can do the update because Whois may set whois_mirror value and this change is meant to be temporary only (for the single run of program)
        #with open(Config.file,"w") as f:
            #Config.config.write(f)
    cacheDir = ""
    def setCacheDir(dir):
        Config.cacheDir = dir

    def getCacheDir():
        """ Cache dir with ending slash. """
        return Config.cacheDir
            