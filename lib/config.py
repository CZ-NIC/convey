# Env config file connection
import configparser

class Config:
    file = 'config.ini'
    #cache = {}
    config = configparser.ConfigParser()
    config.read(file)
    #tempCache = {}

    # set by SourceParser and used by Registry
    hasHeader = False
    header = ""


    def errorCatched():
        if Config.isDebug():
            import ipdb; import traceback; import sys                                    
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            if tb:
                ipdb.post_mortem(tb)
            else:
                print("Lets debug. Hit n to get to the previous scope.")
                ipdb.set_trace()            

    def isDebug():
        return True if Config.get('debug') == "True" else False

    def isTesting():
        return True if Config.get('testing') == "True" else False

    def get(key, section = 'CONVEY'):
        #if key not in Config.cache:
        #    Config.cache[key] = Config.config[section][key]
        #return Config.cache[key]
        return Config.config[section][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY',key)

    #def setTemp(key,val):
    #    Config.tempCache[key] = val
    
    #def set(key, val):
    #    Config.config.set('CONVEY',key,val)
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

Config.method = Config.get("method") # quick access to the property
Config.redo_invalids = Config.get("redo_invalids") # quick access to the property