# Env config file connection
import configparser

class Config:
    file = 'config.ini'
    config = configparser.ConfigParser()
    config.read(file)
    #tempCache = {}

    def isDebug():
        return True if Config.get('debug') == "True" else False

    def get(key):
        return Config.config['CONVEY'][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY',key)

    #def setTemp(key,val):
    #    Config.tempCache[key] = val
    #X Can't update, it would kill comments in config.ini :(
    #def set(key, val):
        #Config.config.set('CONVEY',key,val)
        #with open(Config.file,"w") as f:
            #Config.config.write(f)
    cacheDir = ""
    def setCacheDir(dir):
        Config.cacheDir = dir

    def getCacheDir():
        return Config.cacheDir
            