# spojeni s konfiguracnim souborem
# To change this template file, choose Tools | Templates
# and open the template in the editor.
import configparser

class Config:
    file = 'config.ini'
    config = configparser.ConfigParser()
    config.read(file)

    def get(key):
        return Config.config['CONVEY'][key]

    def getboolean(key):
        return Config.config.getboolean('CONVEY',key)

    #X Zabije komentaredef set(key, val):
        #Config.config.set('CONVEY',key,val)
        #with open(Config.file,"w") as f:
            #Config.config.write(f)
    cacheDir = ""
    def setCacheDir(dir):
        Config.cacheDir = dir

    def getCacheDir():
        return Config.cacheDir
            