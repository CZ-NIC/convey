# spojeni s konfiguracnim souborem
# To change this template file, choose Tools | Templates
# and open the template in the editor.
import configparser

class Config:
    config = configparser.ConfigParser()
    config.read('config.ini')

    def get(key):
        return Config.config['CONVEY'][key]