# Source file choice
import os.path
import sys
import configparser
from lib.config import Config
import tkinter as tk
from tkinter.filedialog import askopenfilename

__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Mar 23, 2015 10:36:35 PM$"

def SourcePicker():
     
    file = ""
    if (len(sys.argv) > 1) and (sys.argv[-1] != ""):
        file = sys.argv[-1]
    else:
        try: # path not set in command line, let's crawl default dir
            dirDefault = Config.get('default_dir')
            dirs = os.listdir(dirDefault)
            print("Source log filepath not set in command line. In which directory should I search?")
            while True:
                i = 1
                if dirs != "":
                    for dir in dirs:
                        print(str(i) + ". " + dir)
                        i += 1
                print("0. Set another path")
                print("x. End")
                sys.stdout.write("? ")
                sys.stdout.flush()

                option = input()
                if option == "x":
                    quit()
                elif option == "0": # we'll set file name afterwards
                    break
                else: # crawlujeme a dir to find filename with known name
                    dir = dirDefault + dirs[int(option)-1] + "/"
                    for fileD in Config.get('default_file').split(","):
                        if os.path.isfile(dir + fileD):
                            file = dir + fileD
                            break
                    if file == "":
                        print("There is not any default log file in that directory: " + Config.get('default_file'))
                    else:
                        break # repeat dir choice
        except FileNotFoundError as e: # favourite dir does not exist
            print("Couldn't load from config.ini directory default_dir {}".format(Config.get('default_dir')))
            pass # let's set the path manually


    if file == "":
        print("Set path to the source log file.")
        sys.stdout.write("? ")
        sys.stdout.flush()
        #file = input() without GUI variant
        root = tk.Tk()
        root.withdraw() # show askopenfilename dialog without the Tkinter window
        file = askopenfilename() # default is all file types
        print(file)


    # open source file path
    try:
        if not os.path.isfile(file):
            print("File {} not found.".format(file))
            quit()
    except TypeError:
        print("File not found, quit.")
        quit()

    return file