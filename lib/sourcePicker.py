# Vyber zdrojoveho souboru
import os.path
import sys
import configparser

__author__ = "edvard"
__date__ = "$Mar 23, 2015 10:36:35 PM$"

def SourcePicker():
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    file = ""
    if (len(sys.argv) > 1) and (sys.argv[1] != ""):
        file = sys.argv[1]
    else:# cesta v prikazove radce nezadana, zkusime default dir

        dirDefault = config['CONVEY']['default_dir'] # zkousime crawlovat oblibeny adresar
        try:
            dirs = os.listdir(dirDefault)
            print("Cesta k souboru s logy nebyla zadána v příkazové řádce. V kterém adresáři ho mám hledat?")
            while True:
                i = 1
                if dirs != "":
                    for dir in dirs:
                        print(str(i) + ". " + dir)
                        i += 1
                print("0. Zadat jinou cestu")
                print("x. Konec")
                sys.stdout.write("? ")
                sys.stdout.flush()

                option = input()
                if option == "x": # skoncit program
                    quit()
                elif option == "0": # zadame pozdeji primo jmeno souboru
                    break
                else: # crawlujeme nejaky adresar, zda se tam nachazi soubor povedomeho nazvu
                    dir = dirDefault + dirs[int(option)-1] + "/"
                    for fileD in config['CONVEY']['default_file'].split(","):
                        if os.path.isfile(dir + fileD):
                            file = dir + fileD
                            break
                    if file == "":
                        print("V tomto adresáři se nevyskytuje žádný z defaultních souborů s logy: " + config['CONVEY']['default_file'])
                    else:
                        break #opakovat volbu adresáře
        except FileNotFoundError as e: #oblibeny adresar neexistuje
            print("Z config.ini se nepovedlo načíst adresář default_dir {}".format(config['CONVEY']['default_dir']))
            pass #budeme muset zadat soubor rucne


    if file == "":
        print("Zadejte cestu k zdrojovému souboru s logy.")
        sys.stdout.write("? ")
        sys.stdout.flush()
        file = input()

    # overit cestu ke zdrojovemu souboru
    if os.path.isfile(file):
        print("Zdrojový soubor nalezen.")
    else:
        print("Soubor {} nenalezen.".format(file))
        quit()

    return file