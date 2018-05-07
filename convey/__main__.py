#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

try:
    from dialog import Dialog
    # import networkx as nx ## networkx - XX if implemented without networkx, we may suppress the dependency (2 MB)
except ImportError:
    print("\nError importing dialog library. Try installing: `sudo apt install dialog`.")
    quit()
from .controller import Controller

__shortdoc__ = """ Convey - CSV swiss knife brought by CSIRT.cz """
# with open("README.md", "r") as f:
#    __doc__ = f.read()
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"


import logging
fileHandler = logging.FileHandler("convey.log")
fileHandler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
fileHandler.setLevel(logging.WARNING)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
consoleHandler.setLevel(logging.WARNING)
handlers = [fileHandler, consoleHandler]
logging.basicConfig(level=logging.INFO, handlers=handlers)
logger = logging.getLogger("convey")

logging.getLogger("lepl").setLevel(logging.ERROR)  # suppress a superfluous info when using lepl e-mail validator


def main():
    print(__shortdoc__),
    try:
        Controller()
    except KeyboardInterrupt:
        print("Interrupted")
    except SystemExit as e:
        pass
    except:
        import traceback

        try:
            import pudb as mod
        except ImportError:
            try:
                import ipdb as mod
            except ImportError:
                import pdb as mod
        type, value, tb = sys.exc_info()
        traceback.print_exc()
        mod.post_mortem(tb)


if __name__ == "__main__":
    main()