#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

from .controller import Controller

__doc__ = """Convey – CSV swiss knife brought by CSIRT.cz"""
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
    print(__doc__)
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
