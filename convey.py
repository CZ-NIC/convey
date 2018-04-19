#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import traceback
import sys
try:
    from dialog import Dialog
    #import networkx as nx ## networkx - XX if implemented without networkx, we may suppress the dependency (2 MB)
except ImportError:
    traceback.print_exc()
    print("\nTry installing the libraries by install.sh")
    quit()
from lib.controller import Controller
__shortdoc__ = """ Convey - CSV swiss knife brought by CSIRT.cz """
#with open("README.md", "r") as f:
#    __doc__ = f.read()
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"
import logging
logging.basicConfig(level=logging.DEBUG, filename="convey.log", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


if __name__ == "__main__":
    print(__shortdoc__),

    #command line flags - it controls the program flow; parameters --id, --ticket, --cookie --token --attachment_name
    #if set(["-h", "--help", "-?", "?", "/?"]).intersection(sys.argv):
    #    print(__doc__)
    #    quit()

    # XX parseargs
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