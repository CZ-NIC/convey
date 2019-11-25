import logging
import os

from .decorators import PickMethod, PickInput

# setup logging
handlers = []
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))
console_handler.setLevel(logging.INFO)
handlers.append(console_handler)
try:
    file_handler = logging.FileHandler("convey.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    file_handler.setLevel(logging.WARNING)
    handlers.append(file_handler)
except PermissionError:
    file_handler = None
    print("Cannot create convey.log here at " + str(os.path.abspath(".")) + " – change directory please.")
    quit()
except FileNotFoundError:  # FileNotFoundError emitted when we are in a directory whose inode exists no more
    print("Current working directory doesn't exist.")
    quit()
logging.basicConfig(level=logging.INFO, handlers=handlers)

__all__ = [PickMethod, PickInput]
