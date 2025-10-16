import csv
import logging

from mininterface import Mininterface
from mininterface.exceptions import Cancelled

from .config import Config

logger = logging.getLogger(__name__)
m: Mininterface


def init_global_interface(interf):
    global m
    # For the global is_yes etc, we prefer a TextInterface,
    # so that text printed in the console is visible – Textual would hide it
    #
    # Alongside, there is prompt toolkit that we need to dynamic UI actions
    # (like del for deleting a column) which is something mininterface does not support.
    #
    # In the future, these might be unified into the single `controller.m` interface.
    # Make mininterface textual keep the console text.
    m = interf


class Debugged(Exception):
    pass


def is_yes(text):
    if Config.get_env().cli.yes:
        return True
    if Config.get_env().process.daemon:
        raise ConnectionAbortedError
    return m.confirm(text)


def is_no(text):
    if Config.get_env().cli.yes:
        return True
    if Config.get_env().process.daemon:
        raise ConnectionAbortedError
    return m.confirm(text, False)


def hit_any_key(text: str):
    """Display text and let the user hit any key. Skip when headless."""
    if Config.get_env().cli.yes:
        logger.info(text)
        return
    m.alert(text)
    return


class Menu:
    def __init__(self, title=None, callbacks=True, fullscreen=False, skippable=True):
        """self.menu of tuples [(key, title, f), ("1", "First option", lambda), ...]
        :type skippable: bool If True and there is single option, the dialog returns 'Ok' without asking user.
        """
        self.title = title
        self.menu = []
        self.callbacks = callbacks
        self.skippable = skippable
        self._keyCount = 0
        self.fullscreen = fullscreen
        self.default = None

    def add(self, title, fn=None, key=None, default=False):
        """Add new item to the menu.

        key - available through this letter
            - if no key set, it will be available through the add order number
            - if False, not available

        default - If user hits enter, the last item with default=True will be triggered.

        """
        if default:
            self.default = key
            title += " ←←←←←"
        if key is None:
            self._keyCount += 1
            key = str(self._keyCount)
        self.menu.append((str(key), title, fn))

    def sout(self, session=None, options={}):
        while True:
            if self.title:
                print("\n" + self.title)
            l = []
            if len(self.menu) == 0:
                input("No possible choices. Continue...")
                return
            for key, name, f in self.menu:
                if key is False or (self.callbacks and not f):
                    l.append(("~", name, False))
                    print("~) {}".format(name))
                    continue
                l.append((key, name, False))
                print("{}) {}".format(key, name))
            try:
                if self.fullscreen:
                    try:
                        ans = m.select(
                            {(it[0], it[1]): it[0] for it in l},
                            self.title,
                            skippable=self.skippable,
                        )
                    except Cancelled:
                        return
                elif session:
                    ans = session.prompt("? ", **options)
                    if ans == "refresh":
                        return
                else:
                    ans = input("? ")
            except EOFError:
                ans = "x"
            print()
            if ans == "" and self.default:
                ans = self.default
            for key, name, f in self.menu:
                if key == ans:
                    if self.callbacks:
                        if not f:
                            continue
                        f()
                        return True
                    else:
                        return key

            else:
                if ans == "x":
                    return
                elif ans == "debug":
                    Config.get_debugger().set_trace()
                    return
                print("Invalid option")


def csv_split(val):
    """Sometimes ",".split is not enough, they can use quotes and commas in our mighty CLI."""
    return list(csv.reader([val]))[0]
