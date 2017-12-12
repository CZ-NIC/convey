import ipdb
from dialog import Dialog
dialog = Dialog()

class Cancelled(Exception):
    pass

class Debugged(Exception):
    pass


class Dialogue:
    def isYes(text):
        return Dialogue.ask(text = text + " [y]/n: ").lower() in ("y", "yes", "")

    def ask(text=None):
        try:
            txt = input(text) if text else input()
        except EOFError:
            txt = "x"
        if txt == "x":
            raise Cancelled(".. cancelled")
        if txt == "debug":
            raise Debugged("lets debug")
            #ipdb.set_trace()
        return txt

    def askNumber(text):
        """
        Let user write number. Empty input = 0.
        """
        while True:
            try:
                t = Dialogue.ask(text=text)
                if not t:
                    return 0
                return int(t)
            except ValueError:
                print("This is not a number")

    def pickOption(options, colName="", guesses=[]):
        """ Loop all options
         guesses = indices of options that should be highlighted
         returns option number OR None
        """
        for i, fieldname in enumerate(options):# print columns
            if i in guesses:
                print("* {}. {} *".format(i + 1, fieldname))
            else:
                print("{}. {}".format(i + 1, fieldname))
        colI = Dialogue.askNumber(colName + " column: ") - 1

        if colI == -1:
            if guesses: # default value
                return guesses[0]
            raise Cancelled(".. no column chosen")
        if colI > len(options):
            print("Not found")
            return Dialogue.pickOption(options, guesses, colName)

        return colI


class Menu:
    def __init__(self, title=None, callbacks=True, fullscreen=False):
        """ self.menu of tuples [(key, title, f), ("1", "First option", lambda), ...] """
        self.title = title
        self.menu = []
        self.callbacks = callbacks
        self._keyCount = 0
        self.fullscreen = fullscreen


    def add(self, title, fn=None, key=None):
        """ Add new item to the menu.

            key - available through this letter
                - if no key set, it will be available through the add order number
                - if False, not available

            """
        #if key is False or not fn:
        #    key = None
        #elif key is None:
        #    key = str(len(self.menu))
        if key is None:
            self._keyCount += 1
            key = str(self._keyCount)
        self.menu.append((str(key), title, fn))

    def sout(self):
        while True:
            if self.title:
                print("\n" + self.title)
            l = []
            for key, name, f in self.menu:
                if key is False or (self.callbacks and not f):
                    l.append(("~", name, False))
                    print("~) {}".format(name))
                    continue
                l.append((key, name, False))
                print("{}) {}".format(key, name))
            try:
                if self.fullscreen:
                    code, ans = dialog.radiolist(self.title, choices=l)
                    if code != "ok":
                        return
                else:
                    ans = input("? ")
            except EOFError:
                ans = "x"
            print()
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
                    import ipdb; ipdb.set_trace()
                print("Not valid option")
