from dialog import Dialog, ExecutableNotFound

try:
    dialog = Dialog(autowidgetsize=True)
except ExecutableNotFound:
    print("\nError importing dialog library. Try installing: `sudo apt install dialog`.")
    quit()



class Cancelled(Exception):
    pass


class Debugged(Exception):
    pass


class Dialogue:
    def isYes(text):
        return Dialogue.ask(text=text + " [y]/n: ").lower() in ("y", "yes", "")

    def ask(text=None):
        try:
            txt = input(text + " ") if text else input()
        except EOFError:
            txt = "x"
        if txt == "x":
            raise Cancelled(".. cancelled")
        if txt == "debug":
            raise Debugged("lets debug")
            # ipdb.set_trace()
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

    def pickOption(options, title="", guesses=[]):
        """ Loop all options
            options tuples of items and descriptions: [("url", "this is url")]
            guesses = indices of options that should be highlighted
            returns option number OR None
        """
        choices = []
        if guesses:
            # X SORTED GUESSES:
            opts = [it for it in enumerate(options)]
            for g in guesses:
                if g < len(opts):
                    choices.append(("{} * {} *".format(g + 1, opts[g][1][0]), opts[g][1][1]))

            # for i, (fieldname, desc) in enumerate(options):# print columns
            #    if i in guesses:
            #        choices.append(("{} * {} *".format(i + 1, fieldname), desc))

        if not len(guesses) == len(options):  # if every column highlighted, no need to list them all just again
            if guesses:
                title += "\n\nAutomatically detected fields on the top"
                choices.append(("-", "-----"))
            for i, (fieldname, desc) in enumerate(options):
                choices.append(("{} {}".format(i + 1, fieldname), desc))

        code, colI = dialog.menu(title or " ", choices=choices)
        if code != "ok":
            raise Cancelled(".. no column chosen")

        colI = colI.split(" ")[0]
        # colI = Dialogue.askNumber(colName + " column: ") - 1

        """if colI == -1:
            if guesses: # default value
                return guesses[0]
            raise Cancelled(".. no column chosen")
        if colI > len(options):
            print("Not found")
            return Dialogue.pickOption(options, guesses, colName)
        """

        return int(colI) - 1


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
        # if key is False or not fn:
        #    key = None
        # elif key is None:
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
                    code, ans = dialog.menu(self.title, choices=[(it[0], it[1]) for it in l])
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
                    import ipdb;
                    ipdb.set_trace()
                    return
                print("Invalid option")
