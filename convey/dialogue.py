import string

from dialog import Dialog, ExecutableNotFound

from .config import Config

try:
    dialog = Dialog(autowidgetsize=True)
except ExecutableNotFound:
    print("\nError importing dialog library. Try installing: `sudo apt install dialog`.")
    quit()


# monkey patch Dialog class so that it skips the dialog in case there is a single value
def skippable_menu(self, *args, skippable=True, **kwargs):
    """
    :param self: Dialog
    :type skippable: bool If True and there is single option, the dialog returns 'Ok' without asking user.
    """
    if skippable and kwargs["choices"] and len(kwargs["choices"]) == 1:
        return "ok", kwargs["choices"][0][0]
    return self.menu(*args, **kwargs)


Dialog.skippable_menu = skippable_menu


class Cancelled(Exception):
    pass


class Debugged(Exception):
    pass


def pick_option(options, title="", guesses=[], skippable=True):
    """ Loop all options
        options tuples of items and descriptions: [("url", "this is url")]
        guesses = indices of options that should be highlighted
        returns option number OR raises Cancelled

        :type skippable: bool If True and there is single option, the dialog returns 'Ok' without asking user.
    """

    # convert numbers `0-8` → `1-9` and `9-...` → `a-...` and then back to number
    abc = string.ascii_lowercase
    i_to_abc = lambda i: abc[i + 1 - 10] if (i + 1 >= 10 and i + 1 - 10 < len(abc)) else i + 1
    abc_to_i = lambda s: int(s) - 1 if s.isdigit() else abc.index(s) + 10 - 1

    choices = []
    if guesses:
        # X SORTED GUESSES:
        opts = [it for it in enumerate(options)]
        for g in guesses:
            if g < len(opts):
                choices.append((f"{i_to_abc(g)} * {opts[g][1][0]} *", str(opts[g][1][1])))

    if not len(guesses) == len(options):  # if every column highlighted, no need to list them all just again
        if guesses:
            title += "\n\nAutomatically detected fields on the top"
            choices.append(("-", "-----"))
        for i, (field_name, desc) in enumerate(options):
            choices.append((f"{i_to_abc(i)} {field_name}", str(desc)))

    code, col_i = dialog.skippable_menu(title or " ", choices=choices, skippable=skippable)
    if col_i == '-':
        return pick_option(options, title, guesses, skippable)
    if code != "ok":
        raise Cancelled(".. no column chosen")
    col_i = col_i.split(" ")[0]
    return abc_to_i(col_i)


def ask_number(text):
    """
    Let user write number. Empty input = 0.
    """
    while True:
        try:
            t = ask(text=text)
            if not t:
                return 0
            return int(t)
        except ValueError:
            print("This is not a number")


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


def is_yes(text):
    if Config.get("yes", get=bool):
        return True
    if Config.get("daemon", get=bool):
        raise ConnectionAbortedError
    return ask(text=text + " [y]/n: ").lower() in ("y", "yes", "")


def is_no(text):
    if Config.get("yes", get=bool):
        return True
    if Config.get("daemon", get=bool):
        raise ConnectionAbortedError
    return ask(text=text + " y/[n]: ").lower() in ("n", "no", "")


class Menu:
    def __init__(self, title=None, callbacks=True, fullscreen=False, skippable=True):
        """ self.menu of tuples [(key, title, f), ("1", "First option", lambda), ...]
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
        """ Add new item to the menu.

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
                    code, ans = dialog.skippable_menu(self.title, choices=[(it[0], it[1]) for it in l], skippable=self.skippable)
                    if code != "ok":
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
