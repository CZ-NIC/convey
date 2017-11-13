import ipdb

class Cancelled(Exception):
    pass

class Debugged(Exception):
    pass


class Dialogue:
    def isYes(text):
        return Dialogue.ask(text = text + " [y]/n: ").lower() in ("y", "yes", "")

    def ask(text=None):
        txt = input(text) if text else input()
        if txt == "x":
            raise Cancelled(".. cancelled")
        if txt == "debug":
            raise Debugged("lets debug")
            #ipdb.set_trace()
        return txt

    def askNumber(text, default=None):
        """
        Let user write number. Empty input = 0.
        """
        while True:
            try:
                t = Dialogue.ask(text=text)
                if not t:
                    t = default or 0
                return int(t)
            except ValueError:
                print("This is not a number")

    def tupled_menu(menu, title = None, repeat=False):
        """ menu of tuples [(key, title, f), ("1", "First option", lambda), ...] """
        while True:
            if title:
                print("\n" + title)
            for key, name, f in menu:
                if key is None:
                    print("~) {}".format(name))
                else:
                    print("{}) {}".format(key, name))
            ans = input("? ")
            print()
            if ans == "x" and repeat:
                return
            elif ans == "debug":
                import ipdb; ipdb.set_trace()
            for key, name, f in menu:
                if key == ans and f:
                    f()
                    if not repeat:
                        return True
                    else:
                        break
            else:
                print("Not valid option")



    def pickOption(options, guesses=[], colName=""):
        """ Loop all options
         guesses = list of columns that should be highlighted
         returns option number OR None
        """
        cols = []
        for i, fieldname in enumerate(options):# print columns
            if fieldname in guesses:
                guesses.remove(fieldname)
                cols.append(i)
                print("* {}. {} *".format(i + 1, fieldname))
            else:
                print("{}. {}".format(i + 1, fieldname))
        default = cols[0] if (len(cols) == 1) else None # XX defaulting now doesnt work at all
        colI = Dialogue.askNumber(colName + " column: ", default) - 1

        if colI == -1:
            raise Cancelled(".. no column chosen")
        if colI > len(options):
            print("Not found")
            return Dialogue.pickOption(options, guesses, colName)

        return colI
