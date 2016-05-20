import ipdb

class Cancelled(Exception):
    pass

class Dialogue:
    def isYes(text):
        return Dialogue.ask(text = text + " [y]/n: ").lower() in ("y", "yes", "")

    def ask(text = None):
        txt = input(text) if text else input()
        if txt == "x":
            raise Cancelled("CANCEL - DOES THIS WORK?? XX JAK UDELAT CUSTOM EXCEPTION?")
        if txt == "debug":
            ipdb.set_trace()
        return txt

    def askNumber(text):
        """
        Let user write number. Empty input = 0.
        """
        while True:
            try:
                t = Dialogue.ask(text=text)
                if not t:
                    t = 0
                return int(t)
            except ValueError:
                print("This is not a number")                
