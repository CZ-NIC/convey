import dateutil

from convey import PickInput
from convey import PickMethod

def dumb_method(val):
    """ This is a dumb testing method """
    return f"-{val}-"

def list_method(arg):
    """ This external type returns a list. The lines should be duplicated. """
    return [arg + "-1", arg + "-2"]


@PickInput
def time_format(val, format_="%H:%M"):
    """ This text will be displayed to the user.
        If running in headless mode, the default format will be "%H:%M" (hours:minutes).   """
    return dateutil.parser.parse(val).strftime(format_)


@PickMethod("all")
class PickMethodTest(PickMethod):
    @staticmethod
    def all(x):
        """ All of them.  """
        return x

    @classmethod
    def filtered(cls, x):
        """ Filter some of them """
        if x in ["a", "b", "c"]:
            return x
