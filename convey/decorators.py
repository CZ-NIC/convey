# Note: as this file is loaded before config.py initializing logging, we cannot use logger here
from abc import ABC, abstractmethod
from typing import Callable


class PickBase(ABC):
    default = None
    subtype: Callable

    @abstractmethod
    def get_lambda(self): pass

    def get_type_description(self):
        return self.subtype.__doc__.strip()


class PickMethod(PickBase):
    """ If you need to ask a question before computing values,
    make a class with methods that will be considered as options.
    User will be asked what computing option they tend to use,
    whilst the description is taken directly from the methods' __doc__ string.
    Than decorate with @PickMethod with optional default:str parameter that points to the default method.

     Ex: A user should be asked if a generator should return every value or perform a filtering.

     @PickMethod("all")
     class MyValues():
        ''' description shown in help '''

        def all(x):
            ''' return every value (this very text will be displayed to the user) '''
            return x

        def filtered(cls, x):
            ''' return only specific values '''
            if x in my_set:
                return x
    """

    def get_lambda(self, custom=None):
        if custom is None:
            custom = self.default
        for name in self._get_options():
            if name == custom:
                return getattr(self.subtype, name)
        else:
            raise NotImplementedError(f"Option {custom} has not been implemented for {self.subtype}, only {self._get_options()}.")

    def get_options(self):
        """ Return generator of options name and description tuples """
        return ((name, getattr(self.subtype, name).__doc__.strip()) for name in self._get_options())

    def _get_options(self):
        return (name for name in self.subtype.__dict__ if not name.startswith("_"))

    def __init__(self, default: str = None):
        self.default = default

    def __call__(self, subtype):
        self.subtype = subtype
        return self


class PickInput(PickBase):
    """ If your external function need to be setup with a variable first,
     decorate with @PickInput and register a function having two parameters. The second may have a default value.

    In this example, we let the user decide what should be the value of `format` before processing.
    All values will be formatted with the same pattern.

    @PickInput
    def time_format(val, format="%H:%i"):
        ''' this text will be displayed to the user '''
        return dateutil.parser.parse(val).strftime(format)

    """

    def get_lambda(self, custom=None):
        if custom:
            return lambda x: self.subtype(x, custom)
        else:
            return lambda x: self.subtype(x)

    def __init__(self, subtype):
        # since it takes about 5 ms and this is loaded directly from __init__.py, we postpone the loading here
        # another solution would be to implement a lazy loading from __init__.py:all
        import inspect
        self.subtype = subtype
        par = list(inspect.signature(subtype).parameters)
        if len(par) != 2:
            raise RuntimeError(f"Cannot import {subtype.__name__}, it has not got two parameters.")
        p = inspect.signature(subtype).parameters[par[1]]
        self.default = None if p.default is p.empty else p.default
        self.description = subtype.__doc__ or (f"Input {subtype.__name__} variable " + par[1])
        self.parameter_name = par[1]
