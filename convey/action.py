from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional

from attrs import define, asdict, field

if TYPE_CHECKING:
    from .field import Field
    from .parser import Parser

# XX we should convert whole parser.settings to Action subclasses
class Action:
    """ A processing operation. """
    pass


@define
class MergeAction(Action):
    local_column: Field
    rows: List[List[str]]
    remote_parser: Parser

    def get(self, key):
        """ Get the rows containing the key.
        If those do not exist, made up a row full of empty values
        so that the dimention of the CSV file will not change.
        """
        return self.rows.get(key) or [Expandable(("",) * len(self.remote_parser.fields))]


class Expandable(list):
    """ A helper class. While merging, multiple columns should be added at once the CSV.
    However, as the pivot value might appear multiple times in the remote file,
    we might want to duplicate the line.
    This class exist to split the columns later, when the line is safely duplicated.
    """
    pass

    @classmethod
    def flatten(cls, xs):
        """ Flatten flattenable elements in an iterable
            https://stackoverflow.com/a/2158532/2036148
            (1, Expandable([2,3])) -> (1, 2, 3)
        """
        for x in xs:
            if isinstance(x, cls):
                yield from cls.flatten(x)
            else:
                yield x
