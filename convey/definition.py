from csv import Dialect
from sys import version_info
from typing import Callable, Dict, TYPE_CHECKING, List, Optional, Tuple, Union, TypedDict

from .action import AggregateAction, MergeAction
from .field import Field

Unique = Optional[List[int]]
Filter = Optional[List[Tuple[bool, int, str]]]

class Settings(TypedDict):
    # XX Convert more to Actions, get rid of complex fields

    add: Optional[List[Field]]
    """  XX handle this old doc
            "add": new_field:Field,
                source_col_i:int - number of field to compute from,
                fitting_type:Field - possible type of source ,
                custom:tuple - If target is a 'custom' field, we'll receive a tuple (module path, method name).
    """
    aggregate: Optional[AggregateAction]
    dialect: Dialect
    "always present (set in controller just after parser.prepare()), output CSV dialect"
    filter: Filter
    merge: Optional[List[MergeAction]]
    split: Optional[int]
    unique: Unique
    header: Optional[bool]
    """ True if input CSV has header and output CSV should have it too.
        False if either input CSV has not header or the output CSV should omit it."""

    # used and set only in Processor
    addByMethod: Optional[List[Tuple[str, int, List[Callable]]]]
    f_pre: Filter
    f_post: Filter
    target_file: Union[None, int, str]
    u_pre: Unique
    u_post: Unique
    merging: Optional[bool]
