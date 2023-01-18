from __future__ import annotations
import csv
from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING, Callable, List, Optional, Type

from attrs import define, asdict, field
from difflib import SequenceMatcher

if TYPE_CHECKING:
    from .field import Field
    from .parser import Parser

logger = logging.getLogger(__name__)


@dataclass
class BareField:
    """ This will become a Field once the parser is ready.
    Note: This cannot be an attrs class because it would be converted to dict by FlagController.read too early.
    """
    task: str


def Column(): return field(converter=lambda x: BareField(x) if x is not None else None, default=None)
def Path(): return field(default=None)


class FlagController:
    def __init__(self, parser: Parser):
        self.parser = parser

    def read(self, flag_type: Type[Flag], val: str):
        """ Sometimes ",".split is not enough, they can use quotes and commas in our mighty CLI.
        Besides, we convert user's will to specific Field.
        Ex: `--merge gif.csv,2` ->  MergeFlag(gif.csv, 2) -> {remote_path: gif.csv, remote_col_i: Field(col_i=2)}
        """
        flag = asdict(flag_type(*next(csv.reader([val]))))

        # post processing
        for k, v in flag.items():
            if isinstance(v, BareField):  # convert BareField to Field, we have the parser now
                flag[k] = self.parser.identifier.get_column_i(v.task, check=True)
        return flag


# XX we should convert more flags to adapt Flag
class Flag:
    """ Flag convert CLI input to an Action """
    pass


@define
class MergeFlag(Flag):
    remote_path = Path()
    remote_col_i = Column()
    local_col_i = Column()
