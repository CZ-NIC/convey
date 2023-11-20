from __future__ import annotations
from collections import defaultdict
import csv
from pathlib import Path
from typing import TYPE_CHECKING, DefaultDict, Dict, List, Optional, Tuple, Union

from attrs import define

from .aggregate import Aggregate, AggregateMethod

if TYPE_CHECKING:
    from .field import Field
    from .parser import Parser

AggregationGroupedRows = DefaultDict[Optional[int], List[Aggregate]]

# XX we should convert whole parser.settings to Action subclasses


class Action:
    """ A processing operation. """
    pass


Pivot = str
"Common value in both local and remote columns"


@define
class MergeAction(Action):
    local_column: Field
    rows: Dict[Pivot, List[Union[List[str], Expandable]]]
    remote_parser: Parser

    def get(self, key):
        """ Get the rows containing the key.
        If those do not exist, made up a row full of empty values
        (thanks to the Expandable helper class)
        so that the dimension of the CSV file will not change.
        """
        # Even though rows return list (for an existing key), cast them
        # to list once again. When processing, the duplication mechanism
        # at line `fields[i] *= row_count // len(fields[i])`
        # would duplicate the very list itself (and test_merge would fail)
        # which would result in exponencially bigger line count.
        return list(self.rows.get(key, ())) or [Expandable(("",) * len(self.remote_parser.fields))]

    @classmethod
    def build(cls, remote_file: Path, remote_parser: Parser, remote_column: Field, local_column: Field):
        """ Cache remote values and return a new instance """
        rows = defaultdict(list)
        with remote_file.open() as f:
            reader = csv.reader(f, dialect=remote_parser.dialect)
            for row in reader:
                if not row:  # skip blank
                    continue
                # {'foo': [Expandable(['john@example.com', 'foo']), Expandable(['mary@example.com', 'foo'])],
                # 'bar': [Expandable(['hyacint@example.com', 'bar'])]})
                rows[row[remote_column.col_i]].append(Expandable(row))

        # convert

        return cls(local_column, rows, remote_parser)


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


@define
class AggregateAction(Action):
    """
        settings["aggregate"] = column to be grouped, [(sum, column to be summed)]
        Ex: settings["aggregate"] = 1, [(Aggregate.sum, 2), (Aggregate.avg, 3)]
        Ex: settings["aggregate"] = 0, [(Aggregate.count, 0)]
        Ex: settings["aggregate"] = None, [(Aggregate.sum, 1)]
        Ex: settings["aggregate"] = None, [(Aggregate.sum, 1), (Aggregate.avg, 1)]
        """
    group_by: Optional[Field]
    "column to be grouped by"

    actions: List[Tuple[AggregateMethod, Field]]
    "[(Aggregate.sum, column to be summed), ...]"
