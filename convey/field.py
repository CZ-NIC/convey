from __future__ import annotations
from bdb import BdbQuit
from math import inf
from typing import TYPE_CHECKING, List, Optional, Union

from .config import Config
from .action import MergeAction
from .types import Type, Types
from .whois import Quota, UnknownValue

if TYPE_CHECKING:
    from .parser import Parser

Cell = Union[str, List[str]]
"""Even though standard fields in the CSV are of type str, while computing new columns,
    these might generate a list. Such list is immediately split to multiple lines while processing,
    but not when previewing the CSV table before the processing starts.
    """


class Field:
    def __init__(self, name, is_chosen=True, source_field: Optional[Field] = None, source_type=None, new_custom=None,
                 merged_from: Optional[Field] = None, merge_operation: Optional[MergeAction] = None):
        self.col_i = None
        "index of the field in parser.fields"
        self.col_i_original = None
        "original index before any sorting"
        self.parser: Optional[Parser] = None
        self.name = str(name)
        self.is_chosen = is_chosen
        self.is_selected = False
        self.merged_from = merged_from
        self.merge_operation = merge_operation
        "This field is merged from a remote file"
        self.possible_types = {}
        if isinstance(name, Type):
            self.type = name
        else:
            self.type = None
        self.is_new = False
        if source_field:
            self.is_new = True
            self.source_field = source_field
            self.source_type = source_type if type(source_type) is Type else getattr(Types, source_type)
            self.new_custom = new_custom
        else:
            self.source_field = self.source_type = self.new_custom = None

    def __repr__(self):
        return f"<Field {self.name}({self.type})>"

    def set_parser(self, parser):
        self.parser = parser

    def move(self, direction=0):
        """ direction = +1 right, -1 left """
        p = self.parser
        i, i2 = self.col_i, (self.col_i + direction) % len(p.fields)
        p.fields[i2].col_i, self.col_i = i, i2

        def swap(i, i2):
            """ Swap given iterable elements on the positions i and i2 """

            def _(it):
                it[i], it[i2] = it[i2], it[i]

            return _

        transposed = list(zip(*p.sample_parsed))
        list(map(swap(i, i2), [p.fields, transposed]))
        p.sample_parsed = list(map(list, zip(*transposed)))

    def toggle_chosen(self):
        self.is_chosen = not self.is_chosen

    @property
    def type(self):
        if self._type:
            return self._type
        if self.possible_types:
            return next(iter(self.possible_types))

    @type.setter
    def type(self, val):
        self._type = val
        if val:
            # for all not newly-added fields,
            # self.possible_types are re-build in identifier.identify_fields
            self.possible_types[val] = 100

    def color(self, v, shorten=False, line_chosen=True):
        """ Colorize single line of a value. Strikes it if field is not chosen. """
        v = str(v)  # ex: Types.http_status returns int
        if shorten:
            v = v[:17] + "..." if len(v) > 20 else v
        l = []
        if not self.is_chosen or not line_chosen:
            l.append("9")  # strike
        if self.is_selected:
            l.append("7")  # bold
        if self.is_new:
            l.append("33")  # yellow
        elif self.type is None or self.type == Types.plaintext:
            l.append("36")  # blue
        else:
            l.append("32")  # green
        s = "\033[" + ";".join(l) + f"m{v}\033[0m"
        return s

    def get(self, long=False, color=True, line_chosen=True):
        s = ""
        if long:
            if self.is_new:
                s = f"{self.name} from:\n{self.source_field}"
            elif self.has_clear_type():
                s = f"{self.name}\n   ({self.type})"
        if not s:
            s = self.name
        if color:
            s = "\n".join((self.color(c, line_chosen=line_chosen) for c in s.split("\n")))
        return s

    def has_clear_type(self):
        return self.type is not None and self.type != Types.plaintext

    def get_methods(self, target=None, start=None):
        if start is None:
            start = self.source_type
        if target is None:
            target = self.type
        return self.parser.identifier.get_methods_from(target, start, self.new_custom)

    def __str__(self):
        return self.name

    def get_samples(self, max_samples=inf, supposed_type=None, target_type=None):
        """ get few sample values of a field """
        c = min(len(self.parser.sample_parsed), max_samples)
        try:
            res = [self.parser.sample_parsed[line][self.col_i] for line in
                   range(0, c)]
        except IndexError:
            rows = []
            for l in self.parser.sample_parsed[slice(None, c)]:
                rows.append(self.compute_preview(l))
            res = rows
        if supposed_type and supposed_type.is_plaintext_derivable:
            rows, res = res.copy(), []
            for c in rows:
                for m in self.get_methods(Types.bytes if target_type == Types.charset else Types.plaintext, self.type):
                    c = m(c)
                res.append(c)
        return res

    def compute_preview(self, source_line: List[Cell]) -> Cell:
        """ source_line is registered under parser.sample_parsed """
        if Config.get("compute_preview") and self.source_field:
            try:
                c = source_line[self.source_field.col_i]
            except IndexError:
                # Needed for this complicated case:
                # convey "http://example.com" --web --field code,"x" --field text,code,url --field reg_m,text
                return "NOT COMPUTED YET"
            if c is None:
                # source column has not yet been resolved because of column resorting
                # (note this will not pose a problem when processing)
                return "..."
            # noinspection PyBroadException
            try:
                for l in self.get_methods():
                    if isinstance(c, list):
                        # resolve all items, while flattening any list encountered
                        c = [y for x in (l(v) for v in c) for y in (x if type(x) is list else [x])]
                    else:
                        c = l(c)
            except Quota.QuotaExceeded:
                c = "QUOTA EXCEEDED"
            except UnknownValue:
                c = "UNKNOWN"
            except BdbQuit:
                raise
            except Exception:
                c = "INVALID"
        elif Config.get("compute_preview") and self.merged_from:
            # this field is merged
            try:
                key = source_line[self.merge_operation.local_column.col_i]
                remote_lines: Optional[List[str]] = self.merge_operation.rows.get(key)
                if remote_lines:
                     # list only first line; user will not know that the line might be duplicated
                     # if key exist multiple times
                    c = remote_lines[0][self.merged_from.col_i]
                else:
                    c = "EMPTY"
            except IndexError:
                # Needed for this complicated case:
                # convey "http://example.com" --web --field code,"x" --field text,code,url --field reg_m,text
                return "NOT COMPUTED YET"
        else: # we do not want the preview to be computed
            c = "..."

        # add a newly computed value to source_parsed
        for _ in range(self.col_i - len(source_line) + 1):  # source_line is shorter than we need - fill the missing cols with Nones
            source_line.append(None)
        if type(c) is list:
            if len(c) == 1:
                # XX add comment when does this happen
                # Can we receive multiple values? Should not we join them?
                c = c[0]
            elif len(c) == 0:
                c = "NOTHING"
        if c is None:
            c = "NOTHING"
        source_line[self.col_i] = c
        return c
