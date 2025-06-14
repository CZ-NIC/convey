import csv
import re
from difflib import SequenceMatcher
import logging
from typing import List, Optional
from pathlib import Path
from sys import exit

from mininterface import Mininterface
from mininterface.tag import PathTag
from prompt_toolkit.shortcuts import clear

from .args_controller import Env

from .action import AggregateAction, MergeAction
from .aggregate import Aggregate, AggregateMethod, aggregate_functions_str, aggregate_functions
from .config import Config
from .decorators import PickBase, PickMethod, PickInput
from .dialogue import Cancelled, Menu, csv_split, hit_any_key, is_yes
from .field import Field
from .parser import Parser
from .types import Types, TypeGroup, types, Type, graph, methods, get_module_from_path
from .wizzard import Preview
from .wrapper import Wrapper

logger = logging.getLogger(__name__)


class ActionController:
    def __init__(self, parser: Parser, m: Mininterface[Env], reprocess=False):
        self.parser = parser
        self.reprocess = reprocess
        self.m = m

    def add_column(self):
        self.select_col("New column", only_computables=True, add=True)
        self.parser.is_processable = True

    def add_aggregation(self, fn_name: str = None, column_task: Optional[str] = None, group: Optional[Field] = None, grouping_probably_wanted=True, exit_on_fail=False):
        # choose what column we want

        fn = self.get_aggregation_fn(fn_name, exit_on_fail)
        if column_task:
            field: Field = self.parser.fields[self.parser.identifier.get_column_i(column_task, "to be aggregated with")]
        else:
            field = self.select_col("aggregation")

        sett = self.parser.settings["aggregate"]
        if sett:
            group_old, fns = sett.group_by, sett.actions
        else:
            group_old, fns = None, []

        group = self.assure_aggregation_group_by(fn, field, group or group_old, grouping_probably_wanted, exit_on_fail)
        fns.append([fn, field])
        self.parser.settings["aggregate"] = AggregateAction(group, fns)
        self.parser.is_processable = True

    def add_dialect(self):
        # XX not ideal and mostly copies Parser.__init__
        # XX There might be a table with all the csv.dialect properties or so.
        dialect = self.parser.settings["dialect"]
        while True:
            s = "What is delimiter " + (f"(default '{dialect.delimiter}')" if dialect.delimiter else "") + ": "
            dialect.delimiter = input(s) or dialect.delimiter
            if len(dialect.delimiter) != 1:
                print("Delimiter must be a 1-character string. Invent one (like ',').")
                continue
            s = "What is quoting char " + (f"(default '{dialect.quotechar}')" if dialect.quotechar else "") + ": "
            dialect.quotechar = input(s) or dialect.quotechar
            break
        dialect.quoting = csv.QUOTE_NONE if not dialect.quotechar else csv.QUOTE_MINIMAL

        if self.parser.has_header:
            if self.parser.settings['header'] is False:
                s = f"Should we remove header? "
            else:
                s = f"Should we include header? "
            if not is_yes(s):
                self.parser.settings["header"] = not self.parser.settings["header"]

        self.parser.is_processable = True

    def add_filter(self):
        self.m.select({
            "Unique filter": self.add_uniquing,
            "Include filter": self.add_filtering,
            "Exclude filter": lambda: self.add_filtering(False),
        }, "Choose a filter")

    def add_merge(self, remote_path=None, remote_col_i: Optional[int] = None, local_col_i: Optional[int] = None):
        if not remote_path:
            remote_path = self.m.ask("What file we should merge the columns from?", PathTag(is_file=True))
        wrapper2 = Wrapper(self.m, Path(remote_path), reprocess=self.reprocess)
        parser2 = wrapper2.parser

        # dialog user and build the link between files
        controller2 = ActionController(parser2, self.m)
        column1 = self.parser.fields[local_col_i] if local_col_i is not None else None

        if remote_col_i is not None:
            column2 = parser2.fields[remote_col_i]
        else:
            high = parser2.get_similar(column1 or self.parser.fields)
            column2 = controller2.select_col("Select remote column to be merged",
                                             include_computables=False, highlighted=high)
        if not column1:
            high = self.parser.get_similar(column2)
            column1 = self.select_col(
                f"Select local column to merge '{column2}' to", include_computables=False, highlighted=high)

        # cache remote values
        operation = MergeAction.build(wrapper2.file, parser2, column2, column1)

        # build local fields based on the remotes
        for rf in parser2.fields:
            f = Field(rf.name,
                      is_chosen=False if rf is column2 else True,
                      merged_from=rf,
                      merge_operation=operation)
            self.parser.add_field(append=f)

        # prepare the operation
        self.parser.is_processable = True
        self.parser.settings["merge"].append(operation)

    def add_new_column(self, task, add=True):
        """
        :type task: str FIELD,[COLUMN],[SOURCE_TYPE], ex: `netname 3|"IP address" ip|sourceip`
        :type add: bool Add to the result.
        """
        target_type, source_field, source_type, custom = self._add_new_column(task)
        if not self.source_new_column(target_type, add, source_field, source_type, custom):
            print("Cancelled")
            exit()
        self.parser.is_processable = True
        return target_type

    def _add_new_column(self, task):
        """ Internal analysis for `add_new_column` """
        task = csv_split(task)
        custom = []
        target_type = task[0]
        m = re.search(r"(\w*)\[([^]]*)\]", target_type)
        if m:
            target_type = m.group(1)
            custom = [m.group(2)]
        try:
            target_type = types[types.index(target_type)]  # determine FIELD by exact name
        except ValueError:
            d = {t.name: SequenceMatcher(None, task[0], t.name).ratio() for t in Types.get_computable_types()}
            rather = max(d, key=d.get)
            logger.error(f"Unknown field '{task[0]}', did not you mean '{rather}'?")
            exit()
        source_field, source_type, c = self.parser.identifier.get_fitting_source(target_type, *task[1:])
        custom = c + custom
        return target_type, source_field, source_type, custom

    def add_uniquing(self, col_i=None):
        if col_i is None:
            col_i = self.select_col("unique").col_i
        self.parser.settings["unique"].append(col_i)
        self.parser.is_processable = True

    def assure_aggregation_group_by(self, fn, field, group, grouping_probably_wanted=True, exit_on_fail=False) -> Optional[Field]:
        match (fn == Aggregate.count, group is None, grouping_probably_wanted):
            case True, True, _:
                group = field
            case False, True, True:
                # here, self.select col might return None
                group = self.select_col("group by", prepended_field=("no grouping", "aggregate whole column"))
            case True, False, _:
                if field != group:
                    logger.error(f"Count column '{field.name}' must be the same"
                                 f" as the grouping column '{group.name}'.")
                    if exit_on_fail:
                        exit()
                    else:
                        raise Cancelled
        return group

    def add_filtering(self, include=True, col_i=None, val=None):
        if col_i is None:
            col_i = self.select_col("filter").col_i
        if val is None:
            s = "" if include else "not "
            val = self.m.ask(f"What value must {s}the field have to keep the line?")
        self.parser.settings["filter"].append((include, col_i, val))
        self.parser.is_processable = True

    def add_splitting(self):
        self.parser.settings["split"] = self.select_col("splitting").col_i
        self.parser.is_processable = True

    def choose_cols(self):
        # XX possibility un/check all
        chosens = set(self.m.select(self.parser.fields, "Choose columns to be included in the output file",
                                    default=[f for f in self.parser.fields if f.is_chosen]))
        for f in self.parser.fields:
            f.is_chosen = f in chosens
            self.parser.is_processable = True

    def get_aggregation_fn(self, fn_name: str = None, exit_on_fail=False) -> AggregateMethod:
        if not fn_name:
            fn_name = self.m.select(aggregate_functions, "Choose aggregate function")
        fn = getattr(Aggregate, fn_name, None)
        if not fn:
            if exit_on_fail:
                logger.error(
                    f"Unknown aggregate function '{fn_name}'. Possible functions are: {aggregate_functions_str}")
                exit()
            else:
                raise Cancelled
        return fn

    def select_col(self, dialog_title="", only_computables=False, include_computables=True, add=None, prepended_field=None, highlighted: Optional[List[Field]] = None) -> Optional[Field]:
        """ Starts dialog where user has to choose a column.
            If cancelled, we return to main menu automatically.
            :type prepended_field: tuple (field_name, description) If present, this field is prepended. If chosen, you receive None.
        """
        # add existing fields
        fields: dict[str, Field | Type] = {}
        if prepended_field:  # a prepended_field is a mere description, not a real field
            fields[prepended_field] = None
        fields.update({(str(field), s): field for field, s in (
            [] if only_computables else self.parser.get_fields_autodetection())})

        # add computable field types
        if include_computables:
            for type_ in Types.get_computable_types():
                if type_.from_message:
                    s = type_.from_message
                else:
                    node_distance = graph.dijkstra(type_, ignore_private=True)
                    s = type_.group.name + " " if type_.group != TypeGroup.general else ""
                    if len(node_distance):
                        s += "from " + ", ".join([str(k) for k in node_distance][:3])
                        if len(node_distance) > 3:
                            s += "..."
                fields[(f"new {type_}...", s)] = type_

        col = self.m.select(fields, dialog_title, tips=highlighted)
        if isinstance(col, Type):
            return self.source_new_column(col, add=add)
        return col

    def source_new_column(self, target_type, add=None, source_field: Field = None, source_type: Type = None,
                          custom: list = None):
        """ We know what Field the new column should be of, now determine how we should extend it:
            Summarize what order has the source field and what type the source field should be considered alike.
                :type source_field: Field
                :type source_type: Type
                :type target_type: Type
                :type add: bool if the column should be added to the table; None ask
                :type custom: List
                :raise Cancelled
                :return Field
        """
        if custom is None:
            # default [] would be evaluated at the time the function is defined, multiple columns may share the same function
            custom = []
        if not source_field or not source_type:
            print(f"\nWhat column we base {target_type} on?")
            vals = {(k, v): k for k, v in self.parser.get_fields_autodetection()}
            source_field = self.m.select(vals, title="Searching source for " + str(target_type),
                                         tips=[self.parser.fields[i] for i in self.parser.identifier.get_fitting_source_i(target_type)])
            source_col_i = self.parser.fields.index(source_field)
            source_type = self.parser.identifier.get_fitting_type(source_field, target_type, try_plaintext=True)

            if source_type is None:
                # ask how should be treated the column as, even it seems not valid
                # list all known methods to compute the desired new_field (e.g. for incident-contact it is: ip, hostname, ...)
                if choices := {(k.name, k.description): k
                               for k, _ in graph.dijkstra(target_type, ignore_private=True).items()}:
                    s = ""
                    if self.parser.sample_parsed:
                        s = f"\n\nWhat type of value '{self.parser.sample_parsed[0][source_col_i]}' is?"
                    title = (f"Choose the right method\n\nNo known method for making {target_type}"
                             f" from column {source_field} because the column type wasn't identified."
                             f" How should I treat the column?{s}")
                    source_type: Type = self.m.select(choices, title=title)
                else:
                    self.m.alert(f"No known method for making {target_type}. Raise your usecase as"
                                 f" an issue at {Config.PROJECT_SITE}.")
                    raise Cancelled("... cancelled")
            clear()

        if not custom:
            try:
                if target_type.group == TypeGroup.custom:
                    if target_type == Types.code:
                        print("What code should be executed? Change 'x'. Ex: x += \"append\";")
                        custom = Preview(source_field, source_type).code()
                    elif target_type in [Types.reg, Types.reg_m, Types.reg_s]:
                        *custom, target_type = Preview(source_field, source_type, target_type).reg()
                    elif target_type == Types.external:  # choose a file with a needed method
                        while True:
                            path = self.m.form({"What .py file should be used as custom source?":
                                                PathTag(is_file=True)})
                            module = get_module_from_path(path)
                            if module:
                                # inspect the .py file, extract methods and let the user choose one
                                method_name = self.m.select([x for x in dir(module) if not x.startswith(
                                    "_")], title=f"What method should be used in the file {path}?")
                                custom = path, method_name
                                break
                            else:
                                self.m.alert(f"The file {path} does not exist or is not a valid .py file.")
                    if not custom:
                        raise Cancelled("... cancelled")
            except Cancelled:
                raise Cancelled("... cancelled")
            path = graph.dijkstra(target_type, start=source_type, ignore_private=True)
            for i in range(len(path) - 1):
                m = methods[path[i], path[i + 1]]
                if isinstance(m, PickBase):
                    c = None
                    if self.m.env.cli.yes:
                        pass
                    elif type(m) is PickMethod:
                        m: PickMethod
                        c = self.m.select({(k, v): k for k, v in m.get_options()}, f"Choose subtype")
                    elif type(m) is PickInput:
                        m: PickInput
                        c = Preview(source_field, source_type, target_type).pick_input(m)
                    custom.insert(0, c)
        if add is None:
            if self.m.confirm(f"New field added: {target_type}\n\nDo you want to include this field as a new column?"):
                add = True

        f = Field(target_type, is_chosen=add,
                  source_field=source_field,
                  source_type=source_type,
                  new_custom=custom)
        if f.source_field.merged_from:
            hit_any_key("Unfortunately, sourcing from columns being merged was not implemented."
                        " Ask for it on Github. And for now, merge first, then add a column.")
            raise Cancelled("Sourcing from columns being merged was not implemented")
        self.parser.settings["add"].append(f)
        self.parser.add_field(append=f)
        return f
