import csv
import itertools
import logging
import re
from _csv import Error, reader
from copy import copy
from csv import Sniffer
from difflib import SequenceMatcher
from statistics import mean

from .config import Config
from .decorators import PickBase
from .types import Types, graph, TypeGroup, Type, get_module_from_path

logger = logging.getLogger(__name__)


class Identifier:

    def __init__(self, parser):
        self.parser = parser
        self.graph = None

    @staticmethod
    def get_methods_from(target, start, custom):
        """
        Returns the nested lambda list that'll receive a value from start field and should produce value in target field.
        :param target: field type name
        :param start: field type name
        :param custom: List of strings that are being used by TypeGroup.custom and PickBase
        :return: lambda[]
        """
        custom = copy(custom)

        def custom_code(e: str):
            def method(x):
                l = locals()
                try:
                    exec(compile(e, '', 'exec'), l)
                except Exception as exception:
                    code = "\n  ".join(e.split("\n"))
                    logger.error(f"Statement failed with {exception}.\n  x = '{x}'; {code}")
                    if not Config.error_caught():  # XX ipdb cannot quit with q here
                        input("We consider 'x' unchanged...")
                    return x
                x = l["x"]
                return x

            return method

        def regex(type_, search, replace=None):
            search = re.compile(search)

            def reg_m_method(s):
                match = search.search(s)
                if not match:
                    return ""
                groups = match.groups()
                if not replace:
                    if not groups:
                        return match.group(0)
                    return match.group(1)
                try:
                    return replace.format(match.group(0), *[g for g in groups])
                except IndexError:
                    logger.error(f"RegExp failed: `{replace}` cannot be used to replace `{s}` with `{search}`")
                    if not Config.error_caught():
                        input("We consider string unmatched...")
                    return ""

            def reg_s_method(s):
                match = search.search(s)
                if not match:
                    return ""
                if not replace:
                    return search.sub("", s)
                try:
                    # we convert "str{0}" → "\g<0>" (works better than conversion to a mere "\0" that may result to ambiguity
                    return search.sub(re.sub("{(\d+)}", r"\\g<\1>", replace), s)
                except re.error:
                    logger.error(f"RegExp failed: `{replace}` cannot be used to substitute `{s}` with `{search}`")
                    if not Config.error_caught():
                        input("We consider string unmatched...")
                    return ""

            return reg_s_method if type_ == Types.reg_s else reg_m_method

        path = graph.dijkstra(target, start=start)  # list of method-names to calculate new fields
        lambdas = []  # list of lambdas to calculate new field
        if not path:
            return []
        for i in range(len(path) - 1):
            lambda_ = Types.get_method(path[i], path[i + 1])
            if isinstance(lambda_, PickBase):
                # either the fields was added (has custom:List)
                # or is being computed in run_single_query() through get_computable_fields that makes us sure PickBase has a default
                lambda_ = lambda_.get_lambda(custom.pop(0) if custom is not None else None)
            elif not hasattr(lambda_, "__call__"):  # the field is invisible, see help text for Types; may be False, None or True
                continue
            lambdas.append(lambda_)

        if target.group == TypeGroup.custom:
            if target == Types.external:
                try:
                    lambda_ = getattr(get_module_from_path(custom[0]), custom[1])  # (module path, method name)
                    if isinstance(lambda_, PickBase):
                        lambda_ = lambda_.get_lambda(custom.pop(2) if len(custom) > 2 else None)
                    lambdas.append(lambda_)
                except IndexError:
                    raise ValueError(f"You must specify which method should be used in {custom[0]}")
                except AttributeError:
                    raise ValueError(f"Cannot find method {custom[1]} in {custom[0]}")
            elif target == Types.code:
                if type(custom) is list and len(custom) == 1:
                    custom = custom[0]  # code accepts a string
                lambdas += [custom_code(custom)]
            elif target in [Types.reg, Types.reg_m, Types.reg_s]:
                lambdas += [regex(target, *custom)]  # custom is in the form (search, replace)
            else:
                raise ValueError(f"Unknown type {target}")

        logger.debug(f"Preparing path from {start} to {target}: " + ", ".join([str(p) for p in path])
                     + " ('" + "', '".join(custom) + "')" if custom else "")
        return lambdas

    @staticmethod
    def get_sample(source_file):
        sample = []
        first_line = ""
        is_pandoc = False
        with open(source_file, 'r') as csv_file:
            for i, row in enumerate(csv_file):
                if i == 0:
                    first_line = row
                if i == 1 and not row.replace("-", "").replace(" ", "").strip():
                    is_pandoc = True
                    continue
                sample.append(row)
                if i == 8:  # sniffer needs 7+ lines to determine dialect, not only 3 (/mnt/csirt-rook/2015/06_08_Ramnit/zdroj), I dont know why
                    break
        return first_line.strip(), sample, is_pandoc
        # csvfile.seek(0)
        # csvfile.close()

    def guess_dialect(self, sample):
        sniffer = Sniffer()
        sample_text = "".join(sample)
        try:
            dialect = sniffer.sniff(sample_text)
            has_header = sniffer.has_header(sample_text)
            if re.match("[a-z]", dialect.delimiter.lower()):  # we do not allow letters to be delimiters, seems like non-sense
                raise Error
        except Error:  # delimiter failed – maybe there is an empty column: "89.187.1.81,06-05-2016,,CZ,botnet drone"
            if sample_text.strip() == "":
                print("The file seems empty")  # XX I got here once after a clean installation at 26.11.2019
                quit()

            # header detection
            l = [line.strip() for line in sample]
            if len(l[1:]) > 0:
                header_to_rows_similarity = mean([SequenceMatcher(None, l[0], it).ratio() for it in l[1:]])
                if len(l[1:]) > 1:
                    rows_similarity = mean([SequenceMatcher(None, *comb).ratio() for comb in itertools.combinations(l[1:], 2)])
                    has_header = rows_similarity > header_to_rows_similarity + 0.1  # it seems that first line differs -> header
                else:
                    has_header = header_to_rows_similarity < 0.5
            else:
                has_header = False

            try:
                s = sample[1]  # we do not take header (there is no empty column for sure)
            except IndexError:  # there is a single line in the file
                s = sample[0]
            delimiter = ""
            for dl in (",", ";", "|"):  # lets suppose the doubled sign is delimiter
                if s.find(dl + dl) > -1:
                    delimiter = dl
                    break
            if not delimiter:  # try find anything that resembles to a delimiter
                for dl in (",", ";", "|"):
                    if s.find(dl) > -1:
                        delimiter = dl
                        break
                else:
                    if self.parser.is_pandoc and s.count(" ") > 1:
                        delimiter = " "
            dialect = csv.unix_dialect
            if delimiter:
                dialect.delimiter = delimiter
        if not dialect.escapechar:
            dialect.escapechar = '\\'
        # dialect.quoting = 3
        dialect.doublequote = True

        seems_single = False
        if len(sample) == 1:
            # there is single line in sample = in the input, so this is definitely not a header
            has_header = False
            if dialect.delimiter not in [".", ",", "\t"] and "|" not in sample_text:
                # usecase: short one-line like "convey hello" would produce stupid "l" delimiter
                # XX should be None maybe, let's think a whole row is a single column – but then we could not add columns
                dialect.delimiter = "|"
                seems_single = True
        if dialect.delimiter == "." and "," not in sample_text:
            # let's propose common use case (bare list of IP addresses) over a strange use case with "." delimiting
            dialect.delimiter = ","
        return dialect, has_header, seems_single

    def identify_fields(self, quiet=False):
        """
        Identify self.parser.fields got in __init__
        Sets them possible types (sorted, higher score mean bigger probability that the field is of that type)
        :type quiet: bool If True, we do not raise exception when sample cannot be processed.
                            Ex: We attempt consider user input "1,2,3" as single field which is not, we silently return False
        """
        samples = [[] for _ in self.parser.fields]
        if len(self.parser.sample) == 1:  # we have too few values, we have to use them
            s = self.parser.sample[:1]
        else:  # we have many values and the first one could be header, let's omit it
            s = self.parser.sample[1:]

        for row in reader(s, skipinitialspace=self.parser.is_pandoc, dialect=self.parser.dialect) if self.parser.dialect else [s]:
            for i, val in enumerate(row):
                try:
                    samples[i].append(val)
                except IndexError:
                    if not quiet:
                        print("It seems rows have different lengths. Cannot help you with column identifying.")
                        print("Fields row: " + str([(i, str(f)) for i, f in enumerate(self.parser.fields)]))
                        print("Current row: " + str(list(enumerate(row))))
                        if not Config.error_caught():
                            input("\n... Press any key to continue.")
                    return False

        for i, field in enumerate(self.parser.fields):
            possible_types = {}
            for type_ in Types.get_guessable_types():
                score = type_.check_conformity(samples[i], self.parser.has_header, field)
                if score:
                    possible_types[type_] = score
                # print("hits", hits)

            if possible_types:  # sort by biggest score - biggest probability the column is of this type
                field.possible_types = {k: v for k, v in sorted(possible_types.items(), key=lambda k: k[1], reverse=True)}
        return True

    def get_fitting_type(self, source_field_i, target_field, try_plaintext=False):
        """ Loops all types the field could be and return the type best suited method for compute new field. """
        _min = 999
        fitting_type = None
        possible_fields = list(self.parser.fields[source_field_i].possible_types)
        dijkstra = graph.dijkstra(target_field)  # get all fields that new_field is computable from
        for _type in possible_fields:
            # loop all the types the field could be, loop from the FieldType we think the source_col correspond the most
            # a column may have multiple types (url, hostname), use the best
            if _type not in dijkstra:
                continue
            i = dijkstra[_type]
            if i < _min:
                _min, fitting_type = i, _type
        if not fitting_type and try_plaintext and Types.plaintext in dijkstra:
            # try plaintext field as the last one. Do not try it earlier, usecase:
            # we want to produce reg_s from base64. If we inserted plaintext earlier,
            #  fitting_type would be plaintext since it is a step nearer - but the field would not be decoded
            return Types.plaintext
        return fitting_type

    def get_fitting_source_i(self, target_type, try_hard=False):
        """ Get list of source_i that may be of such a field type that new_field would be computed effectively.
            Note there is no fitting column for TypeGroup.custom, if you try_hard, you receive first column as a plaintext.

            Sorted by relevance.
        """
        possible_cols = {}
        if target_type.group != TypeGroup.custom:
            valid_types = graph.dijkstra(target_type)
            for val in valid_types:  # loop from the best suited type
                for i, f in enumerate(self.parser.fields):  # loop from the column we are most sure with its field type
                    if val in f.possible_types:
                        possible_cols[i] = f.possible_types[val]
                        break
        if not possible_cols and try_hard and target_type.is_plaintext_derivable:
            # because any plaintext would do (and no plaintext-only type has been found), take the first column
            possible_cols = [0]
        return list(possible_cols)

    def get_fitting_source(self, target_type: Type, *task):
        """
        For a new field, we need source column and its field type to compute new field from.
        :rtype: source_field: Field, source_type: Type, custom: List[str]
        :param target_type: Type
        :type task: List[str]: [COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM...]
            COLUMN: int|existing name
            SOURCE_TYPE: field type name|field type usual names
            CUSTOM: any parameter
        """
        source_col_i = None
        source_type = None
        source_col_candidates = ()
        task = list(task)

        if Config.is_debug():
            print(f"Getting type {target_type} with args {task}")

        # determining source_col_i from a column candidate
        column_candidate = task.pop(0) if len(task) else None
        if column_candidate:  # determine COLUMN
            source_col_i = self.get_column_i(column_candidate)  # get field by exact column name, ID or type
            if source_col_i is None:
                if len(task) and target_type.group != TypeGroup.custom:
                    print(f"Invalid field type {task[0]}, already having defined by {column_candidate}")
                    quit()
                task.insert(0, column_candidate)  # this was not COLUMN but SOURCE_TYPE or CUSTOM, COLUMN remains empty
        if source_col_i is None:  # get a column whose field could be fitting for that target_tape or any column as a plaintext
            try:
                source_col_candidates = [self.parser.fields[i] for i in self.get_fitting_source_i(target_type, True)]
                source_col_i = source_col_candidates[0].col_i
            except IndexError:
                pass


        # determining source_type
        source_type_candidate = task.pop(0) if len(task) else None
        if source_type_candidate:  # determine SOURCE_TYPE
            source_type = Types.find_type(source_type_candidate)
            if source_type:
                # We have to choose the right column - if there are some source_col_candidates it means the column
                # was not determined exactly, we are just guessing. Get the one of the candidates whose type is nearest
                # to the demanded source_type.
                # Usecase: `--field incident-contact,source_ip`, when having only `hostname` between columns.
                # This will check there is no source_ip amongst columns and corrects `source_type = hostname`
                # instead of letting it be `source_type = source_ip` which would fail when resolving hostname.

                # XX as of Python3.8, replace the next statement with this
                # try:
                #     best_candidate = min((len(path), field.col_i, field.type) for field in source_col_candidates
                #                             if (path:=graph.dijkstra(field.type, start=source_type) is not False))
                #     source_type = best_candidate[2]
                # except ValueError:
                #     pass

                best_candidate = None
                for field in source_col_candidates:
                    path = graph.dijkstra(field.type, start=source_type)
                    if path:
                        best_candidate = min((len(path), field.col_i, field.type), best_candidate or (float('INF'),))
                        source_type = best_candidate[2]

            elif target_type.group == TypeGroup.custom:
                # this was not SOURCE_TYPE but CUSTOM, for custom fields, SOURCE_TYPE may be implicitly plaintext
                #   (if preprocessing ex: from base64 to plaintext is not needed)
                task.insert(0, source_type_candidate)
                # source_type = Types.plaintext
            else:
                print(f"Cannot determine new field from {source_type_candidate}")
                quit()

        # determining missing info
        if source_col_i is not None and not source_type:
            try:
                source_type = self.get_fitting_type(source_col_i, target_type, try_plaintext=True)
            except IndexError:
                print(f"Column ID {source_col_i + 1} does not exist. We have these so far: " +
                      ", ".join([f.name for f in self.parser.fields]))
                quit()
            if not source_type:
                print(f"We could not identify a method how to make '{target_type}' from '{self.parser.fields[source_col_i]}'")
                quit()
        if source_type and source_col_i is None:
            # searching for a fitting type amongst existing columns
            # [source col i] = score (bigger is better)
            possibles = {i: t.possible_types[source_type] for i, t in enumerate(self.parser.fields)
                         if source_type in t.possible_types}
            try:
                source_col_i = sorted(possibles, key=possibles.get, reverse=True)[0]
            except IndexError:
                f = [f for f in self.parser.fields if not f.is_new]
                if len(f) == 1:
                    # there is just a single non-computed (and thus unidentified) column
                    # since we are forcing source_type, let's pretend the column is of this type
                    source_col_i = f[0].col_i
                else:
                    print(f"No suitable column of type '{source_type}' found to make field '{target_type}'")
                    quit()

        if not source_type or source_col_i is None:
            print(f"No suitable column found for field '{target_type}'")
            quit()

        try:
            f = self.parser.fields[source_col_i]
        except IndexError:
            print(f"Column ID {source_col_i + 1} does not exist, only these: " + ", ".join(f.name for f in self.parser.fields))
            quit()

        # Check there is a path between nodes and that path is resolvable
        path = graph.dijkstra(target_type, start=source_type)
        if path is False:
            print(f"No suitable path from '{f.name}' treated as '{source_type}' to '{target_type}'")
            quit()
        for i in range(len(path) - 1):  # assure there is a valid method
            try:
                Types.get_method(path[i], path[i + 1])
            except LookupError:
                print(f"Path from '{f.name}' treated as '{source_type}' to '{target_type}' blocked at {path[i]} – {path[i + 1]}")

        if Config.is_debug():
            print(f"Preparing type {target_type} of field={f}, source_type={source_type}, custom={task}, path={path}")
        return f, source_type, task

    def get_column_i(self, column, check=False):
        """
        Useful for parsing user input COLUMN from the CLI args.
        :type column: object Either column ID (ex "1" points to column index 0) or an exact column name or the field
        :type check: If not False and not found, error is raised and quit. If str, this string will be included in the error text.
        :rtype: int Either column_i or None if not found.
        """
        source_col_i = None
        if hasattr(column, "col_i"):
            return column.col_i
        if column.isdigit():  # number of column
            source_col_i = int(column) - 1
        elif column in self.parser.first_line_fields:  # exact column name
            source_col_i = self.parser.first_line_fields.index(column)
        else:
            searched_type = Types.find_type(column)  # get field by its type
            if searched_type:
                reserve = None
                for f in self.parser.fields:
                    if f.type == searched_type:
                        source_col_i = f.col_i
                    elif searched_type in f.possible_types and not reserve:
                        reserve = f.col_i
                if not source_col_i:
                    source_col_i = reserve
        if check and (source_col_i is None or len(self.parser.fields) <= source_col_i):
            logger.error(f"Cannot identify COLUMN {column}" + (" " + check if type(check) is str else "") +
                         ", put there an exact column name or the numerical order starting with 1.")
            quit()
        return source_col_i
