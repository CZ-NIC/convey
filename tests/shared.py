from convey.dialogue import Cancelled
from convey.controller import Controller
from contextlib import redirect_stdout
from io import StringIO
import shlex
from subprocess import PIPE, run
import sys
import os
import logging
from pathlib import Path
from stat import S_IRGRP, S_IRUSR
from typing import List, Union
from unittest import TestCase

sys.path.append(str(Path(__file__).parent.parent))


logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

# to evade project folder pollution, chdir to a temp folder
PROJECT_DIR = Path.cwd()
# temp = TemporaryDirectory() XX As the output folder appears in the file folder, this has diminished effect.
# os.chdir(temp.name)
# os.chdir("tests")

TESTDATA_DIR = Path("tests") / Path("test_data")


def p(s):
    """all mentioned resources files are in the tests folder"""
    return PROJECT_DIR / TESTDATA_DIR / Path(s)


HELLO_B64 = "aGVsbG8="
SHEET_CSV = p("sheet.csv")
GIF_CSV = p("gif.csv")
PERSON_CSV = p("person.csv")
PERSON_XLS = p("person.xls")
PERSON_XLSX = p("person.xlsx")
PERSON_ODS = p("person.ods")
COMBINED_SHEET_PERSON = p("combined_sheet_person.csv")
PERSON_HEADER_CSV = p("person_header.csv")
COMBINED_LIST_METHOD = p("combined_list_method.csv")
SHEET_DUPLICATED_CSV = p("sheet_duplicated.csv")
SHEET_HEADER_CSV = p("sheet_header.csv")
SHEET_HEADER_ITSELF_CSV = p("sheet_header_itself.csv")
SHEET_HEADER_PERSON_CSV = p("sheet_header_person.csv")
SHEET_PERSON_CSV = p("sheet_person.csv")
PERSON_GIF_CSV = p("person_gif.csv")
CONSUMPTION = p("consumption.csv")
p("red-permission.gif").chmod(S_IRUSR | S_IRGRP)  # make file unreadable to others


class Convey:
    """While we prefer to check the results with .check method
    (quicker, directly connected with the internals of the library),
    this method is able to test piping and interprocess communication.
    """

    def __init__(
        self,
        *args,
        filename: Union[str, Path] = None,
        text=None,
        whois=False,
        debug=None,
    ):
        """It is important that an input is flagged with --file or --input when performing tests
        because otherwise, main() would hang on `not sys.stdin.isatty() -> sys.stdin.read()`
        :type args: object
        """
        self.debug = debug

        # XX travis will not work will daemon=true (which imposes slow testing)
        self.cmd = [
            str(PROJECT_DIR / "convey.py"),
            "--output",
            "--reprocess",
            "--headless",
            "--daemon",
            "false",
            "--debug",
            "false",
            "--crash-post-mortem",
            "false",
        ]
        if (
            filename is None
            and not text
            and len(args) == 1
            and not str(args[0]).startswith("-")
        ):
            filename = args[0]
            args = None
        if filename:
            if not Path(filename).exists():
                raise FileNotFoundError(filename)
            self.cmd.extend(("--file", str(filename)))
        if text:
            self.cmd.extend(("--input", text))

        self.has_filename = bool(filename)
        self.has_text = bool(text)
        if not whois:
            self.cmd.extend(("--whois-cache", "false"))
        if args:
            self.cmd.extend(args)

    def __call__(self, cmd="", text=None, debug=None, piped_text=None):
        if debug is not None:
            self.debug = debug
        if not any(
            (self.has_filename, self.has_text, piped_text)
        ) and not cmd.startswith("-"):
            cmd = "--input " + cmd

        cmd = [*self.cmd, *shlex.split(cmd)]
        if text:
            cmd.extend(("--input", text))
        if self.debug:
            print(" ".join(cmd))
        # run: blocking, output
        input_ = piped_text.encode() if piped_text else None
        lines = (
            run(cmd, input=input_, stdout=PIPE, timeout=3)
            .stdout.decode("utf-8")
            .splitlines()
        )
        if self.debug:
            print(lines)
        if lines and lines[-1] == "\x1b[0m":
            # colorama put this reset string at the end. I am not able to reproduce it in bash, only in Python piping.
            lines = lines[:-1]
        return lines


class TestAbstract(TestCase):
    maxDiff = None

    def check(
        self,
        check: Union[List, str, None],
        cmd: str = "",
        text=None,
        filename: Union[str, Path] = None,
        debug=None,
    ):
        # o = Convey(filename=filename, text=text, debug=debug)(cmd)
        args = [
            "--output",
            "--reprocess",
            "--headless",
            "--daemon",
            "false",
            "--debug",
            "false",
            "--crash-post-mortem",
            "false",
        ]
        if filename:
            args.extend(("--file", str(filename)))
        if text:
            args.extend(("--input", text))
        args.extend(shlex.split(cmd))

        if isinstance(check, Path):
            check = Path(check).read_text().splitlines()
        if debug:
            print("convey", " ".join(args))
            print(check)
        info = ("Cmd", "convey " + " ".join(args), "Check", check)

        with redirect_stdout(StringIO()) as buf:
            c = Controller()
            try:
                c.run(given_args=args)
            except SystemExit as e:
                if e.code:
                    raise AssertionError(f"Bad exit code: {e.code}")
            except Cancelled as e:
                print(str(e))
            except Exception as e:
                raise Exception(*info) from e
            finally:
                c.cleanup()
            o = buf.getvalue().splitlines()

        try:
            if isinstance(check, list):
                self.assertListEqual(check, o)
            elif check == "":  # check empty output
                self.assertFalse(o)
            elif check is None:  # we do not want to do any checks
                pass
            elif not len(o):
                raise AssertionError(f"Output too short: {o}")
            else:
                self.assertEqual(check, o[0])
        except AssertionError as e:
            raise AssertionError(*info) from e

        return c
