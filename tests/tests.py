from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import logging
import os
import shlex
import shutil
from stat import S_IRGRP, S_IRUSR
import sys
from base64 import b64encode
from datetime import datetime
from pathlib import Path
from subprocess import run, PIPE
from tempfile import TemporaryDirectory
from typing import Union, List
from unittest import TestCase, main

from convey.controller import Controller
from convey.dialogue import Cancelled

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
os.chdir("tests")  # all mentioned resources files are in that folder
os.chmod("red-permission.gif", S_IRUSR | S_IRGRP)  # make file unreadable to others
HELLO_B64 = 'aGVsbG8='
SHEET_CSV = Path("sheet.csv")
GIF_CSV = Path("gif.csv")
PERSON_CSV = Path("person.csv")
PERSON_XLS = Path("person.xls")
PERSON_XLSX = Path("person.xlsx")
PERSON_ODS = Path("person.ods")
COMBINED_SHEET_PERSON = Path("combined_sheet_person.csv")
PERSON_HEADER_CSV = Path("person_header.csv")
COMBINED_LIST_METHOD = Path("combined_list_method.csv")
SHEET_DUPLICATED_CSV = Path("sheet_duplicated.csv")
SHEET_HEADER_CSV = Path("sheet_header.csv")
SHEET_HEADER_ITSELF_CSV = Path("sheet_header_itself.csv")
SHEET_HEADER_PERSON_CSV = Path("sheet_header_person.csv")
SHEET_PERSON_CSV = Path("sheet_person.csv")
PERSON_GIF_CSV = Path("person_gif.csv")
CONSUMPTION = Path("consumption.csv")


class Convey:
    def __init__(self, *args, filename: Union[str, Path] = None, text=None, whois=False, debug=None):
        """ It is important that an input is flagged with --file or --input when performing tests
            because otherwise, main() would hang on `not sys.stdin.isatty() -> sys.stdin.read()`
            :type args: object
        """
        self.debug = debug

        # XX travis will not work will daemon=true (which imposes slow testing)
        self.cmd = ["../convey.py", "--output", "--reprocess", "--headless",
                    "--daemon", "false", "--debug", "false", "--crash-post-mortem", "false"]
        if filename is None and not text and len(args) == 1 and not str(args[0]).startswith("-"):
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
        if not any((self.has_filename, self.has_text, piped_text)) and not cmd.startswith("-"):
            cmd = "--input " + cmd

        cmd = [*self.cmd, *shlex.split(cmd)]
        if text:
            cmd.extend(("--input", text))
        if self.debug:
            print(" ".join(cmd))
        # run: blocking, output
        input_ = piped_text.encode() if piped_text else None
        lines = run(cmd, input=input_, stdout=PIPE, timeout=3).stdout.decode("utf-8").splitlines()
        if self.debug:
            print(lines)
        if lines and lines[-1] == '\x1b[0m':
            # colorama put this reset string at the end. I am not able to reproduce it in bash, only in Python piping.
            lines = lines[:-1]
        return lines


convey = Convey()


class TestAbstract(TestCase):
    def check(self, check: Union[List, str], cmd: str = "", text=None, filename: Union[str, Path] = None, debug=None):
        # o = Convey(filename=filename, text=text, debug=debug)(cmd)
        args = ["--output", "--reprocess", "--headless", "--daemon",
                "false", "--debug", "false", "--crash-post-mortem", "false"]
        if filename:
            args.extend(("--file", str(filename)))
        if text:
            args.extend(("--input",  text))
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
            elif check is None:
                self.assertFalse(o)
            elif not len(o):
                raise AssertionError(f"Output too short: {o}")
            else:
                self.assertEqual(check, o[0])
        except AssertionError as e:
            raise AssertionError(*info) from e


class TestFilter(TestCase):
    def test_filter(self):
        convey = Convey(SHEET_CSV)
        self.assertEqual(3, len(convey("--include-filter 1,foo")))
        self.assertEqual(2, len(convey("--exclude-filter 1,foo")))
        self.assertEqual(2, len(convey("--unique 1")))

    def test_post_filter(self):
        """ Filter after a field was generated. """
        convey = Convey(SHEET_CSV)
        self.assertEqual(3, len(convey("--field base64,1 --include-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --exclude-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --unique base64")))


class TestDialect(TestCase):
    def test_dialect(self):
        convey = Convey(SHEET_CSV)
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|'"))
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false"))
        self.assertNotIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false --header"))


class TestColumns(TestAbstract):
    def test_column_selection(self):
        """ Allows specify index (even negative) """

        self.check("com", "-f tld,-1", "one.com")
        self.check('"one.com","com"', "-f tld,-1 -C", "one.com")
        self.check("com", "-f tld,1", "one.com")
        self.check("Column ID 2 does not exist. We have these so far: one.com", "-f tld,2", "one.com")
        self.check('two.cz,one.com,com', "-f tld,2 -C", "two.cz,one.com")

        c = Convey(filename=SHEET_CSV)
        self.assertEqual('foo,green,first.example.com,com', c("-f tld,-1")[1])
        self.assertEqual('foo,green,first.example.com,com', c("-f tld,3")[1])
        self.assertEqual('foo,green,first.example.com,com,comA', c("-f tld,-1 -f code,-1,'x+=\"A\"'")[1])
        self.assertEqual('foo,green,first.example.com,com,first.example.comA', c("-f tld,-1 -f code,-2,'x+=\"A\"'")[1])

    def test_split(self):
        lines = Convey()("--split email", "one@example.com\nsecond@example.com")
        [self.assertIn(s, lines) for s in
         ('* Saved to second@example.com', '"second@example.com"', '* Saved to one@example.com', '"one@example.com"')]


class TestFields(TestAbstract):

    def test_base64_detection(self):
        """ Base64 detection should work if majority of the possibly decoded characters are not gibberish."""
        self.check("base64", "--single-detect", HELLO_B64)
        self.check(None, "--single-detect", "ahojahoj")

    def test_base64_charset(self):
        """ Base64 detection should work even if encoded with another charset """
        s = "Žluťoučký kůň pěl ďábelské ódy."
        encoded = b64encode(s.encode("iso-8859-2"))
        convey = Convey()
        self.assertIn(s, convey("-f charset,,,iso-8859-2", text=encoded.decode("utf-8")))

    def test_base64_disambiguation(self):
        """ Base64 must not mix up with I.E. hostname """
        c = Convey("--single-detect")
        self.assertIn("hostname", c("example.com"))  # hostname must not be confounded with base64
        self.assertFalse(c("base"))  # 'base' is plaintext

        c = Convey("--single-query")
        self.assertIn("m«", c("base -t base64"))  # 'base' can be base64 if explicitly told

    def test_phone_detection(self):
        """ Various phone formats must pass. """
        c = Convey("--single-detect")
        self.assertIn("timestamp", c("2020-02-29"))  # date value must not be confused with the phone regex
        for phone in ("+420123456789", "+1-541-754-3010", "1-541-754-3010", "001-541-754-3010", "+49-89-636-4801"):
            self.assertIn("phone", c(phone), phone)

    def test_pint(self):
        """ Test unit conversion works """
        c = Convey()
        self.assertIn("unit", c("--single-detect", text="1 kg"))
        self.assertIn("2.6792288807189983 troy_pound", c("-f unit[troy_pound]", text="1 kg"))

    def test_wrong_url(self):
        c = Convey()
        self.assertEqual("http://example.com", c("-f url", text="hXXp://example.com")[0])
        self.assertEqual("https://an.eXAmple.com", c("-f url", text="hxxps://an[.]eXAmple[.]com")[0])
        self.assertEqual("http://185.33.144.243/main_content/",
                         c("-f url", text="hxxp://185.33.144[.]243/main_content/")[0])
        self.assertEqual("http://80.211.218.7/fb/", c("-f url", text="80.211.218.7/fb/")[0])

    def test_hostname(self):
        self.assertIn("hostname", convey("--single-detect", text="_spf.google.com"))

    def test_timestamp(self):
        self.assertIn("timestamp", convey("--single-detect", text="26. 03. 1999"))
        time = datetime.now()
        self.assertIn("timestamp", convey("--single-detect", text=str(time)))
        self.assertIn("timestamp", convey("--single-detect", text=str(int(time.timestamp()))))

        # as of Python3.7 use:
        # distant_future = datetime.fromisoformat("3000-01-01")  # it is less probable distant dates are dates
        distant_future = datetime.fromtimestamp(32503680000.0)

        self.assertIn("timestamp", convey("--single-detect", text=str(distant_future)))
        self.assertIn("phone", convey("--single-detect", text=str(int(distant_future.timestamp()))))
        # there is no path to datetype date from a phone
        self.assertIn("No suitable column found for field 'date'",
                      convey("-S -f date", text=str(distant_future.timestamp())))
        # however, is is possible to get a date if specified
        self.assertIn("3000-01-01", convey("-t timestamp -f date", text=str(int(distant_future.timestamp()))))
        # works for float numbers too
        self.assertIn("3000-01-01", convey("-t timestamp -f date", text=str(distant_future.timestamp())))

        # short number is not considered a timestamp from the beginning of the Unix epoch (1970)
        self.assertEqual([], convey("--single-detect", text="12345"))


class TestAction(TestAbstract):
    def test_aggregate(self):
        self.check(["sum(price)", "972.0"], f"--aggregate price,sum", filename=CONSUMPTION)
        self.check(['category,sum(price)', 'total,972.0', 'kettle,602.0', 'bulb,370.0'],
                   f"--aggregate price,sum,category", filename=CONSUMPTION)
        self.check(['category,sum(price),avg(consumption)',
                    'total,972.0,41.0',
                    'kettle,602.0,75.0',
                    'bulb,370.0,18.33'], f"--aggregate price,sum,consumption,avg,category", filename=CONSUMPTION)
        self.check(['category,sum(price),list(price)',
                    'total,972.0,(all)',
                    '''kettle,602.0,"['250', '352']"''',
                    '''bulb,370.0,"['100', '150', '120']"'''], f"--aggregate price,sum,price,list,category", filename=CONSUMPTION)

        # XX this will correctly split the files,
        # however, the output is poor and for a reason not readable by the check.
        # self.check(['','Split location: bulb','','Split location: kettle'],
        #            "--agg price,sum --split category", filename=CONSUMPTION)
        # Until then, following substitution is used to generate the files at least
        Convey(filename=CONSUMPTION)("--agg price,sum --split category")

        # Check the contents of the files that just have been split
        check1 = False
        check2 = False
        for f in Path().glob("consumption.csv_convey*/*"):
            if f.name == "kettle" and f.read_text() == "sum(price)\n602.0\n":
                check1 = True
            if f.name == "bulb" and f.read_text() == "sum(price)\n370.0\n":
                check2 = True
        self.assertTrue(check1)
        self.assertTrue(check2)

    def test_merge(self):
        # merging generally works
        self.check(COMBINED_SHEET_PERSON, f"--merge {PERSON_CSV},2,1", filename=SHEET_CSV)
        # rows can be duplicated due to other fields
        self.check(COMBINED_LIST_METHOD,
                   f"--merge {PERSON_CSV},2,1 -f external,external_pick_base.py,list_method,1", filename=SHEET_CSV)

        # merging file with header and with a missing value
        self.check(SHEET_PERSON_CSV, f"--merge {PERSON_HEADER_CSV},2,1", filename=SHEET_CSV)

        # merge on a column type
        self.check(PERSON_GIF_CSV, f"--merge {GIF_CSV},email,email", filename=PERSON_CSV)

        # merge by a column number
        self.check(PERSON_GIF_CSV, f"--merge {GIF_CSV},email,1", filename=PERSON_CSV)

        # invalid column definition
        msg = "ERROR:convey.identifier:Cannot identify COLUMN invalid, put there an exact column name, its type, the numerical order starting with 1, or with -1."
        with self.assertLogs(level='WARNING') as cm:
            self.check(None, f"--merge {GIF_CSV},email,invalid", filename=PERSON_CSV)
            self.assertEqual([msg], cm.output)

        # merging a file with itself
        self.check(SHEET_HEADER_ITSELF_CSV, f"--merge {SHEET_HEADER_CSV},4,2", filename=SHEET_HEADER_CSV)

        # only local file has header; different dialects
        self.check(SHEET_HEADER_PERSON_CSV, f"--merge {PERSON_CSV},2,1", filename=SHEET_HEADER_CSV)

    def test_compute_from_merge(self):
        """ Computing a new column from another file currenlty being merged was not implemented. """
        self.check('Sourcing from columns being merged was not implemented', f"--merge {PERSON_CSV},2,1 -f base64,6", filename=SHEET_CSV)

class TestLaunching(TestAbstract):
    def test_piping_in(self):
        convey = Convey()
        # just string specified, nothing else
        lines = convey(piped_text="3 kg")
        self.assertTrue(len(lines) == 1)
        self.assertTrue("'1.806642228624337e+27 dalton'" in lines[0])

        # field base64 specified
        self.assertListEqual([HELLO_B64], convey("-f base64", piped_text="hello"))
        self.assertListEqual(['hello'], convey(piped_text=HELLO_B64))
        self.assertListEqual([], convey(piped_text="hello"))

    def test_single_query_processing(self):
        """ Stable --single-query parsing  """

        # Single field containing a comma, still must be fully converted (comma must not be mistaken for a CSV delimiter)
        self.check("aGVsbG8sIGhlbGxv", "-f base64", "hello, hello", debug=True)
        self.check("V=C3=A1=C5=BEen=C3=A1 Ad=C3=A9lo, ra=C4=8Dte vstoupit",
                   "-f quoted_printable", "Vážená Adélo, račte vstoupit")
        self.check([], "",  "hello, hello")

        # multiline base64 string
        multiline = "ahoj\nahoj"
        multiline_64 = b64encode(multiline.encode()).decode()
        word = "ahoj"
        word_64 = b64encode(word.encode()).decode()

        self.check(multiline_64, "--single-query -f base64", multiline)
        self.check([f'"{word}","{word_64}"']*2, "-f base64", multiline)


    def test_conversion(self):
        lines = ["john@example.com", "mary@example.com", "hyacint@example.com"]
        with TemporaryDirectory() as temp:
            for pattern in (PERSON_XLS, PERSON_XLSX, PERSON_ODS):
                    f = Path(temp, pattern.name)
                    f_converted = Path(temp, pattern.name + ".csv")
                    # XX as of Python3.8, use this line: shutil.copy(pattern, f)
                    shutil.copy(str(pattern), str(f))  # move to temp dir to not pollute the tests folder

                    self.assertFalse(f_converted.exists())
                    self.check(lines, f"-s 1", filename=f)
                    self.assertTrue(f_converted.exists())
                    # try again, as the file now exists
                    self.check(lines, f"-s 1", filename=f)

                    # clean the converted file up and use it not as the main file but
                    # as a secondary Wrapper – in a merge action
                    f_converted.unlink()
                    self.check(COMBINED_SHEET_PERSON, f"--merge {f},2,1", filename=SHEET_CSV)
                    self.assertTrue(f_converted.exists())
                    self.check(COMBINED_SHEET_PERSON, f"--merge {f},2,1", filename=SHEET_CSV)


class TestSending(TestCase):
    def test_dynamic_template(self):
        convey = Convey("--output", "False", filename=SHEET_CSV)
        cmd = """--field code,3,'x="example@example.com" if "example.com" in x else x+"@example.com"'""" \
              " --split code --send-test {mail} 'email_template.eml' --headless"
        lines = convey(cmd.format(mail="example@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a long amount of lines!', lines)
        self.assertIn('We send you lots of colours: red, green, yellow.', lines)
        self.assertIn('foo,green,first.example.com,example@example.com', lines)
        # attachment must not be present because we called attachment() in the template
        self.assertNotIn('Attachment', lines[0])

        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a short amount of lines!', lines)
        self.assertIn('We send you single colour: orange.', lines)
        self.assertIn('Attachment sheet.csv (text/csv):', lines[0])

        cmd += " --header"  # we force first row to be a header
        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        # even though there is header in the file, we should still get single value
        self.assertIn('We send you single colour: orange.', lines)

    # XX we should test body, subject, references flag
    # def test_body_flag(self):
    #     convey = Convey(FILTER_FILE)
    #     cmd = """--body "body text" """

    def test_send(self):
        BLACK = "Attachment black.gif (image/gif)"
        WHITE = "Attachment white.gif (image/gif)"
        COLOURS = "Attachment gif.csv (text/csv)"
        convey = Convey("--output", "False", filename=GIF_CSV)
        cmd_pattern = """-t abusemail,path --split abusemail --send-test {mail} 'bare_template.eml' """

        cmd = cmd_pattern + "--attach-files False --attach-paths-from-path-column True"

        # Single image is attached
        lines = convey(cmd.format(mail="john@example.com"))
        self.assertIn(BLACK, lines[0])
        lines = convey(cmd.format(mail="mary@example.com"))
        self.assertIn(WHITE, lines[0])

        # Two images are attached
        lines = convey(cmd.format(mail="jack@example.com"))
        self.assertIn(BLACK, lines[0])
        self.assertIn(WHITE, lines[4])

        # Image cannot be attached
        lines = convey(cmd.format(mail="hyacint@example.com"))
        self.assertIn("Convey crashed at For security reasons, path must be readable to others: red-permission.gif", lines[0])

        # Flags controlling attachments work
        lines = convey(cmd_pattern.format(mail="john@example.com") + "--attach-files True --attach-paths-from-path-column False")
        self.assertIn(COLOURS, lines[0])
        lines = convey(cmd_pattern.format(mail="john@example.com") + "--attach-files True --attach-paths-from-path-column True")
        self.assertIn(COLOURS, lines[0])
        self.assertIn(BLACK, lines[1])
        lines = convey(cmd_pattern.format(mail="john@example.com") + "--attach-files False --attach-paths-from-path-column False")
        self.assertNotIn(COLOURS, lines[0])
        self.assertNotIn(BLACK, lines[1])


class TestExternals(TestAbstract):

    def test_list_in_result(self):
        """ The method returns a list while CSV processing. """
        self.check(SHEET_DUPLICATED_CSV, "-f external,external_pick_base.py,list_method", filename=SHEET_CSV)

    def test_bare_method(self):
        convey = Convey()
        lines = convey("--field external,external_pick_base.py,dumb_method --input 'foo'")
        self.assertEqual(lines, ["-foo-"])

    def test_pick_input(self):
        convey = Convey()
        lines = convey("--field external,external_pick_base.py,time_format --input '2016-08-08 12:00'")
        self.assertEqual(lines, ['12:00'])

    def test_pick_method(self):
        convey = Convey()
        # method "all" (default one) is used and "1" passes
        self.assertEqual(["1"], convey("--field external,external_pick_base.py,PickMethodTest --input '1'"))
        # method "filtered" is used and "a" passes
        self.assertEqual(["a"], convey("--field external,external_pick_base.py,PickMethodTest,filtered --input 'a'"))
        # method "filtered" is used which excludes "1"
        self.assertNotEqual(["1"], convey("--field external,external_pick_base.py,PickMethodTest,filtered --input '1'"))

        # XX does not work, error when resolving path Unit -> Plaintext -> External. Identifier.get_methods_from
        # `lambda_ = lambda_.get_lambda(custom.pop(0) if custom is not None else None)`
        #       -> get_module_from_path(custom[0], ...) does not contain a path
        # self.assertEqual(["a"], convey("--field external,external_pick_base.py,PickMethodTest --input 'mm'"))


if __name__ == '__main__':
    main()
