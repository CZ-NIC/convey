import logging
import shlex
import sys
from base64 import b64encode
from pathlib import Path
from subprocess import run, PIPE
from unittest import TestCase, main

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


class Convey:
    def __init__(self, *args, filename=None, text=None, whois=False, debug=None):
        """ It is important that an input is flagged with --file or --input when performing tests
            because otherwise, main() would hang on `not sys.stdin.isatty() -> sys.stdin.read()`
            :type args: object
        """
        self.debug = debug

        # XX travis will not work will daemon=true (which imposes slow testing)
        self.cmd = ["../convey.py", "--output", "--reprocess", "--headless", "--daemon", "false"]
        if filename is None and not text and len(args) == 1 and not args[0].startswith("-"):
            filename = args[0]
            args = None
        if filename:
            if not Path(filename).exists():
                raise FileNotFoundError(filename)
            self.cmd.extend(("--file", filename))
        if text:
            self.cmd.extend(("--input", text))

        self.filename = filename
        self.text = text
        if not whois:
            self.cmd.extend(("--whois-cache", "false"))
        if args:
            self.cmd.extend(args)

    def __call__(self, cmd="", text=None, debug=None):
        if debug is not None:
            self.debug = debug
        if not any((self.filename, self.text)) and not cmd.startswith("-"):
            cmd = "--input " + cmd

        cmd = [*self.cmd, *shlex.split(cmd)]
        if text:
            cmd.extend(("--input", text))
        if self.debug:
            print(" ".join(cmd))
        # run: blocking, output
        lines = run(cmd, stdout=PIPE, timeout=3).stdout.decode("utf-8").splitlines()
        if self.debug:
            print(lines)
        if lines and lines[-1] == '\x1b[0m':
            # colorama put this reset string at the end. I am not able to reproduce it in bash, only in Python piping.
            lines = lines[:-1]
        return lines


class TestFilter(TestCase):
    def test_filter(self):
        convey = Convey("filter.csv")
        self.assertEqual(3, len(convey("--include-filter 1,foo")))
        self.assertEqual(2, len(convey("--exclude-filter 1,foo")))
        self.assertEqual(2, len(convey("--unique 1")))

    def test_post_filter(self):
        """ Filter after a field was generated. """
        convey = Convey("filter.csv")
        self.assertEqual(3, len(convey("--field base64,1 --include-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --exclude-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --unique base64")))


class TestDialect(TestCase):
    def test_dialect(self):
        convey = Convey("filter.csv")
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|'"))
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false"))
        self.assertNotIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false --header"))


class TestFields(TestCase):

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


class TestTemplate(TestCase):
    def test_dynamic_template(self):
        convey = Convey("filter.csv")
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
        self.assertIn('Attachment filter.csv (text/csv):', lines[0])

        cmd += " --header"  # we force first row to be a header
        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        # even though there is header in the file, we should still get single value
        self.assertIn('We send you single colour: orange.', lines)

    # XX we should test body, subject, references flag
    # def test_body_flag(self):
    #     convey = Convey("filter.csv")
    #     cmd = """--body "body text" """


class TestExternals(TestCase):
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

        # XXXX does not work, error when resolving path Unit -> Plaintext -> External. Identifier.get_methods_from
        # `lambda_ = lambda_.get_lambda(custom.pop(0) if custom is not None else None)`
        #       -> get_module_from_path(custom[0], ...) does not contain a path
        # self.assertEqual(["a"], convey("--field external,external_pick_base.py,PickMethodTest --input 'mm'"))


if __name__ == '__main__':
    main()
