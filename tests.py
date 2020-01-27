import logging
import shlex
import sys
from pathlib import Path
from subprocess import run, PIPE
from unittest import TestCase

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


class Convey:
    def __init__(self, filename=None):
        # XX travis will not work will daemon=true
        self.cmd = ["./convey.py", "--output", "--reprocess", "--headless", "--daemon", "false"]
        if filename:
            if not Path(filename).exists():
                raise FileNotFoundError(filename)
            self.cmd.extend(["--file", filename])

    def __call__(self, cmd, see=False):
        cmd = [*self.cmd, *shlex.split(cmd)]
        if see:
            print(" ".join(cmd))
        # run: blocking, output
        lines = run(cmd, stdout=PIPE, timeout=3).stdout.decode("utf-8").splitlines()
        if see:
            print(lines)
        if lines and lines[-1] == '\x1b[0m':
            # colorama put this reset string at the end. I am not able to reproduce it in bash, only in Python piping.
            lines = lines[:-1]
        return lines


class TestFilter(TestCase):
    def test_filter(self):
        convey = Convey("tests/filter.csv")
        self.assertEqual(3, len(convey("--include-filter 1,foo", see=True)))
        self.assertEqual(2, len(convey("--exclude-filter 1,foo")))
        self.assertEqual(2, len(convey("--unique 1")))


class TestDialect(TestCase):
    def test_dialect(self):
        convey = Convey("tests/filter.csv")
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|'"))
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false"))
        self.assertNotIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false --header"))


class TestTemplate(TestCase):
    def test_dynamic_template(self):
        convey = Convey("tests/filter.csv")
        cmd = "--field code,3,'x='\\''example@example.com'\\'' if '\\''example.com'\\'' in x else x+'\\''@example.com'\\'''" \
              " --split code --send-test {mail} 'tests/email_template.eml' --headless"
        lines = convey(cmd.format(mail="example@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a long amount of lines!', lines)
        self.assertIn('We send you lots of colours: red, green, yellow.', lines)
        self.assertIn('foo,green,first.example.com,example@example.com', lines)
        # attachment must not be present because we called print_attachment() in the template
        self.assertNotIn('Attachment:', lines[0])

        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a short amount of lines!', lines)
        self.assertIn('We send you single colour: orange.', lines)
        self.assertIn('Attachment:', lines[0])

        cmd += " --header"  # we force first row to be a header
        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        # even though there is header in the file, we should still get single value
        self.assertIn('We send you single colour: orange.', lines)


if __name__ == '__main__':
    unittest.main()
