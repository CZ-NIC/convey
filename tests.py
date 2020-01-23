import logging
import sys
import unittest
from pathlib import Path
from subprocess import run, PIPE

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


class Convey:
    def __init__(self, filename=None):
        # XX travis will not work will daemon=true
        self.cmd = ["./convey.py", "--output", "--reprocess", "--headless", "--daemon", "false"]
        if filename:
            if not Path(filename).exists():
                raise FileNotFoundError(filename)
            self.cmd.extend(["--file", filename])

    def __call__(self, *args, see=False):
        # run: blocking, output
        cmd = [*self.cmd, *args]
        if see:
            print(" ".join(cmd))
        lines = run(cmd, stdout=PIPE, timeout=3).stdout.decode("utf-8").splitlines()
        if see:
            print(lines)
        return lines


class TestFilter(unittest.TestCase):
    def test_filter(self):
        convey = Convey("tests/filter.csv")
        self.assertEqual(3, len(convey("--include-filter", "1,foo")))
        self.assertEqual(2, len(convey("--exclude-filter", "1,foo")))
        self.assertEqual(2, len(convey("--unique", "1")))


if __name__ == '__main__':
    unittest.main()
