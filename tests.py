import logging
import sys
import unittest
from pathlib import Path
from subprocess import run, PIPE

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


class Convey:
    def __init__(self, filename=None):
        self.cmd = ["./convey.py", "--output", "--reprocess", "--headless"]
        if filename:
            if not Path(filename).exists():
                raise FileNotFoundError(filename)
            self.cmd.extend(["--file", filename])

    def __call__(self, *args):
        # run: blocking, output
        cmd = [*self.cmd, *args]
        # print(" ".join(cmd))
        return run(cmd, stdout=PIPE, timeout=3).stdout.decode("utf-8").splitlines()


class TestFilter(unittest.TestCase):
    def test_filter(self):
        convey = Convey("tests/filter.csv")
        lines = convey("--include-filter", "1,foo")
        self.assertEqual(3, len(lines))

        lines = convey("--exclude-filter", "1,foo")
        self.assertEqual(2, len(lines))

        lines = convey("--unique", "1")
        self.assertEqual(2, len(lines))


if __name__ == '__main__':
    unittest.main()
