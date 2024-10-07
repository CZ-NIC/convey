from unittest import TestCase

from tests.shared import SHEET_CSV, Convey


class TestDialect(TestCase):
    def test_dialect(self):
        convey = Convey(SHEET_CSV)
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|'"))
        self.assertIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false"))
        self.assertNotIn("foo|red|second.example.com", convey("--delimiter-output '|' --header-output false --header"))
