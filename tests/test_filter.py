from unittest import TestCase

from tests.shared import SHEET_CSV, Convey


class TestFilter(TestCase):
    def test_filter(self):
        convey = Convey(SHEET_CSV)
        self.assertEqual(3, len(convey("--include-filter 1,foo")))
        self.assertEqual(2, len(convey("--exclude-filter 1,foo")))
        self.assertEqual(2, len(convey("--unique 1")))

    def test_post_filter(self):
        """Filter after a field was generated."""
        convey = Convey(SHEET_CSV)
        self.assertEqual(3, len(convey("--field base64,1 --include-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --exclude-filter base64,Zm9v")))
        self.assertEqual(2, len(convey("--field base64,1 --unique base64")))
