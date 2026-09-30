from unittest.mock import MagicMock

from convey.action_controller import ActionController
from tests.shared import (
    DUPLICATE_NAMES_CSV,
    GIF_CSV,
    PERSON_CSV,
    PERSON_GIF_CSV,
    TestAbstract,
)


class TestInternal(TestAbstract):
    def test_similar_fields(self):
        """Recommending of the similar columns"""
        c1 = self.check(None, f"--merge {PERSON_CSV},2,1", filename=GIF_CSV).controller
        parser1A, parser1B = c1.parser, c1.parser.settings["merge"][0].remote_parser
        fields1A = c1.parser.fields
        fields1B = parser1B.fields
        self.assertListEqual([fields1A[0]], parser1A.get_similar(fields1B))
        self.assertListEqual([fields1B[0]], parser1B.get_similar(fields1A))
        self.assertListEqual([fields1B[0]], parser1B.get_similar(fields1A[0]))
        self.assertListEqual([], parser1B.get_similar(fields1A[1]))

        c2 = self.check(None, f"--merge {PERSON_GIF_CSV},2,1", filename=GIF_CSV).controller
        parser2A, parser2B = c2.parser, c2.parser.settings["merge"][0].remote_parser
        fields2A = c2.parser.fields
        fields2B = parser2B.fields
        self.assertListEqual([fields2A[0], fields2A[1]], parser2A.get_similar(fields2B))
        self.assertListEqual([fields2A[0]], parser2A.get_similar(fields2B[0]))
        self.assertListEqual([], parser2A.get_similar(fields2B[1]))
        self.assertListEqual([fields2A[1]], parser2A.get_similar(fields2B[3]))
        self.assertListEqual([fields2B[0], fields2B[3]], parser2B.get_similar(fields2A))

    def test_duplicate_field_names(self):
        """Columns sharing a name (ex: after a merge) must all be offered in the dialogs."""
        parser = self.check(None, filename=DUPLICATE_NAMES_CSV).controller.parser
        self.assertListEqual(
            ["name (1)", "regulation_level", "name (3)", "is_regulated", "name (5)"],
            list(parser.get_field_labels().values()),
        )

        m = MagicMock()
        m.select.side_effect = lambda options, *_, **__: options
        ac = ActionController(parser, m)
        options = ac.select_col(include_computables=False)
        self.assertListEqual(parser.fields, list(options.values()))

        ac.choose_cols()
        options = m.select.call_args.args[0]
        self.assertListEqual(parser.fields, list(options.values()))
