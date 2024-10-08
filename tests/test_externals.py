from tests.shared import SHEET_CSV, SHEET_DUPLICATED_CSV, Convey, TestAbstract, p


class TestExternals(TestAbstract):

    def test_list_in_result(self):
        """The method returns a list while CSV processing."""
        self.check(SHEET_DUPLICATED_CSV, "-f external," + str(p("external_pick_base.py")) + ",list_method", filename=SHEET_CSV)

    def test_bare_method(self):
        # single value converted by the external
        self.check("-foo-", "--field external," + str(p("external_pick_base.py")) + ",dumb_method --input 'foo'")

        # by default, first column is used
        self.check("foo,bar,-foo-", "--field external," + str(p("external_pick_base.py")) + ",dumb_method -C --input 'foo,bar'")

        # specify 2nd column is the source for the external field
        self.check("foo,bar,-bar-", "--field external,2,plaintext," + str(p("external_pick_base.py")) + ",dumb_method -C --input 'foo,bar'")

    def test_pick_input(self):
        convey = Convey()
        lines = convey("--field external," + str(p("external_pick_base.py")) + ",time_format --input '2016-08-08 12:00'")
        self.assertEqual(lines, ["12:00"])

    def test_pick_method(self):
        convey = Convey()
        # method "all" (default one) is used and "1" passes
        self.assertEqual(["1"], convey("--field external," + str(p("external_pick_base.py")) + ",PickMethodTest --input '1'"))
        # method "filtered" is used and "a" passes
        self.assertEqual(["a"], convey("--field external," + str(p("external_pick_base.py")) + ",PickMethodTest,filtered --input 'a'"))
        # method "filtered" is used which excludes "1"
        self.assertNotEqual(["1"], convey("--field external," + str(p("external_pick_base.py")) + ",PickMethodTest,filtered --input '1'"))

        # XX does not work, error when resolving path Unit -> Plaintext -> External. Identifier.get_methods_from
        # `lambda_ = lambda_.get_lambda(custom.pop(0) if custom is not None else None)`
        #       -> get_module_from_path(custom[0], ...) does not contain a path
        # self.assertEqual(["a"], convey("--field external,external_pick_base.py,PickMethodTest --input 'mm'"))
