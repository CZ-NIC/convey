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

        # "mm" is detected as a unit, the path is unit -> plaintext -> external.
        # The intermediate unit method must not consume the CUSTOM parts (path, method name) of the external.
        self.assertEqual(["mm"], convey("--field external,1,plaintext," + str(p("external_pick_base.py")) + ",PickMethodTest --input 'mm'"))
        self.assertIn("1000.0 micron", convey("--field external," + str(p("external_pick_base.py")) + ",PickMethodTest --input 'mm'")[0])

    def test_registered_file(self):
        """The whole file is registered. Its imports (a module, PickInput) must not break it
        and a PickMethod class without a docstring works."""
        convey = Convey()
        path = str(p("external_pick_base.py"))
        self.assertEqual(["-foo-"], convey(f"--external-fields {path} --field dumb_method --input 'foo'"))
        self.assertEqual(["a,b,a"], convey(f"--external-fields {path} --field PickMethodTest[filtered] -C --input 'a,b'"))
        self.assertEqual(["12"], convey(f"--external-fields {path}:time_format --field time_format[%H] --input '2016-08-08 12:00'"))
