from tests.shared import SHEET_CSV, Convey, TestAbstract


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
