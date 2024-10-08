from base64 import b64encode
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from tests.shared import COMBINED_SHEET_PERSON, HELLO_B64, PERSON_ODS, PERSON_XLS, PERSON_XLSX, SHEET_CSV, Convey, TestAbstract


class TestLaunching(TestAbstract):
    def test_piping_in(self):
        convey = Convey()
        # just string specified, nothing else
        lines = convey(piped_text="3 kg")
        self.assertTrue(len(lines) == 1)
        self.assertTrue("'1.806642228624337e+27 dalton'" in lines[0])

        # field base64 specified
        self.assertListEqual([HELLO_B64], convey("-f base64", piped_text="hello"))
        self.assertListEqual(["hello"], convey(piped_text=HELLO_B64))
        self.assertListEqual([], convey(piped_text="hello"))

    def test_single_query_processing(self):
        """Stable --single-query parsing"""

        # Single field containing a comma, still must be fully converted (comma must not be mistaken for a CSV delimiter)
        self.check("aGVsbG8sIGhlbGxv", "-f base64", "hello, hello", debug=True)
        self.check("V=C3=A1=C5=BEen=C3=A1 Ad=C3=A9lo, ra=C4=8Dte vstoupit", "-f quoted_printable", "Vážená Adélo, račte vstoupit")
        self.check([], "", "hello, hello")

        # multiline base64 string
        multiline = "ahoj\nahoj"
        multiline_64 = b64encode(multiline.encode()).decode()
        word = "ahoj"
        word_64 = b64encode(word.encode()).decode()

        self.check(multiline_64, "--single-query -f base64", multiline)
        self.check([f'"{word}","{word_64}"'] * 2, "-f base64", multiline)

    def test_conversion(self):
        lines = ["john@example.com", "mary@example.com", "hyacint@example.com"]
        with TemporaryDirectory() as temp:
            for pattern in (PERSON_XLS, PERSON_XLSX, PERSON_ODS):
                f = Path(temp, pattern.name)
                f_converted = Path(temp, pattern.name + ".csv")
                # XX as of Python3.8, use this line: shutil.copy(pattern, f)
                shutil.copy(str(pattern), str(f))  # move to temp dir to not pollute the tests folder

                self.assertFalse(f_converted.exists())
                self.check(lines, f"-s 1", filename=f)
                self.assertTrue(f_converted.exists())
                # try again, as the file now exists
                self.check(lines, f"-s 1", filename=f)

                # clean the converted file up and use it not as the main file but
                # as a secondary Wrapper – in a merge action
                f_converted.unlink()
                self.check(COMBINED_SHEET_PERSON, f"--merge {f},2,1", filename=SHEET_CSV)
                self.assertTrue(f_converted.exists())
                self.check(COMBINED_SHEET_PERSON, f"--merge {f},2,1", filename=SHEET_CSV)
