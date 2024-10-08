from base64 import b64encode
from datetime import datetime

from tests.shared import HELLO_B64, Convey, TestAbstract

convey = Convey()

class TestFields(TestAbstract):

    def test_base64_detection(self):
        """Base64 detection should work if majority of the possibly decoded characters are not gibberish."""
        self.check("base64", "--single-detect", HELLO_B64)
        self.check("", "--single-detect", "ahojahoj")

    def test_base64_charset(self):
        """Base64 detection should work even if encoded with another charset"""
        s = "Žluťoučký kůň pěl ďábelské ódy."
        encoded = b64encode(s.encode("iso-8859-2"))
        convey = Convey()
        self.assertIn(s, convey("-f charset,,,iso-8859-2", text=encoded.decode("utf-8")))

    def test_base64_disambiguation(self):
        """Base64 must not mix up with I.E. hostname"""
        c = Convey("--single-detect")
        self.assertIn("hostname", c("example.com"))  # hostname must not be confounded with base64
        self.assertFalse(c("base"))  # 'base' is plaintext

        c = Convey("--single-query")
        self.assertIn("m«", c("base -t base64"))  # 'base' can be base64 if explicitly told

    def test_phone_detection(self):
        """Various phone formats must pass."""
        c = Convey("--single-detect")
        self.assertIn("timestamp", c("2020-02-29"))  # date value must not be confused with the phone regex
        for phone in ("+420123456789", "+1-541-754-3010", "1-541-754-3010", "001-541-754-3010", "+49-89-636-4801"):
            self.assertIn("phone", c(phone), phone)

    def test_pint(self):
        """Test unit conversion works"""
        c = Convey()
        self.assertIn("unit", c("--single-detect", text="1 kg"))
        self.assertIn("2.6792288807189983 troy_pound", c("-f unit[troy_pound]", text="1 kg"))

    def test_wrong_url(self):
        c = Convey()
        self.assertEqual("http://example.com", c("-f url", text="hXXp://example.com")[0])
        self.assertEqual("https://an.eXAmple.com", c("-f url", text="hxxps://an[.]eXAmple[.]com")[0])
        self.assertEqual("http://185.33.144.243/main_content/", c("-f url", text="hxxp://185.33.144[.]243/main_content/")[0])
        self.assertEqual("http://80.211.218.7/fb/", c("-f url", text="80.211.218.7/fb/")[0])

    def test_hostname(self):
        self.assertIn("hostname", convey("--single-detect", text="_spf.google.com"))

    def test_timestamp(self):
        self.assertIn("timestamp", convey("--single-detect", text="26. 03. 1999"))
        time = datetime.now()
        self.assertIn("timestamp", convey("--single-detect", text=str(time)))
        self.assertIn("timestamp", convey("--single-detect", text=str(int(time.timestamp()))))

        # as of Python3.7 use:
        # distant_future = datetime.fromisoformat("3000-01-01")  # it is less probable distant dates are dates
        distant_future = datetime.fromtimestamp(32503680000.0)

        self.assertIn("timestamp", convey("--single-detect", text=str(distant_future)))
        self.assertIn("phone", convey("--single-detect", text=str(int(distant_future.timestamp()))))
        # there is no path to datetype date from a phone
        self.assertIn("No suitable column found for field 'date'", convey("-S -f date", text=str(distant_future.timestamp())))
        # however, is is possible to get a date if specified
        self.assertIn("3000-01-01", convey("-t timestamp -f date", text=str(int(distant_future.timestamp()))))
        # works for float numbers too
        self.assertIn("3000-01-01", convey("-t timestamp -f date", text=str(distant_future.timestamp())))

        # short number is not considered a timestamp from the beginning of the Unix epoch (1970)
        self.assertEqual([], convey("--single-detect", text="12345"))
