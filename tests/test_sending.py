from contextlib import redirect_stderr
import io
import os
from pathlib import Path
from unittest import TestCase

from tests.shared import GIF_CSV, PROJECT_DIR, SHEET_CSV, TESTDATA_DIR, Convey, TestAbstract


class TestSending(TestAbstract):
    def test_dynamic_template(self):
        convey = Convey("--output", "False", filename=SHEET_CSV)
        cmd = """--field code,3,'x="example@example.com" if "example.com" in x else x+"@example.com"'""" \
              " --split code --send-test {mail} 'email_template.eml' --headless"

        os.chdir(PROJECT_DIR / TESTDATA_DIR)

        lines = convey(cmd.format(mail="example@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a long amount of lines!', lines)
        self.assertIn('We send you lots of colours: red, green, yellow.', lines)
        self.assertIn('foo,green,first.example.com,example@example.com', lines)
        # attachment must not be present because we called attachment() in the template
        self.assertNotIn('Attachment', lines[0])

        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        self.assertIn('Subject: My cool dynamic template demonstrating a short amount of lines!', lines)
        self.assertIn('We send you single colour: orange.', lines)
        self.assertIn('Attachment sheet.csv (text/csv):', lines[0])

        cmd += " --header"  # we force first row to be a header
        lines = convey(cmd.format(mail="wikipedia.com@example.com"))
        # even though there is header in the file, we should still get single value
        self.assertIn('We send you single colour: orange.', lines)

    # XX we should test body, subject, references flag
    # def test_body_flag(self):
    #     convey = Convey(FILTER_FILE)
    #     cmd = """--body "body text" """

    def test_send(self):
        BLACK = "Attachment black.gif (image/gif)"
        WHITE = "Attachment white.gif (image/gif)"
        COLOURS = "Attachment gif.csv (text/csv)"
        cmd_pattern = "-t abusemail,path --split abusemail --send-test {mail} 'bare_template.eml' "
        cmd = cmd_pattern + "--attach-files False --attach-paths-from-path-column True"

        os.chdir(PROJECT_DIR / TESTDATA_DIR)

        def ch(c, logs=None):
            return self.check(cmd=c.format(mail="john@example.com"), filename=GIF_CSV, logs=logs)

        # Single image is attached
        lines = ch(cmd.format(mail="john@example.com")).stdout
        self.assertIn(BLACK, lines[19])
        lines = ch(cmd.format(mail="mary@example.com")).stdout
        self.assertIn(WHITE, lines[19])

        # Two images are attached
        lines = ch(cmd.format(mail="jack@example.com")).stdout
        self.assertIn(BLACK, lines[19])
        self.assertIn(WHITE, lines[23])

        # Image cannot be attached
        ch(cmd.format(mail="hyacint@example.com"), logs='INFO:convey.dialogue:For security reasons, path must be readable to others: red-permission.gif')

        # Flags controlling attachments work
        lines = ch(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files True --attach-paths-from-path-column False").stdout
        self.assertIn(COLOURS, lines[19])
        lines = ch(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files True --attach-paths-from-path-column True").stdout
        self.assertIn(COLOURS, lines[19])
        self.assertIn(BLACK, lines[20])

        lines = ch(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files False --attach-paths-from-path-column False").stdout
        self.assertNotIn(COLOURS, lines[19])
        self.assertNotIn(BLACK, lines[20])
