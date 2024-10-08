import os
from pathlib import Path
from unittest import TestCase

from tests.shared import GIF_CSV, PROJECT_DIR, SHEET_CSV, TESTDATA_DIR, Convey, p


class TestSending(TestCase):
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
        convey = Convey("--output", "False", filename=GIF_CSV)
        cmd_pattern = "-t abusemail,path --split abusemail --send-test {mail} 'bare_template.eml' "

        cmd = cmd_pattern + "--attach-files False --attach-paths-from-path-column True"

        os.chdir(PROJECT_DIR / TESTDATA_DIR)

        # Single image is attached
        lines = convey(cmd.format(mail="john@example.com"))
        self.assertIn(BLACK, lines[0])
        lines = convey(cmd.format(mail="mary@example.com"))
        self.assertIn(WHITE, lines[0])

        # Two images are attached
        lines = convey(cmd.format(mail="jack@example.com"))
        self.assertIn(BLACK, lines[0])
        self.assertIn(WHITE, lines[4])

        # Image cannot be attached
        lines = convey(cmd.format(mail="hyacint@example.com"))
        self.assertIn(
            "Convey crashed at For security reasons, path must be readable to others: red-permission.gif", lines[0])

        # Flags controlling attachments work
        lines = convey(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files True --attach-paths-from-path-column False")
        self.assertIn(COLOURS, lines[0])
        lines = convey(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files True --attach-paths-from-path-column True")
        self.assertIn(COLOURS, lines[0])
        self.assertIn(BLACK, lines[1])
        lines = convey(cmd_pattern.format(mail="john@example.com") +
                       "--attach-files False --attach-paths-from-path-column False")
        self.assertNotIn(COLOURS, lines[0])
        self.assertNotIn(BLACK, lines[1])
