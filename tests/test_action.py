from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from shared import (
    CONSUMPTION,
    COMBINED_LIST_METHOD,
    COMBINED_SHEET_PERSON,
    GIF_CSV,
    MERGE_MAIN_CSV,
    MERGE_REMOTE_A_CSV,
    MERGE_REMOTE_B_CSV,
    PERSON_CSV,
    PERSON_GIF_CSV,
    PERSON_HEADER_CSV,
    SHEET_CSV,
    SHEET_HEADER_CSV,
    SHEET_HEADER_ITSELF_CSV,
    SHEET_HEADER_PERSON_CSV,
    SHEET_PERSON_CSV,
    TestAbstract,
    Convey,
    PROJECT_DIR,
    p,
)


class TestAction(TestAbstract):
    def test_aggregate(self):
        self.check(
            ["sum(price)", "972.0"], f"--aggregate price,sum", filename=CONSUMPTION
        )
        self.check(
            ["category,sum(price)", "total,972.0", "kettle,602.0", "bulb,370.0"],
            f"--aggregate price,sum,category",
            filename=CONSUMPTION,
        )
        self.check(
            [
                "category,sum(price),avg(consumption)",
                "total,972.0,41.0",
                "kettle,602.0,75.0",
                "bulb,370.0,18.33",
            ],
            f"--aggregate price,sum,consumption,avg,category",
            filename=CONSUMPTION,
        )
        self.check(
            [
                "category,sum(price),list(price)",
                "total,972.0,(all)",
                '''kettle,602.0,"['250', '352']"''',
                '''bulb,370.0,"['100', '150', '120']"''',
            ],
            f"--aggregate price,sum,price,list,category",
            filename=CONSUMPTION,
        )

        # XX this will correctly split the files,
        # however, the output is poor and for a reason not readable by the check.
        # self.check(['','Split location: bulb','','Split location: kettle'],
        #            "--agg price,sum --split category", filename=CONSUMPTION)
        # Until then, following substitution is used to generate the files at least
        Convey(filename=CONSUMPTION)("--aggregate price,sum --split category")

        # Check the contents of the files that just have been split
        check1 = False
        check2 = False
        for f in CONSUMPTION.parent.glob(f"{CONSUMPTION.name}_convey*/*"):
            if f.name == "kettle" and f.read_text() == "sum(price)\n602.0\n":
                check1 = True
            if f.name == "bulb" and f.read_text() == "sum(price)\n370.0\n":
                check2 = True
        self.assertTrue(check1)
        self.assertTrue(check2)

    def test_aggregate_group_col(self):
        # group by a column without any additional info means counting
        self.check(
            [
                "price,count(price)",
                "total,5",
                "100,1",
                "150,1",
                "250,1",
                "352,1",
                "120,1",
            ],
            f"-a price",
            filename=CONSUMPTION,
        )

        # group by the same column works
        self.check(
            [
                "price,sum(price)",
                "total,972.0",
                "352,352.0",
                "250,250.0",
                "150,150.0",
                "120,120.0",
                "100,100.0",
            ],
            f"--aggregate price,sum,price",
            filename=CONSUMPTION,
        )

        self.check(
            [
                "price,count(price)",
                "total,5",
                "100,1",
                "150,1",
                "250,1",
                "352,1",
                "120,1",
            ],
            f"--aggregate price,count,price",
            filename=CONSUMPTION,
        )

        # group by a different column when counting does not make sense
        msg = "ERROR:convey.action_controller:Count column 'price' must be the same as the grouping column 'consumption'."
        with self.assertLogs(level="WARNING") as cm:
            self.check("", f"--aggregate price,count,consumption", filename=CONSUMPTION)
            self.assertEqual([msg], cm.output)

    def test_merge(self):
        # merging generally works
        self.check(
            COMBINED_SHEET_PERSON, f"--merge {PERSON_CSV},2,1", filename=SHEET_CSV
        )

        # rows can be duplicated due to other fields
        self.check(
            COMBINED_LIST_METHOD,
            f"--merge {PERSON_CSV},2,1 -f external,1,"
            + str(p("external_pick_base.py"))
            + ",list_method",
            filename=SHEET_CSV,
        )

        # merging file with header and with a missing value
        self.check(
            SHEET_PERSON_CSV, f"--merge {PERSON_HEADER_CSV},2,1", filename=SHEET_CSV
        )

        # merge on a column type
        self.check(
            PERSON_GIF_CSV, f"--merge {GIF_CSV},email,email", filename=PERSON_CSV
        )

        # merge by a column number
        self.check(PERSON_GIF_CSV, f"--merge {GIF_CSV},email,1", filename=PERSON_CSV)

        # merge two files at once, each by a different local column
        self.check(
            [
                "name,id_a,id_b,color,size,city,zip",
                "alice,a1,b2,red,S,Brno,60200",
                "bob,a2,b1,green,M,Praha,11000",
                "carol,a3,b3,blue,L,Ostrava,70200",
            ],
            f"--merge {MERGE_REMOTE_A_CSV},1,2 --merge {MERGE_REMOTE_B_CSV},1,3",
            filename=MERGE_MAIN_CSV,
        )

        # invalid column definition
        msg = "ERROR:convey.identifier:Cannot identify COLUMN invalid, put there an exact column name, its type, the numerical order starting with 1, or with -1."
        with self.assertLogs(level="WARNING") as cm:
            self.check("", f"--merge {GIF_CSV},email,invalid", filename=PERSON_CSV)
            self.assertEqual([msg], cm.output)

        return  # TODO – delimiter changed, detect why
        # merging a file with itself
        self.check(
            SHEET_HEADER_ITSELF_CSV,
            f"--merge {SHEET_HEADER_CSV},4,2",
            filename=SHEET_HEADER_CSV,
        )

        # only local file has header; different dialects
        self.check(
            SHEET_HEADER_PERSON_CSV,
            f"--merge {PERSON_CSV},2,1",
            filename=SHEET_HEADER_CSV,
        )

    def test_compute_from_merge(self):
        """Computing a new column from another file currenlty being merged was not implemented."""
        self.check(
            "Column ID 6 does not exist. We have these so far: foo, red, second.example.com",
            f"--merge {PERSON_CSV},2,1 -f base64,6",
            filename=SHEET_CSV,
        )

    def test_sort(self):
        # pick and reorder columns by their position, name or position from the right
        for cols in ("2,1", "price,category", "-2,1"):
            self.check(
                ["price,category", "100,bulb", "150,bulb", "250,kettle", "352,kettle", "120,bulb"],
                f"--sort {cols}",
                filename=CONSUMPTION,
            )

    def test_field_order(self):
        """An excluded field may be referred by its column number in the order of the CLI flags."""
        self.check("aGVsbG8%3D", "-fe base64 -f urlencode,2,plaintext", text="hello")


class TestCachedRun(TestAbstract):
    """Without --reprocess, the cache of the previous run is used."""

    def run_convey(self, cwd, *args):
        cmd = [str(PROJECT_DIR / "convey.py"), "--daemon", "False", "--headless", "--github-crash-submit", "False", *args]
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.splitlines()

    def test_headless_output_twice(self):
        with TemporaryDirectory() as temp:
            shutil.copy(str(CONSUMPTION), temp)
            for _ in range(2):  # the second run has nothing new to process, still prints the result
                out = self.run_convey(temp, "consumption.csv", "-f", "base64,1", "--output")
                self.assertEqual("bulb,100,30,YnVsYg==", out[1])
            # relative output path is relative to CWD; the cached run does not stick to the previous stdout
            self.run_convey(temp, "consumption.csv", "--output", "out.csv")
            self.assertEqual("bulb,100,30,YnVsYg==", Path(temp, "out.csv").read_text().splitlines()[1])

    def test_split_aggregate(self):
        with TemporaryDirectory() as temp:
            shutil.copy(str(CONSUMPTION), temp)
            out = self.run_convey(temp, "consumption.csv", "-a", "price,sum", "--split", "category", "--output")
            self.assertIn("* Saved to bulb", out)
            self.assertIn("370.0", out)
            self.assertIn("602.0", out)
