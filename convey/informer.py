import csv
import datetime
import logging
import subprocess
import sys
from itertools import zip_longest
from math import ceil
from pathlib import Path

import humanize
from tabulate import tabulate

from .config import Config, get_terminal_width


class Informer:
    """ Prints analysis data in nice manner. """

    def __init__(self, csv):
        self.csv = csv

    def sout_info(self, clear=True, full=False):
        if Config.verbosity >= logging.WARNING:
            return

        """ Prints file information on the display. """
        if clear:
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            # os.system('cls' if os.name == 'nt' else 'clear')
        # sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        # print(chr(27) + "[2J")
        l = []
        l.append("Source file: " + str(self.csv.source_file) if self.csv.source_file else "Reading STDIN")
        if self.csv.dialect:
            l.append("delimiter: '" + self.csv.dialect.delimiter + "'")
            l.append("quoting: '" + self.csv.dialect.quotechar + "'")
        if self.csv.has_header is not None:
            l.append("header: " + ("used" if self.csv.has_header else "not used"))
        if self.csv.settings["filter"]:
            l.append("Filter: " + ", ".join([f"{self.csv.fields[f]}({val})" for f, val in self.csv.settings["filter"]]))
        if self.csv.settings["unique"]:
            l.append("Unique col: " + ", ".join([self.csv.fields[f] for f in self.csv.settings["unique"]]))
        if self.csv.settings["split"]:
            l.append("Split by: {}".format(self.csv.fields[self.csv.settings["split"]]))

        # XX
        # if self.csv.redo_invalids is not None:
        #    l.append("Redo invalids: " + str(self.csv.redo_invalids))
        sys.stdout.write(", ".join(l))

        if self.csv.settings["add"]:
            l2 = []
            for f in self.csv.settings["add"]:
                l2.append(f"{f} (from {str(f.source_field)})")
            sys.stdout.write("\nComputed columns: " + ", ".join(l2))
        l = []
        if self.csv.line_count:
            if self.csv.ip_count:
                sys.stdout.write(", {} IPs".format(self.csv.ip_count))
            elif self.csv.ip_count_guess:
                sys.stdout.write(", around {} IPs".format(self.csv.ip_count_guess))
            l.append("\nLog lines processed: {}/{}, {} %".format(self.csv.line_count, self.csv.lines_total,
                                                                 ceil(100 * self.csv.line_count / self.csv.lines_total)))
        else:
            l.append("\nLog lines: {}".format(self.csv.lines_total))
        if self.csv.time_end:
            l.append("{}".format(self.csv.time_end - self.csv.time_start))
        elif self.csv.time_start:
            l.append(f"{datetime.datetime.now().replace(microsecond=0) - self.csv.time_start}")
            l.append(f"{self.csv.velocity} lines / s")
            l.append(f"{self.csv.processor.descriptors_count} file descriptors open")
        sys.stdout.write(", ".join(l) + "\n")
        if self.csv.whois_stats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.csv.whois_stats.items())
                  + f"; {len(self.csv.ranges)} prefixes discovered")

        print("\nSample:\n" + "".join(self.csv.sample[:4]))  # show first 3rd lines

        if self.csv.is_formatted:
            print("\nExperimental output XXX XXXX předělat X:")
            # rows = [x for x in self.csv.sample_parsed]
            rows = self.csv.sample_parsed
            # print(tabulate(rows, headers=self.csv.first_line_fields))

            shorten = lambda x: x[:17] + "..." if len(x) > 20 else x
            rows = []
            for l in self.csv.sample_parsed:
                row = []

                for f, c in zip_longest(self.csv.fields, l):
                    if c:
                        c = shorten(c)
                    else:
                        c = l[self.csv.fields.index(f.source_field)]
                        # try:
                        for m in f.get_methods() or ():
                            c = m(c)
                        if isinstance(c, tuple):
                            c = c[1] or "unknown"
                        # except:
                        #     c = "X"
                        # c = "..."
                    if not f.is_chosen:
                        row.append("\x1b[9m{}\x1b[0m".format(c or "empty"))
                    else:
                        row.append(c)
                rows.append(row)
                # print(",".join(row))
            header = [f.get() for f in self.csv.fields]
            # print(rows)
            # XXX header = [f"{x} ({y})" for x, y in zip(self.csv.first_line_fields, self.csv.identifier.field_type.values())]
            # ... ...
            tab = tabulate(rows, headers=header)
            if len(tab.split("\n")[0]) <= get_terminal_width():
                print(tab)
            else:
                print("Result:")
                s = ", ".join([f.name for f in self.csv.fields]) + "\n" + "\n".join([", ".join(r) for r in rows])
                print(s)

                lines = [[h + ": "] for h in header]
                for r in rows:
                    for i, f in enumerate(r):
                        lines[i].append(f)
                print(tabulate(lines, tablefmt="plain"))
        if self.csv.settings["dialect"] or [f for f in self.csv.fields if (not f.is_chosen) or f.is_new]:
            ar = []
            for i, f in enumerate(self.csv.fields):
                if not self.csv.fields[i].is_chosen:
                    ar.append(" \x1b[9m{}\x1b[0m".format(f or "empty"))
                else:
                    ar.append(" " + str(f))
            if ar:
                print("Fields after processing: ", end="")
                csv.writer(sys.stdout, dialect=self.csv.settings["dialect"] or self.csv.dialect).writerow(ar)
            output = Config.get("output")
            if output:
                print(f"Output file specified: {output}")

        if self.csv.is_analyzed:
            if self.csv.target_file is False:
                print("\n** Processing completed, results were not saved to a file.")
            elif self.csv.target_file:
                print(f"\n** Processing completed: Result file in {self.csv.target_file}")
            else:
                partner_count, abuse_count, non_deliverable, totals = map(self.csv.stats.get, (
                    'partner_count', 'abuse_count', 'non_deliverable', 'totals'))

                print(f"** Processing completed: {totals} result files in {Config.get_cache_dir()}")
                # abuse_count = Contacts.count_mails(self.attachments.keys(), abusemails_only=True)
                # partner_count = Contacts.count_mails(self.attachments.keys(), partners_only=True)
                if totals == non_deliverable:
                    print("* It seems no file is meant to serve as an e-mail attachment.")
                else:
                    if abuse_count[0] + partner_count[0] == 0:
                        print(
                            "Already sent all {} partner e-mails and {} other e-mails".format(partner_count[1], abuse_count[1]))
                    if abuse_count[1] + partner_count[1] > 1:
                        print("* already sent {}/{} partner e-mails\n* {}/{} other e-mails".format(partner_count[1],
                                                                                                   sum(partner_count),
                                                                                                   abuse_count[1],
                                                                                                   sum(abuse_count)))
                    else:
                        print(
                            "* {} files seem to be attachments for partner e-mails\n* {} for other e-mails".format(partner_count[0],
                                                                                                                   abuse_count[0]))
                    if non_deliverable:
                        print("* {} files undeliverable".format(non_deliverable))

                if Config.get('testing'):
                    print(
                        "\n*** TESTING MOD - mails will be send to mail {} ***\n (For turning off testing mode set `testing = False` in config.ini.)".format(
                            Config.get('testing_mail')))

            stat = self.get_stats_phrase()
            print("\n Statistics overview:\n" + stat)
            if Config.get("write_statistics") and self.csv.source_file:
                # we write statistics.txt only if we're sourcing from a file, not from stdin
                with open(Path(Path(self.csv.source_file).parent, "statistics.txt"), "w") as f:
                    f.write(stat)
            """
            XX
            if csv.abuseReg.stat("records", False):
                print("Couldn't find {} abusemails for {}× IP.".format(csv.reg["local"].stat("records", False), csv.reg["local"].stat("ips", False)))
            if csv.countryReg.stat("records", False):
                print("Couldn't find {} csirtmails for {}× IP.".format(csv.reg["foreign"].stat("records", False), csv.reg["foreign"].stat("ips", False)))
            """

        if full:
            if len(self.csv.ranges.items()):
                rows = []
                for prefix, o in self.csv.ranges.items():
                    prefix, location, incident, asn, netname, country, abusemail = o
                    rows.append((prefix, location, incident or "-", asn or "-", netname or "-"))
                print("\n\n** Whois information overview **\n",
                      tabulate(rows, headers=("prefix", "location", "contact", "asn", "netname")))
            else:
                print("No whois information available.")

            if self.csv.is_split:
                rows = []
                for o in self.csv.attachments:
                    rows.append((o.path,
                                 {True: "partner", False: "✓", None: "×"}[o.partner],
                                 {True: "✓", False: "error", None: "no"}[o.sent],
                                 humanize.naturalsize(Path(o.get_abs_path()).stat().st_size),
                                 ))
                print("\n\n** Generated files overview **\n", tabulate(rows, headers=("file", "deliverable", "sent", "size")))
            # else:
            #     print("Files overview not needed – everything have been processed into a single file.")

            print("\n\nPress enter to continue...")

    def get_stats_phrase(self, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        st = self.csv.stats

        ips_unique = len(st["ipsUnique"])
        isp_cz_found = len(st["ispCzFound"])
        ips_cz_missing = len(st["ipsCzMissing"])
        ips_cz_found = len(st["ipsCzFound"])
        ips_world_missing = len(st["ipsWorldMissing"])
        ips_world_found = len(st["ipsWorldFound"])
        countries_missing = len(st["countriesMissing"])
        countries_found = len(st["countriesFound"])

        """         XX
        invalidLines = self.csv.invalidReg.stat()
        """

        if ips_unique > 0:
            res = "Totally {} of unique IPs".format(ips_unique)
        else:
            res = "No IP addresses"
        if ips_world_found or countries_found:
            res += "; information for {} countries".format(countries_found) \
                   + " ({} unique IPs)".format(ips_world_found)
        if ips_world_missing or countries_missing:
            res += ", no contact for {} countries without national/goverment CSIRT".format(countries_missing) \
                   + " ({} unique IPs)".format(ips_world_missing)
        if ips_cz_found or isp_cz_found:
            res += "; {} unique local IPs".format(ips_cz_found) \
                   + " distributed for {} ISP".format(isp_cz_found)
        if ips_cz_missing:
            res += " (for {} unique local IPs ISP not found).".format(ips_cz_missing)

        """ XX
        if invalidLines:
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.csv.invalidReg.getPath())"""

        return res

    def source_file_len(self):
        """ When a source file is reasonably small (100 MB), count the lines by `wc -l`. Otherwise, guess a value.
            XIf we are using stdin instead of a file, determine the value by enlist all the lines.
        """
        if self.csv.size < 100 * 10 ** 6:
            p = subprocess.Popen(['wc', '-l', self.csv.source_file], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            return int(result.strip().split()[0])
        else:
            # bytes / average number of characters on line in sample
            return ceil(self.csv.size / (len("".join(self.csv.sample)) / len(self.csv.sample)) / 1000000) * 1000000
