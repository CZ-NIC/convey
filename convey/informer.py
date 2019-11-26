import subprocess
import sys
from csv import writer
from datetime import datetime
from itertools import cycle
from math import ceil
from pathlib import Path

import humanize
from tabulate import tabulate

from .config import Config, get_terminal_size
from .types import Aggregate
from .whois import Whois


class Informer:
    """ Prints analysis data in nice manner. """

    def __init__(self, parser):
        self.parser = parser

    def sout_info(self, clear=True, full=False):
        if Config.is_quiet():
            return

        """ Prints file information on the display. """
        if clear and not Config.get("daemon", get=bool):
            sys.stderr.write("\x1b[2J\x1b[H")
            sys.stderr.flush()
            # os.system('cls' if os.name == 'nt' else 'clear')
        # sys.stderr.write("\x1b[2J\x1b[H") # clears gnome-terminal
        # print(chr(27) + "[2J")
        l = []
        l.append("Reading STDIN" if self.parser.stdin else "Source file: " + str(self.parser.source_file))
        if self.parser.dialect:
            l.append("delimiter: '" + self.parser.dialect.delimiter + "'")
            l.append("quoting: '" + self.parser.dialect.quotechar + "'")
        if self.parser.has_header is not None:
            l.append("header: " + ("used" if self.parser.has_header else "not used"))
        if self.parser.settings["filter"]:
            l.append("Filter: " + ", ".join([f"{self.parser.fields[f].name}({val})" for f, val in self.parser.settings["filter"]]))
        if self.parser.settings["unique"]:
            l.append("Unique col: " + ", ".join([self.parser.fields[f].name for f in self.parser.settings["unique"]]))
        if self.parser.settings["split"]:
            l.append("Split by: {}".format(self.parser.fields[self.parser.settings["split"]]))
        if self.parser.settings["aggregate"]:
            # settings["aggregate"] = column to be grouped, [(sum, column to be summed)]
            # Ex: settings["aggregate"] = 1, [(Aggregate.sum, 2), (Aggregate.avg, 3)]
            v = ", ".join(f"{fn.__name__}({self.parser.fields[col].name})" for fn, col in self.parser.settings["aggregate"][1])
            if self.parser.settings["aggregate"][0] is not None:
                l.append(f"Group by {self.parser.fields[self.parser.settings['aggregate'][0]]}: " + v)
            else:
                l.append("Aggregate: " + v)

        # XX
        # if self.parser.redo_invalids is not None:
        #    l.append("Redo invalids: " + str(self.parser.redo_invalids))
        sys.stdout.write(", ".join(l))

        l3 = []
        for f in self.parser.fields:
            if not f.is_new and f.has_clear_type():
                t = ", ".join([str(t) for t in f.possible_types])
                l3.append(f.color(f"{f} ({t})"))
        sys.stdout.write("\nIdentified columns: " + ", ".join(l3))
        if self.parser.settings["add"]:
            l2 = []
            for f in self.parser.settings["add"]:
                l2.append(f.color(f"{f} (from {str(f.source_field)})"))
            sys.stdout.write("\nComputed columns: " + ", ".join(l2))
        l = []
        progress = 0
        if self.parser.line_count:
            if self.parser.ip_count:
                sys.stdout.write(", {} IPs".format(self.parser.ip_count))
            elif self.parser.ip_count_guess:
                sys.stdout.write(", around {} IPs".format(self.parser.ip_count_guess))
            l.append("Log lines processed: {}/{}, {} %".format(self.parser.line_count, self.parser.lines_total,
                                                               ceil(100 * self.parser.line_count / self.parser.lines_total)))
            progress = self.parser.line_count / self.parser.lines_total
        else:
            l.append("Log lines: {}".format(self.parser.lines_total))
        if self.parser.time_end:
            l.append("{}".format(self.parser.time_end - self.parser.time_start))
        elif self.parser.time_start:
            l.append(f"{datetime.now().replace(microsecond=0) - self.parser.time_start}")
            l.append(f"{self.parser.velocity} lines / s")
            l.append(f"{self.parser.processor.descriptors_count} file descriptors open")
        if self.parser.queued_lines_count:
            if len(Whois.queued_ips) != self.parser.queued_lines_count:
                v = f" lines ({len(Whois.queued_ips)} unique IPs)"
            else:
                v = " lines"
            s = f"skipped {self.parser.queued_lines_count}{v} due to LACNIC quota"
            if Whois.quota.is_running():
                s += f" till {Whois.quota.time()}"
            l.append(s)
        r = ", ".join(l)
        if progress:
            _, width = get_terminal_size()
            progress = round(progress * width) if width else 0
            if len(r) < progress:
                r += " " * (progress - len(r))
            r = f"\033[7m{r[:progress]}\033[0m" + r[progress:]
        sys.stdout.write("\n" + r + "\n")
        if self.parser.whois_stats:
            print("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in self.parser.whois_stats.items())
                  + f"; {len(self.parser.ranges)} prefixes discovered")

        print("\nSample:\n" + "".join(self.parser.sample[:4]))  # show first 3rd lines

        if self.parser.is_formatted:  # show how would the result be alike
            full_rows, rows = self.parser.get_sample_values()

            first_line_length = tabulate(rows, headers=[f.get(True, color=False) for f in self.parser.fields]).split("\n")[0]
            if rows and not self.parser.settings["dialect"] and len(first_line_length) <= get_terminal_size()[1]:
                # print big and nice table because we do not care about the dialect and terminal is wide enough
                print("\033[0;36mPreview:\033[0m")
                header = [f.get(True) for f in self.parser.fields]
                print(tabulate(rows, headers=header))
            else:
                # print the rows in the same way so that they optically match the Sample above
                print("\033[0;36mCompact preview:\033[0m")
                cw = writer(sys.stdout, dialect=self.parser.settings["dialect"] or self.parser.dialect)
                cw.writerow([f.get() for f in self.parser.fields])
                for r in full_rows:
                    cw.writerow(r)

        output = Config.get("output")
        if output:
            print(f"Output file specified: {output}")

        if self.parser.aggregation:  # an aggregation has finished
            print("\n")
            if len(self.parser.aggregation) == 1:
                print(self.get_aggregation(next(iter(self.parser.aggregation.values())), color=True, limit=8))
            else:
                print("Aggregating in split files...")

        if self.parser.is_analyzed:
            if self.parser.saved_to_disk is False:
                print("\n** Processing completed, results were not saved to a file yet.")
                print(tabulate(self.parser.stdout_sample, headers="firstrow" if self.parser.has_header else ()))
            elif self.parser.saved_to_disk:
                print(f"\n** Processing completed: Result file in {self.parser.target_file}")
            else:
                partner_count, abuse_count, non_deliverable, totals = map(self.parser.stats.get, (
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
            if Config.get("write_statistics") and not self.parser.stdin:
                # we write statistics.txt only if we're sourcing from a file, not from stdin
                # XX move this to parser.run_analysis and _resolve_again or to Processor – do not rewrite it every time here!
                with open(Path(Path(self.parser.source_file).parent, "statistics.txt"), "w") as f:
                    f.write(stat)
            """
            XX
            if parser.abuseReg.stat("records", False):
                print("Couldn't find {} abusemails for {}× IP.".format(parser.reg["local"].stat("records", False), parser.reg["local"].stat("ips", False)))
            if parser.countryReg.stat("records", False):
                print("Couldn't find {} csirtmails for {}× IP.".format(parser.reg["foreign"].stat("records", False), parser.reg["foreign"].stat("ips", False)))
            """

        if full:
            # XX subprocess.run("less", input=v, encoding="utf-8")
            # XX show aggregation too
            if len(self.parser.ranges.items()):
                rows = []
                for prefix, o in self.parser.ranges.items():
                    prefix, location, incident, asn, netname, country, abusemail, timestamp = o
                    rows.append((prefix, location, incident or "-", asn or "-", netname or "-"))
                print("\n\n** Whois information overview **\n",
                      tabulate(rows, headers=("prefix", "location", "contact", "asn", "netname")))
            else:
                print("No whois information available.")

            if self.parser.is_split:
                rows = []
                for o in self.parser.attachments:
                    rows.append((o.path,
                                 {True: "partner", False: "✓", None: "×"}[o.partner],
                                 {True: "✓", False: "error", None: "no"}[o.sent],
                                 humanize.naturalsize(Path(o.get_abs_path()).stat().st_size),
                                 ))
                print("\n\n** Generated files overview **\n", tabulate(rows, headers=("file", "deliverable", "sent", "size")))
            # else:
            #     print("Files overview not needed – everything have been processed into a single file.")

            print("\n\nPress enter to continue...")

    def get_aggregation(self, data, color=False, limit=None):
        form = lambda v, fmt: f"\033[{fmt}m{v}\033[0m" if color else v
        header = []
        grouping = self.parser.settings["aggregate"][0] is not None
        if grouping:
            header.append(form(self.parser.fields[self.parser.settings["aggregate"][0]].name, 36))
        header.extend([form(f"{fn.__name__}({self.parser.fields[col]})", 33) for fn, col in self.parser.settings["aggregate"][1]])

        rows = []
        generators = cycle(g[0] for g in self.parser.settings["aggregate"][1])

        for i, (row, d) in enumerate(data.items()):
            if limit and i == limit:
                rows.append(["..." for fn, count in d])
                break
            if row is None and len(self.parser.settings["aggregate"][1]) == 1 \
                    and next(generators) == Aggregate.list:
                # This is the total row
                # We are aggregating only single thing which is list.
                # That list would comprehend all of the values in the column. We omit it.
                continue

            # import ipdb; ipdb.set_trace()
            # rows.append([form(count if fn.__name__ in ("count", "list") else round(count * 100) / 100, 33) for fn, count in d])
            rows.append([form(count if next(generators) not in (Aggregate.sum, Aggregate.avg) else round(count * 100) / 100, 33) for
                         fn, count in d])
            if grouping:
                rows[-1].insert(0, form("total" if row is None else row, 36))
        return tabulate(rows, header)

    def get_stats_phrase(self, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        st = self.parser.stats

        ips_unique = len(st["ipsUnique"])
        isp_cz_found = len(st["ispCzFound"])
        ips_cz_missing = len(st["ipsCzMissing"])
        ips_cz_found = len(st["ipsCzFound"])
        ips_world_missing = len(st["ipsWorldMissing"])
        ips_world_found = len(st["ipsWorldFound"])
        countries_missing = len(st["countriesMissing"])
        countries_found = len(st["countriesFound"])

        """         XX
        invalidLines = self.parser.invalidReg.stat()
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
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.parser.invalidReg.getPath())"""

        return res

    def source_file_len(self, source_file):
        """ When a source file is reasonably small (100 MB), count the lines by `wc -l`. Otherwise, guess a value.
            XIf we are using stdin instead of a file, determine the value by enlist all the lines.
        """
        size = Path(source_file).stat().st_size
        if size < 100 * 10 ** 6:
            p = subprocess.Popen(['wc', '-l', source_file], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            return int(result.strip().split()[0]), size
        else:
            # bytes / average number of characters on line in sample
            return ceil(size / (len("".join(self.parser.sample)) / len(self.parser.sample)) / 1000000) * 1000000, size
