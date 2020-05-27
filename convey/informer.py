import subprocess
import sys
from collections import deque
from csv import writer
from datetime import datetime
from io import StringIO
from itertools import cycle, count
from math import ceil, log10
from pathlib import Path
from threading import Event, Thread
from time import sleep

import humanize
from colorama import Fore
from tabulate import tabulate

from .config import Config, get_terminal_size
from .types import Aggregate
from .whois import Whois


class Informer:
    """ Prints analysis data in nice manner. """

    def __init__(self, parser):
        self.parser = parser
        self.queue = deque(maxlen=10)
        self.stdout = sys.stdout
        self.stats_stop = Event()  # if ._flag is True, ends, if is 1, pauses, if is False, runs

    def sout_info(self, clear=True, full=False):
        """ Prints file information on the display. """
        if Config.is_quiet():
            return

        stdout = StringIO()

        if clear and not Config.get("daemon", get=bool):
            stdout.write("\x1b[2J\x1b[H")

        def print_s(s):
            stdout.write(s + "\n")

        l = []
        p = self.parser
        se = p.settings
        l.append("Reading STDIN" if p.stdin else "Source file: " + str(p.source_file))
        if p.dialect:
            s = p.dialect.delimiter.replace("\t", "TAB")
            if se["dialect"] and p.dialect.delimiter != se["dialect"].delimiter:
                s2 = se['dialect'].delimiter.replace("\t", "TAB")
                s = f"{s} → {s2}"
            l.append(f"delimiter: '{Fore.YELLOW}{s}{Fore.RESET}'")

            s = p.dialect.quotechar
            if se["dialect"] and p.dialect.quotechar != se["dialect"].quotechar:
                s = f"{s} → {se['dialect'].quotechar}"
            l.append(f"quoting: '{Fore.YELLOW}{s}{Fore.RESET}'")
        if p.has_header is not None:
            l.append("header: " + (("remove" if se["header"] is False else "used") if p.has_header else "not used"))
        if se["filter"]:
            l.append("Filter: " + ", ".join([f"{p.fields[f].name} {'' if include else '!'}= {val}"
                                             for include, f, val in se["filter"]]))
        if se["unique"]:
            l.append("Unique col: " + ", ".join([p.fields[f].name for f in se["unique"]]))
        if se["split"] or se["split"] is 0:
            l.append("Split by: {}".format(p.fields[se["split"]]))
        if se["aggregate"]:
            # settings["aggregate"] = column to be grouped, [(sum, column to be summed)]
            # Ex: settings["aggregate"] = 1, [(Aggregate.sum, 2), (Aggregate.avg, 3)]
            v = ", ".join(f"{fn.__name__}({p.fields[col].name})" for fn, col in se["aggregate"][1])
            if se["aggregate"][0] is not None:
                l.append(f"Group by {p.fields[se['aggregate'][0]]}: " + v)
            else:
                l.append("Aggregate: " + v)

        # XX
        # if self.parser.redo_invalids is not None:
        #    l.append("Redo invalids: " + str(self.parser.redo_invalids))
        stdout.write(", ".join(l))

        l3 = []
        for f in p.fields:
            if not f.is_new and f.has_clear_type():
                t = ", ".join([str(t) for t in f.possible_types])
                l3.append(f.color(f"{f} ({t})"))
        stdout.write("\nIdentified columns: " + ", ".join(l3))
        if se["add"]:
            l2 = []
            for f in se["add"]:
                l2.append(f.color(f"{f} (from {str(f.source_field)})"))
            stdout.write("\nComputed columns: " + ", ".join(l2))
        l = []
        progress = 0
        if p.line_count:
            if p.ip_count:
                stdout.write(", {} IPs".format(p.ip_count))
            elif p.ip_count_guess:
                stdout.write(", around {} IPs".format(p.ip_count_guess))
            l.append("Log lines processed: {}/{}, {} %".format(p.line_count, p.lines_total,
                                                               ceil(100 * p.line_count / p.lines_total)))
            progress = p.line_count / p.lines_total
        else:
            l.append("Log lines: {}".format(p.lines_total))
        if p.time_end:
            l.append("{}".format(p.time_end - p.time_start))
        elif p.time_start:
            l.append(f"{datetime.now().replace(microsecond=0) - p.time_start}")
            l.append(f"{p.velocity} lines / s")
            l.append(f"{p.processor.descriptors_count} file descriptors open")
        if p.queued_lines_count and hasattr(Whois, "queued_ips"):
            # XX it would be cleaner if the case that Whois.queued_ips (and Whois.quota) does not exist
            #    will not happen; but it will when queued, interrupted and launched again.
            if Whois.queued_ips and len(Whois.queued_ips) != p.queued_lines_count:
                # why Whois.queued_ips > 0: Quota has ended and set of queued IPs has been emptied
                # ... but the lines are still queued. We lost the information about the number of unique queued IPs.
                v = f" lines ({len(Whois.queued_ips)} unique IPs)"
            else:
                v = " lines"
            s = f"skipped {p.queued_lines_count}{v} due to LACNIC quota"
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
        stdout.write("\n" + r + "\n")
        if p.whois_stats:
            print_s("Whois servers asked: " + ", ".join(key + " (" + str(val) + "×)" for key, val in p.whois_stats.items())
                    + f"; {len(p.ranges)} prefixes discovered")

        print_s("\nSample:\n" + "".join(p.sample[:4]))  # show first 3rd lines

        if p.is_formatted:  # show how would the result be alike
            full_rows, rows = p.get_sample_values()

            first_line_length = tabulate(rows, headers=[f.get(True, color=False) for f in p.fields]).split("\n")[0]
            if rows and len(first_line_length) <= get_terminal_size()[1]:
                # print big and nice table because we do not care about the dialect and terminal is wide enough
                # we do not display dialect change in the big preview
                print_s("\033[0;36mPreview:\033[0m")
                header = [f.get(True, line_chosen=se["header"] is not False) for f in p.fields]
                print_s(tabulate(rows, headers=header))
            else:
                # print the rows in the same way so that they optically match the Sample above
                print_s("\033[0;36mCompact preview:\033[0m")
                cw = writer(stdout, dialect=se["dialect"] or p.dialect)
                if se["header"] is not False and p.has_header:
                    cw.writerow([f.get() for f in p.fields])
                for r in full_rows:
                    cw.writerow(r)

        output = Config.get("output")
        if output:
            print_s(f"Output file specified: {output}")

        if p.aggregation:  # an aggregation has finished
            print_s("\n")
            if len(p.aggregation) == 1:
                print_s(self.get_aggregation(next(iter(p.aggregation.values())), color=True, limit=8))
            else:
                print_s("Aggregating in split files...")

        if p.is_analyzed:
            if p.saved_to_disk is False:
                print_s("\n** Processing completed, results were not saved to a file yet.")
                print_s(tabulate(p.stdout_sample, headers="firstrow" if p.has_header else ()))
            elif p.saved_to_disk:
                print_s(f"\n** Processing completed: Result file in {p.target_file}")
            else:
                abroad, local, non_deliverable, totals = map(p.stats.get, (
                    'abroad', 'local', 'non_deliverable', 'totals'))

                print_s(f"** Processing completed: {totals} result files in {Config.get_cache_dir()}")
                # local = Contacts.count_mails(self.attachments.keys(), abusemails_only=True)
                # abroad = Contacts.count_mails(self.attachments.keys(), abroads_only=True)
                if totals == non_deliverable:
                    print_s("* It seems no file is meant to serve as an e-mail attachment.")
                else:
                    if local[0] + abroad[0] == 0:
                        print_s(f"Already sent all {abroad[1]} abroad e-mails and {local[1]} local e-mails")
                    elif local[1] + abroad[1] > 1:
                        print_s(f"Already sent {abroad[1]}/{sum(abroad)} abroad e-mails and {local[1]}/{sum(local)} local e-mails")
                    else:
                        print_s(f"* {abroad[0]} files seem to be attachments for abroad e-mails\n* {local[0]} for local e-mails")
                    if non_deliverable:
                        print_s(f"* {non_deliverable} files undeliverable")

                if Config.get('testing'):
                    print_s(
                        "\n*** TESTING MOD - mails will be send to mail {} ***\n (For turning off testing mode set `testing = False` in config.ini.)".format(
                            Config.get('testing_mail')))

            stat = self.get_stats_phrase()
            if stat:
                print_s("\n Statistics overview:\n" + stat)
            """
            XX
            if parser.abuseReg.stat("records", False):
                print_s("Couldn't find {} abusemails for {}× IP.".format(parser.reg["local"].stat("records", False), parser.reg["local"].stat("ips", False)))
            if parser.countryReg.stat("records", False):
                print_s("Couldn't find {} csirtmails for {}× IP.".format(parser.reg["abroad"].stat("records", False), parser.reg["abroad"].stat("ips", False)))
            """

        if full:
            # XX subprocess.run("less", input=v, encoding="utf-8")
            # XX show aggregation too
            if len(p.ranges.items()):
                rows = []
                for prefix, o in p.ranges.items():
                    prefix, location, incident, asn, netname, country, abusemail, timestamp = o
                    rows.append((prefix, location, incident or "-", asn or "-", netname or "-"))
                print_s("\n\n** Whois information overview **\n" +
                        tabulate(rows, headers=("prefix", "location", "contact", "asn", "netname")))
            else:
                print_s("No whois information available.")

            if p.is_split:
                rows = []
                for o in p.attachments:
                    rows.append((o.filename,
                                 {True: "abroad", False: "✓", None: "×"}[o.abroad],
                                 {True: "✓", False: "error", None: "no"}[o.sent],
                                 humanize.naturalsize(o.path.stat().st_size),
                                 ))
                print_s("\n\n** Generated files overview **\n" + tabulate(rows, headers=("file", "deliverable", "sent", "size")))
            # else:
            #     print_s("Files overview not needed – everything have been processed into a single file.")

            print_s("\n\nPress Enter to continue...")

        # atomic print out
        self.stdout.write(stdout.getvalue())
        if self.queue:  # what has been printed out during processing stays on the screen
            self.stdout.write("".join(self.queue))
            # XX if random true, pops out an element so that it wont stay forever

    def get_aggregation(self, data, color=False, limit=None, nice=True):
        """

        @param data:
        @param color:
        @param limit:
        @param nice: If true, tabulated result returned, else we get (header, rows) tuple.
        @return:
        """
        form = lambda v, fmt: f"\033[{fmt}m{v}\033[0m" if color else v
        header = []
        grouping = self.parser.settings["aggregate"][0] is not None
        if grouping:
            header.append(form(self.parser.fields[self.parser.settings["aggregate"][0]].name, 36))
        header.extend([form(f"{fn.__name__}({self.parser.fields[col]})", 33) for fn, col in self.parser.settings["aggregate"][1]])

        rows = []
        generators = cycle(g[0] for g in self.parser.settings["aggregate"][1])
        # sorting by first column (may be a bottleneck, re-sorting every time)
        dd = sorted(data.items(), key=lambda x: x[1][0][1], reverse=True)
        for i, (grouped_el, d) in enumerate(dd):
            if limit and i == limit:
                rows.append(["..." for fn, count in d])
                if grouping:
                    rows[-1].insert(0, "...")
                break
            if grouped_el is None and len(self.parser.settings["aggregate"][1]) == 1 \
                    and next(generators) == Aggregate.list:
                # This is the total row
                # We are aggregating only single thing which is list.
                # That list would comprehend all of the values in the column. We omit it.
                continue

            # rows.append([form(count if fn.__name__ in ("count", "list") else round(count * 100) / 100, 33) for fn, count in d])
            rows.append([form(count if next(generators) not in (Aggregate.sum, Aggregate.avg) else round(count, 2), 33) for
                         fn, count in d])
            if grouping:
                rows[-1].insert(0, form("total" if grouped_el is None else grouped_el, 36))
        # floatfmt - display numbers longers than 15 as the scientific 1e+15, not numbers bigger than a million only
        return tabulate(rows, header, floatfmt=".15g") if nice else (header, rows)

    def get_stats_phrase(self, generate=False):
        """ Prints phrase "Totally {} of unique IPs in {} countries...": """
        st = self.parser.stat

        ip_unique = st("ip_unique")
        abusemail_local = st("abusemail_local")
        abusemail_abroad = st("abusemail_abroad")
        abusemail_unofficial = st("abusemail_unofficial")  # subset of abusemail_abroad
        ip_local_unknown = st("ip_local_unknown")
        ip_local_known = st("ip_local_known")
        ip_abroad_known = st("ip_abroad_known")
        ip_abroad_unknown = st("ip_abroad_unknown")
        prefix_local_known = st("prefix_local_known")
        prefix_local_unknown = st("prefix_local_unknown")
        prefix_abroad_known = st("prefix_abroad_known")
        prefix_abroad_unknown = st("prefix_abroad_unknown")
        prefix_csirtmail_unofficial = st("prefix_csirtmail_unofficial")
        ip_csirtmail_unofficial = st("ip_csirtmail_unofficial")
        ip_csirtmail_known = st("ip_csirtmail_known")
        csirtmail_unofficial = st("csirtmail_unofficial")
        csirtmail_known = st("csirtmail_known")

        """         XX
        invalidLines = self.parser.invalidReg.stat()
        """

        res = []
        if ip_unique > 0:
            res.append(f"Totally {ip_unique} of unique IPs")

        # * deliverable to 67 national/governmental CSIRTs (116490 IPs),
        #       no official contact for 554 abroad e-mail addreses of 107 countries (1615 IP in 45 prefixes)
        # * 445 e-mail addresses (38454 IP in 784 prefixes, unknown contact for 84 IP in 5 prefixes)
        # * 6848 abroad e-mail addresses (34515 IP in 84 prefixes, unknown contact for 84 in 4 prefixes)

        # interesting if using incident-contact field
        if ip_csirtmail_known or ip_csirtmail_unofficial:
            s = s2 = ""
            if ip_csirtmail_known:
                s = f"({ip_csirtmail_known} IP)"
            if ip_csirtmail_unofficial:
                s2 = f", no official contact for {abusemail_unofficial} abroad e-mail addresses" \
                     f" in {csirtmail_unofficial} countries ({ip_csirtmail_unofficial} IP in {prefix_csirtmail_unofficial} prefixes)"
            res.append(f"deliverable to {csirtmail_known} national/governmental CSIRTs {s}{s2}")

        # interesting if using either incident-contact or abusemail
        if ip_local_known or ip_local_unknown:
            l = []
            if ip_local_known:
                l.append(f"{ip_local_known} IP in {prefix_local_known} prefixes")
            if ip_local_unknown:
                l.append(f"unknown contact for {ip_local_unknown} IP in {prefix_local_unknown} prefixes")
            res.append(f"{abusemail_local} e-mail addresses ({', '.join(l)})")

        # interesting if using abusemail
        if ip_abroad_known or ip_abroad_unknown:
            l = []
            if ip_abroad_known:
                l.append(f"{ip_abroad_known} IP in {prefix_abroad_known} prefixes")
            if ip_abroad_unknown:
                l.append(f"unknown contact for {ip_abroad_unknown} IP in {prefix_abroad_unknown} prefixes")
            res.append(f"{abusemail_abroad} abroad e-mail addresses ({', '.join(l)})")

        r = "; ".join(res) + "." if res else ""            
        """ XX
        if invalidLines:
            res += "\nThere were {} invalid lines in {} file.".format(invalidLines, self.parser.invalidReg.getPath())"""

        return r

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

    def start(self):
        q = self.queue

        class queue_stdout(StringIO):
            def write(self, s):
                if q and not q[-1].endswith("\n"):
                    q[-1] += s
                else:
                    q.append(s)
                sys.__stdout__.write(s)
                sys.__stdout__.flush()

        self.stdout = sys.stdout
        sys.stdout = queue_stdout()

        Thread(target=self._stats, daemon=True).start()

    def stop(self):
        if sys.stdout is not self.stdout:
            self.queue.clear()
            sys.stdout = self.stdout
        self.stats_stop.set()

    def pause(self):
        self.stats_stop._flag = 1

    def release(self):
        self.stats_stop._flag = False

    def _stats(self):
        parser = self.parser
        last_count = 0
        speed = 0.1  # speed of refresh
        for tick in count():
            if self.stats_stop._flag is True:
                return
            # do not refresh when stuck (ex: pdb debugging) (as a side effect, clock does not run on the screen)
            if self.stats_stop._flag is not 1 and last_count != parser.line_count:
                v = (parser.line_count - last_count) / speed  # current velocity (lines / second) since last time
                if tick < 20:  # in the beginning, refresh quickly; great look & lower performance
                    speed = 0.2
                elif v == 0:
                    speed = 1  # refresh in 1 sec when processing so heavy no line processed since last time
                else:
                    # faster we process, slower we display (to not waste CPU with displaying)
                    # 10^2 lines/s = 1 s, 10^3 ~ 2, 10^4 ~ 3...
                    # But to make the transition more smoothly, make the avg with the last speed (which is weighted 3 times)
                    speed = (log10(v) - 1 + speed * 3) / 4
                    if speed < 0.3:  # but if going too slow, we will not refresh in such a quick interval
                        speed = 0.3

                parser.velocity = round(v) if v > 1 else round(v, 3)
                last_count = parser.line_count

                self.sout_info()
                Whois.quota.check_over()
            sleep(speed)

    def write_statistics(self):
        if Config.get("write_statistics") and not self.parser.stdin:
            # we write statistics.txt only if we're sourcing from a file, not from stdin
            # XX move this to parser.run_analysis and _resolve_again or to Processor – do not rewrite it every time here!
            stat = self.get_stats_phrase()
            if stat:
                Path(self.parser.source_file.parent, "statistics.txt").write_text(stat)
