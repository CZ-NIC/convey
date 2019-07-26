# EXPERIMENTAL USAGE XX - this file is not yet documented and probably will be removed
#
#
#
import queue
import threading
from time import sleep

from .whois import Whois
from .config import Config
from .contacts import Contacts
from .dialogue import assume_yes
from .processor import Processor
from .sourceWrapper import SourceWrapper


class _stream:
    def __init__(self):
        self.q = queue.Queue()
        self.closed = False

    def close(self):
        self.closed = True

    def writerow(self, l):
        self.q.put(l)

    def write(self, l):
        # we are not interested in header that processor.py writes at the stream beginning
        pass


def loop(file_or_input=None, fresh=True, yes=True, mute=True, settings={}):
    """
    :param mute: bool Do not print any additional information. XX
    :param yes: bool Run non-interactively, reply all the questions with the suggested option.
    :type settings: dict Will be merged with convey.processor dict.
    """
    # XXIsnt that all superfluous? simple with open: csv.reader() would handle all that code if advanced Convey properties not needed

# CHANGELOG.md - XXten mute je asi k nicemu – pro cli je to debilni a pro import z programu nutnost. Spis bych mel zavest nejake verbosity.

    # load CSV
    Config.init(yes, mute)
    wrapper = SourceWrapper(file_or_input, fresh=fresh)
    csv = wrapper.csv
    Contacts.init()

    # merge possible custom settings
    for k, v in settings.items():
        csv.settings[k] = v

    # tell the CSV we'll handle the output ourselves
    csv.stdout = _stream()

    def run_analysis(csv):
        csv.run_analysis(autoopen_editor=False)

    threading.Thread(target=run_analysis, args=(csv,)).start()

    while True:  # while analysis is still running we return the rows
        while not csv.stdout.q.empty():
            yield csv.stdout.q.get()
        if csv.stdout.closed:
            break
        sleep(0.05)

# class convey:
#     def __init__(self, file_or_input):
# XX Here can be an API for convey manipulation - add columns etc.

class whois:
    def __init__(self, ip):
        self.ip = ip
        self.prefix, _, self.incident_contact, self.asn, self.netname, self.country, self.abusemail = Whois(ip).analyze()