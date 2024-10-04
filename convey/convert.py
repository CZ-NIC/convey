import logging
import re
from urllib.parse import urlsplit

from .config import Config
from .utils import print_atomic
import subprocess

logger = logging.getLogger(__name__)

reIpWithPort = re.compile(r"((\d{1,3}\.){4})(\d+)")
reAnyIp = re.compile(r"\"?((\d{1,3}\.){3}(\d{1,3}))")
reFqdn = re.compile(
    r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-_]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")  # Xtoo long, infinite loop: ^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$
reUrl = re.compile(r'[htps]*://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
# reBase64 = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')


def wrong_url_2_url(s, make=True):
    s = re.sub("^hxxp", 'http', s, flags=re.I).replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if make and not s.lower().startswith("http"):
        s = "http://" + s
    return s


def any_ip_ip(s):
    m = reAnyIp.search(s)
    if m:
        return m.group(1)


def port_ip_ip(s):
    m = reIpWithPort.match(s)
    if m:
        return m.group(1).rstrip(".")


def port_ip_port(s):
    m = reIpWithPort.match(s)
    if m:
        return m.group(3)


def url_port(s):
    s = s.split(":")[1]
    return re.match(r"^(\d*)", s).group(1)


def url_hostname(url):
    """ Covers both use cases "http://example.com..." and "example.com..." """
    s = urlsplit(url)
    s = s.netloc or s.path.split("/")[:1][0]
    return s.split(":")[0]  # strips port

def dig(rr):
    def dig_query(query):
        print_atomic(f"Digging {rr} of {query}")
        if rr == "SPF":
            t = "TXT"
        elif rr == "DMARC":
            query = "_dmarc." + query
            t = "TXT"
        else:
            t = rr
        try:
            text = subprocess.check_output(["dig", "+short", "-t", t, query, "+timeout=1"]).decode("utf-8")
        except FileNotFoundError:
            Config.missing_dependency("dnsutils")
        if text.startswith(";;"):
            return None
        spl = text.split("\n")[:-1]
        if t == "TXT":
            spl = [r[1:-1] for r in spl if r.startswith('"') and r.endswith('"')]  # row without " may be CNAME redirect
            if rr == "SPF":
                return [r for r in spl if r.startswith('v=spf')]
            elif rr == "TXT":
                return [r for r in spl if not r.startswith('v=spf')]
        logger.debug(f"Dug {spl}")
        return spl

    return dig_query


# @PickInput XX not yet possible to PickInput
# 1. since for port '80' wizzard loads the port '8' and then '80'
# 2. since we cannot specify `--field ports[80,443]` because comma ',' is taken for a delmiiter between FIELD and COLUMN
#   and pair quoting char '[]' is not allowed in csv.reader that parses CLI
def nmap(val, port=""):
    """
    :type port: int Port to scan, you may delimit by a comma. Ex: `80, 443`
    """
    logger.info(f"NMAPing {val}...")
    try:
        cmd = ["nmap", val]
        if port:
            cmd.extend(["-p", port])
        text = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode("utf-8")
    except FileNotFoundError:
        Config.missing_dependency("nmap")
    text = text[text.find("PORT"):]
    text = text[text.find("\n") + 1:]
    text = text[:text.find("\n\n")]
    if Config.get("multiple_nmap_ports", "FIELDS"):
        l = []
        for row in text.split("\n"):
            l.append(int(re.match(r"(\d+)", row).group(1)))
        return l

    return text
