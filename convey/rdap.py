"""RDAP – the JSON successor of the port-43 WHOIS protocol.

Why: ICANN's Registration Data Policy lets gTLD registries drop port 43 (since 2025-01-28) and the
RIRs are heading the same way. RDAP (RFC 7480–7484, 9082–9083) answers with structured JSON, so we
do not have to regex five different registry text formats.

What RDAP does *not* give us is the announcing ASN (whois has it in the `origin:` route object), so
that one field is resolved separately through Cymru's IP-to-ASN DNS zone – see `origin_asn`.

The module is deliberately split into
* pure parsers (`parse_ip`, `parse_domain`, `parse_cymru`) – no network, unit-testable,
* `Bootstrap` – the IANA registry telling us which server owns which prefix/TLD,
* `Rdap` – the thin HTTP client glueing it together.
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from time import time
from typing import Optional, Union

from netaddr import AddrFormatError, IPAddress, IPNetwork, IPRange

from .config import Config, config_dir, subprocess_env
from .infodicts import address_country_lowered

logger = logging.getLogger(__name__)

Prefix = Union[IPNetwork, IPRange, None]

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/"
BOOTSTRAP_TTL = 7 * 24 * 3600

# Used when the IANA bootstrap is neither cached nor reachable. Asked one by one; a registry that
# does not hold the resource replies 404, which is cheap.
RIR_ENDPOINTS = (
    "https://rdap.arin.net/registry/",
    "https://rdap.db.ripe.net/",
    "https://rdap.apnic.net/",
    "https://rdap.lacnic.net/rdap/",
    "https://rdap.afrinic.net/rdap/",
)

email_regex = re.compile(r"[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,125}[a-z]{2,63}")


class RdapError(Exception):
    """RDAP could not answer; the caller may fall back to whois."""


class RdapNotFound(RdapError):
    """The server does not know the resource (HTTP 404)."""


class RdapRateLimited(RdapError):
    """HTTP 429 – the very thing LACNIC does over whois too."""


@dataclass
class Record:
    """Registry answer, backend agnostic (both RDAP and whois produce it)."""

    prefix: Prefix = None
    country: str = ""
    netname: str = ""
    abusemail: str = ""
    asn: str = ""
    source: str = ""  # server asked, for the statistics table

    def is_sufficient(self, for_domain=False):
        """Whether it makes no sense to ask another backend."""
        if for_domain:
            return bool(self.abusemail)
        return bool(self.prefix) and bool(self.abusemail)

    def merge(self, other: "Record") -> "Record":
        """Fields missing here are taken from `other`. Self wins."""
        if not other:
            return self
        return Record(
            prefix=self.prefix if self.prefix is not None else other.prefix,
            country=self.country or other.country,
            netname=self.netname or other.netname,
            abusemail=self.abusemail or other.abusemail,
            asn=self.asn or other.asn,
            source=self.source or other.source,
        )


# --- vCard / entity digging -------------------------------------------------------------------


def _vcard_values(vcard_array, name):
    """All values of a jCard property. vcardArray = ["vcard", [[name, params, type, value], …]]"""
    out = []
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return out
    for prop in vcard_array[1]:
        if not isinstance(prop, list) or len(prop) < 4 or prop[0] != name:
            continue
        value = prop[3]
        if isinstance(value, list):  # ex: `adr` is a list of address components
            out.append(" ".join(str(v) for v in value if v))
        else:
            out.append(str(value))
    return out


def _entity_email(entity) -> str:
    for value in _vcard_values(entity.get("vcardArray"), "email"):
        match = email_regex.search(value.lower())
        if match:
            return match.group(0)
    return ""


def _walk_entities(entities, roles=()):
    """Depth-first walk. If `roles` given, yields only entities holding one of them."""
    for entity in entities or ():
        if not isinstance(entity, dict):
            continue
        entity_roles = [str(r).lower() for r in entity.get("roles") or ()]
        if not roles or set(roles) & set(entity_roles):
            yield entity
        yield from _walk_entities(entity.get("entities"), roles)


def abuse_email(data: dict) -> str:
    """The abuse contact of an RDAP object (any nesting level)."""
    for entity in _walk_entities(data.get("entities"), ("abuse",)):
        if mail := _entity_email(entity):
            return mail
    # RIPE puts `abuse-mailbox` into remarks when there is no abuse-c
    for remark in data.get("remarks") or ():
        if "abuse" in str(remark.get("title", "")).lower():
            match = email_regex.search(
                " ".join(remark.get("description") or ()).lower()
            )
            if match:
                return match.group(0)
    return ""


def registrar_abuse_email(data: dict) -> str:
    """Domain objects nest the abuse contact under the registrar entity."""
    for registrar in _walk_entities(data.get("entities"), ("registrar",)):
        for entity in _walk_entities(registrar.get("entities"), ("abuse",)):
            if mail := _entity_email(entity):
                return mail
    return abuse_email(data)


def _country_from_entities(data: dict) -> str:
    """Not every registry fills in `country`; try the postal address then (as whois does)."""
    for entity in _walk_entities(data.get("entities")):
        for address in _vcard_values(entity.get("vcardArray"), "adr"):
            if c := address_country_lowered(address.lower()):
                return c
    return ""


# --- parsers ----------------------------------------------------------------------------------


def _prefixes(data: dict):
    """Every network range the object announces, most specific first."""
    out = []
    for cidr in data.get("cidr0_cidrs") or ():
        try:
            version = "v4prefix" if "v4prefix" in cidr else "v6prefix"
            out.append(IPNetwork(f"{cidr[version]}/{cidr['length']}"))
        except (KeyError, AddrFormatError, ValueError):
            logger.debug(f"RDAP: unparsable cidr0 {cidr}")
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        try:
            out.append(IPRange(start, end))
        except (AddrFormatError, ValueError, IndexError):
            logger.debug(f"RDAP: unparsable range {start} - {end}")
    out.sort(key=lambda p: p.size)
    return out


def parse_ip(data: dict, queried_ip: Optional[str] = None) -> Record:
    """An RDAP IP network object -> Record. Values are lowered to match the whois backend."""
    prefix = None
    candidates = _prefixes(data)
    if queried_ip:
        # cidr0_cidrs may describe several disjunct blocks; only one holds our IP
        try:
            ip = IPAddress(queried_ip)
            candidates = [p for p in candidates if ip in p] or candidates
        except (AddrFormatError, ValueError):
            pass
    if candidates:
        prefix = candidates[0]
    country = str(data.get("country") or "").lower()
    if len(country) != 2:
        country = ""
    return Record(
        prefix=prefix,
        country=country or _country_from_entities(data),
        netname=str(data.get("name") or "").lower(),
        abusemail=abuse_email(data),
    )


def parse_domain(data: dict) -> Record:
    """An RDAP domain object -> Record (only the registrar abuse contact is of use)."""
    return Record(abusemail=registrar_abuse_email(data))


# --- Cymru IP-to-ASN --------------------------------------------------------------------------


def parse_cymru(text: str, queried_ip: Optional[str] = None) -> Record:
    """Parse `origin.asn.cymru.com` TXT records.

    Ex: '"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"' -> Record(asn='as15169', …)
    """
    best = None
    for line in text.splitlines():
        parts = [p.strip() for p in line.strip().strip('"').split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        asn = parts[0].split()[0]  # a prefix may be announced by several ASes
        if not asn.isdigit():
            continue
        try:
            prefix = IPNetwork(parts[1])
        except (AddrFormatError, ValueError):
            prefix = None
        country = parts[2].lower() if len(parts[2]) == 2 else ""
        record = Record(prefix=prefix, country=country, asn=f"as{asn}", source="cymru")
        if best is None or (
            prefix is not None
            and (best.prefix is None or prefix.size < best.prefix.size)
        ):
            best = record
    return best or Record()


def cymru_name(ip: str) -> str:
    """The DNS name to ask for the given IP address."""
    address = IPAddress(ip)
    reverse = address.reverse_dns.rstrip(".")
    if address.version == 6:
        return reverse.replace(".ip6.arpa", ".origin6.asn.cymru.com")
    return reverse.replace(".in-addr.arpa", ".origin.asn.cymru.com")


def origin_asn(ip: str, timeout: int = 3) -> Record:
    """The announcing ASN of an IP – RDAP does not carry it, so ask Cymru over DNS."""
    try:
        query = cymru_name(ip)
    except (AddrFormatError, ValueError):
        return Record()
    try:
        text = subprocess.run(
            ["dig", "+short", "-t", "TXT", query, f"+timeout={timeout}"],
            capture_output=True,
            timeout=timeout + 2,
            env=subprocess_env,
        ).stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        Config.missing_dependency("dnsutils")
        return Record()
    except subprocess.TimeoutExpired:
        logger.info(f"Cymru ASN lookup timed out for {ip}")
        return Record()
    return parse_cymru(text, ip)


# --- bootstrap --------------------------------------------------------------------------------


class Bootstrap:
    """IANA bootstrap registries (RFC 9224): which RDAP server holds which prefix / TLD."""

    def __init__(
        self, timeout=5, base_url=IANA_BOOTSTRAP_URL, cache_dir=None, ttl=BOOTSTRAP_TTL
    ):
        self.timeout = timeout
        self.base_url = base_url
        self.cache_dir = Path(cache_dir or config_dir)
        self.ttl = ttl
        self._registries = {}

    def registry(self, kind) -> dict:
        """`kind` is one of ipv4, ipv6, dns, asn. Empty dict if unobtainable."""
        if kind in self._registries:
            return self._registries[kind]
        data = self._load_cached(kind)
        if data is None:
            data = self._download(kind)
        self._registries[kind] = data or {}
        return self._registries[kind]

    def _cache_file(self, kind) -> Path:
        return self.cache_dir / f"rdap_bootstrap_{kind}.json"

    def _load_cached(self, kind):
        path = self._cache_file(kind)
        try:
            if path.stat().st_mtime + self.ttl < time():
                return None
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def _download(self, kind):
        url = f"{self.base_url.rstrip('/')}/{kind}.json"
        try:
            data = fetch_json(url, self.timeout)
        except RdapError as e:
            logger.info(
                f"RDAP bootstrap {kind} unavailable ({e}), falling back to the RIR list"
            )
            # a stale copy still beats no copy
            try:
                return json.loads(self._cache_file(kind).read_text())
            except (OSError, ValueError):
                return None
        try:
            self._cache_file(kind).write_text(json.dumps(data))
        except OSError as e:
            logger.debug(f"RDAP bootstrap {kind} not cached: {e}")
        return data

    @staticmethod
    def _pick_url(urls):
        for url in urls or ():
            if str(url).startswith("https:"):
                return str(url)
        return str(urls[0]) if urls else None

    def servers_for_ip(self, ip) -> list:
        """RDAP base URLs able to answer for the IP, most specific first, RIR fallback appended."""
        try:
            address = IPAddress(ip)
        except (AddrFormatError, ValueError):
            return list(RIR_ENDPOINTS)
        found = []
        for keys, urls in self.registry(f"ipv{address.version}").get("services") or ():
            for key in keys:
                try:
                    network = IPNetwork(key)
                except (AddrFormatError, ValueError):
                    continue
                if address in network and (url := self._pick_url(urls)):
                    found.append((network.prefixlen, url))
                    break
        found.sort(key=lambda i: -i[0])
        servers = [url for _, url in found]
        return servers or list(RIR_ENDPOINTS)

    def servers_for_domain(self, domain) -> list:
        """RDAP base URLs for a domain. Empty when the TLD has no RDAP (most ccTLDs) – use whois."""
        labels = str(domain).lower().strip(".").split(".")
        registry = self.registry("dns").get("services") or ()
        # the registry may hold multi-label zones, ex: 'com.br'; prefer the longest match
        for start in range(len(labels) - 1, -1, -1):
            zone = ".".join(labels[start:])
            for keys, urls in registry:
                if any(str(k).lower().strip(".") == zone for k in keys):
                    if url := self._pick_url(urls):
                        return [url]
        return []


# --- client -----------------------------------------------------------------------------------


def fetch_json(url, timeout) -> dict:
    """GET a JSON document. Raises RdapError subclasses only."""
    import requests  # a lazy import; convey startup time is precious

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/rdap+json, application/json"},
        )
    except requests.RequestException as e:
        raise RdapError(f"{url}: {e}") from e
    if response.status_code == 404:
        raise RdapNotFound(url)
    if response.status_code == 429:
        raise RdapRateLimited(url)
    if response.status_code != 200:
        raise RdapError(f"{url}: HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as e:
        raise RdapError(f"{url}: not a JSON ({e})") from e


class Rdap:
    def __init__(self, timeout=5, asn_lookup=True, bootstrap=None, stats=None):
        self.timeout = timeout
        self.asn_lookup = asn_lookup
        self.bootstrap = bootstrap or Bootstrap(timeout=timeout)
        self.stats = stats  # defaultdict(int) shared with the whois statistics

    def _count(self, url):
        if self.stats is not None:
            self.stats["rdap:" + str(url).split("/")[2]] += 1

    def _query(self, servers, path) -> tuple:
        """Ask the servers one by one. Returns (json, base_url). Raises RdapError if all fail."""
        if not servers:
            raise RdapError(f"no RDAP server known for {path}")
        last = RdapError(f"no RDAP server answered for {path}")
        for base in servers:
            url = f"{base.rstrip('/')}/{path}"
            self._count(base)
            try:
                return fetch_json(url, self.timeout), base
            except RdapRateLimited:
                raise
            except RdapError as e:
                last = e
        raise last

    def ip(self, ip) -> Record:
        data, base = self._query(self.bootstrap.servers_for_ip(ip), f"ip/{ip}")
        record = parse_ip(data, ip)
        record = replace(record, source="rdap:" + str(base).split("/")[2])
        if self.asn_lookup:
            # RDAP has no `origin:`; Cymru also patches a missing prefix/country up
            record = record.merge(origin_asn(ip, min(self.timeout, 3)))
        return record

    def domain(self, domain) -> Record:
        servers = self.bootstrap.servers_for_domain(domain)
        if not servers:
            raise RdapError(f"{domain}: TLD has no RDAP service")
        data, base = self._query(servers, f"domain/{domain}")
        return replace(parse_domain(data), source="rdap:" + str(base).split("/")[2])
