import json
import logging
from collections import defaultdict
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import main
from unittest.mock import patch

from netaddr import IPNetwork, IPRange

from convey.args_controller import WhoisModule
from convey.config import Config
from convey.contacts import Contacts
from convey.rdap import (
    Bootstrap,
    Rdap,
    RdapError,
    RdapNotFound,
    RdapRateLimited,
    Record,
    RIR_ENDPOINTS,
    abuse_email,
    cymru_name,
    parse_cymru,
    parse_domain,
    parse_ip,
    registrar_abuse_email,
)
from convey.whois import Quota, Whois

from tests.shared import TestAbstract, p

RDAP_DIR = p("rdap")


def fixture(name):
    return json.loads(Path(RDAP_DIR, name).read_text())


class TestRdapParsing(TestAbstract):
    def test_ripe_ip(self):
        r = parse_ip(fixture("ripe_ip.json"), "195.113.144.230")
        self.assertEqual(IPNetwork("195.113.128.0/18"), r.prefix)
        self.assertEqual("cz", r.country)
        self.assertEqual("cesnet-cz", r.netname)
        self.assertEqual("abuse@cesnet.cz", r.abusemail)
        self.assertEqual("", r.asn)  # RDAP never carries the announcing ASN

    def test_arin_nested_abuse_entity(self):
        """ARIN nests the abuse contact under the registrant and gives no country field."""
        r = parse_ip(fixture("arin_ip.json"), "8.8.8.8")
        self.assertEqual(
            IPNetwork("8.8.8.0/24"), r.prefix
        )  # the most specific cidr0 wins
        self.assertEqual("network-abuse@google.com", r.abusemail)
        self.assertEqual(
            "us", r.country
        )  # taken from the postal address, as whois does
        self.assertEqual("gogl", r.netname)

    def test_lacnic_range_and_remark(self):
        """No cidr0, no country, abuse mail only in the remarks."""
        r = parse_ip(fixture("lacnic_ip.json"), "200.40.1.1")
        self.assertEqual(IPRange("200.40.0.0", "200.40.255.255"), r.prefix)
        self.assertEqual("uy", r.country)
        self.assertEqual("abuse@antel.net.uy", r.abusemail)

    def test_prefix_containing_the_queried_ip(self):
        """Several disjunct blocks may be listed; only the one holding our IP is ours."""
        data = {
            "name": "SPLIT",
            "cidr0_cidrs": [
                {"v4prefix": "10.0.0.0", "length": 24},
                {"v4prefix": "10.9.0.0", "length": 16},
            ],
        }
        self.assertEqual(IPNetwork("10.9.0.0/16"), parse_ip(data, "10.9.9.9").prefix)
        self.assertEqual(IPNetwork("10.0.0.0/24"), parse_ip(data, "10.0.0.5").prefix)
        # an unrelated IP: fall back to the most specific block instead of nothing
        self.assertEqual(IPNetwork("10.0.0.0/24"), parse_ip(data, "1.2.3.4").prefix)

    def test_empty_and_broken_input(self):
        r = parse_ip({}, "1.2.3.4")
        self.assertEqual(Record(), r)
        self.assertFalse(r.is_sufficient())
        broken = {
            "country": "EUROPE",  # not a two letter code
            "cidr0_cidrs": [{"v4prefix": "not-an-ip", "length": 24}],
            "startAddress": "1.2.3.4",
            "endAddress": "nonsense",
            "entities": ["a string, not an object"],
        }
        self.assertEqual(Record(), parse_ip(broken, "1.2.3.4"))

    def test_no_abuse_contact(self):
        data = {
            "entities": [
                {
                    "roles": ["technical"],
                    "vcardArray": [
                        "vcard",
                        [["email", {}, "text", "tech@example.com"]],
                    ],
                }
            ]
        }
        self.assertEqual("", abuse_email(data))

    def test_domain_registrar_abuse(self):
        r = parse_domain(fixture("domain_com.json"))
        # lowered, and the registrar's technical contact must not win over the abuse one
        self.assertEqual("domainabuse@registrar.example", r.abusemail)
        self.assertTrue(r.is_sufficient(for_domain=True))
        self.assertFalse(r.is_sufficient())

    def test_domain_abuse_without_registrar(self):
        data = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [["email", {}, "text", "abuse@example.com"]],
                    ],
                }
            ]
        }
        self.assertEqual("abuse@example.com", registrar_abuse_email(data))


class TestRecord(TestAbstract):
    def test_merge_prefers_self(self):
        rdap = Record(prefix=IPNetwork("1.2.3.0/24"), country="cz")
        whois = Record(
            prefix=IPNetwork("1.0.0.0/8"), country="sk", abusemail="a@b.cz", asn="as1"
        )
        merged = rdap.merge(whois)
        self.assertEqual(IPNetwork("1.2.3.0/24"), merged.prefix)
        self.assertEqual("cz", merged.country)
        self.assertEqual("a@b.cz", merged.abusemail)  # the gap is filled in
        self.assertEqual("as1", merged.asn)

    def test_sufficiency(self):
        self.assertFalse(Record(prefix=IPNetwork("1.2.3.0/24")).is_sufficient())
        self.assertFalse(Record(abusemail="a@b.cz").is_sufficient())
        self.assertTrue(
            Record(prefix=IPNetwork("1.2.3.0/24"), abusemail="a@b.cz").is_sufficient()
        )


class TestCymru(TestAbstract):
    def test_query_name(self):
        self.assertEqual("8.8.8.8.origin.asn.cymru.com", cymru_name("8.8.8.8"))
        self.assertTrue(
            cymru_name("2001:4860::8888").endswith(".origin6.asn.cymru.com")
        )

    def test_parse(self):
        r = parse_cymru('"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"')
        self.assertEqual("as15169", r.asn)
        self.assertEqual(IPNetwork("8.8.8.0/24"), r.prefix)
        self.assertEqual("us", r.country)

    def test_parse_multiple_announcements(self):
        """The most specific announcement wins; a multi-origin prefix yields the first AS."""
        text = (
            '"3320 8560 | 217.0.0.0/8 | DE | ripencc | 1996-01-01"\n'
            '"1299 | 217.115.16.0/20 | DE | ripencc | 1999-01-01"\n'
        )
        r = parse_cymru(text, "217.115.16.1")
        self.assertEqual("as1299", r.asn)
        self.assertEqual(IPNetwork("217.115.16.0/20"), r.prefix)

    def test_parse_garbage(self):
        self.assertEqual(Record(), parse_cymru(""))
        self.assertEqual(
            Record(), parse_cymru("connection timed out; no servers could be reached")
        )


class TestBootstrap(TestAbstract):
    def bootstrap(self):
        b = Bootstrap()
        b._registries = {
            "ipv4": fixture("bootstrap_ipv4.json"),
            "dns": fixture("bootstrap_dns.json"),
            "ipv6": {},
        }
        return b

    def test_most_specific_server_first(self):
        self.assertEqual(
            ["https://rdap.db.ripe.net/", "https://rdap.arin.net/registry/"],
            self.bootstrap().servers_for_ip("195.113.144.230"),
        )

    def test_https_preferred(self):
        # the ARIN entry lists http first, we must not downgrade
        self.assertEqual(
            ["https://rdap.arin.net/registry/"],
            self.bootstrap().servers_for_ip("8.8.8.8"),
        )

    def test_unknown_ip_falls_back_to_the_rir_list(self):
        self.assertEqual(
            list(RIR_ENDPOINTS), self.bootstrap().servers_for_ip("1.2.3.4")
        )
        self.assertEqual(
            list(RIR_ENDPOINTS), self.bootstrap().servers_for_ip("nonsense")
        )

    def test_domain(self):
        b = self.bootstrap()
        self.assertEqual(
            ["https://rdap.verisign.com/com/v1/"], b.servers_for_domain("example.com")
        )
        # the longest matching zone wins
        self.assertEqual(
            ["https://rdap.registro.br/"], b.servers_for_domain("xyz.com.br")
        )
        # ccTLDs mostly have no RDAP - the caller has to keep using whois
        self.assertEqual([], b.servers_for_domain("nic.cz"))

    def test_registry_cache(
        self,
    ):
        """A fresh file on the disk is used, no download is attempted."""
        with patch("convey.rdap.fetch_json", side_effect=AssertionError("no network")):
            b = Bootstrap(
                cache_dir=RDAP_DIR, ttl=10**9
            )  # the fixture must never look stale
            b._cache_file = lambda kind: Path(RDAP_DIR, f"bootstrap_{kind}.json")
            self.assertEqual(
                ["https://rdap.registro.br/"], b.servers_for_domain("a.com.br")
            )

    def test_registry_download_failure_is_survivable(self):
        with patch("convey.rdap.fetch_json", side_effect=RdapError("down")):
            b = Bootstrap(cache_dir=Path("/nonexistent-convey-test"))
            self.assertEqual({}, b.registry("ipv4"))
            self.assertEqual(list(RIR_ENDPOINTS), b.servers_for_ip("8.8.8.8"))
            self.assertEqual([], b.servers_for_domain("example.com"))


class TestRdapClient(TestAbstract):
    def client(self, **kwargs):
        b = Bootstrap()
        b._registries = {
            "ipv4": fixture("bootstrap_ipv4.json"),
            "dns": fixture("bootstrap_dns.json"),
        }
        return Rdap(bootstrap=b, asn_lookup=False, stats=defaultdict(int), **kwargs)

    def test_ip(self):
        c = self.client()
        with patch("convey.rdap.fetch_json", return_value=fixture("ripe_ip.json")) as f:
            r = c.ip("195.113.144.230")
        f.assert_called_once_with("https://rdap.db.ripe.net/ip/195.113.144.230", 5)
        self.assertEqual("abuse@cesnet.cz", r.abusemail)
        self.assertEqual("rdap:rdap.db.ripe.net", r.source)
        self.assertEqual(1, c.stats["rdap:rdap.db.ripe.net"])

    def test_asn_is_added_from_cymru(self):
        c = self.client()
        c.asn_lookup = True
        with patch(
            "convey.rdap.fetch_json", return_value=fixture("ripe_ip.json")
        ), patch(
            "convey.rdap.origin_asn", return_value=Record(asn="as2852", country="xx")
        ):
            r = c.ip("195.113.144.230")
        self.assertEqual("as2852", r.asn)
        self.assertEqual("cz", r.country)  # RDAP wins over Cymru
        self.assertEqual(IPNetwork("195.113.128.0/18"), r.prefix)

    def test_next_server_asked_when_the_first_does_not_know(self):
        c = self.client()
        answers = [RdapNotFound("first"), fixture("arin_ip.json")]
        with patch("convey.rdap.fetch_json", side_effect=answers) as f:
            r = c.ip("1.2.3.4")  # not in the bootstrap, so all the RIRs are tried
        self.assertEqual(2, f.call_count)
        self.assertEqual("network-abuse@google.com", r.abusemail)

    def test_all_servers_failing_raises(self):
        c = self.client()
        with patch("convey.rdap.fetch_json", side_effect=RdapNotFound("nope")):
            self.assertRaises(RdapError, c.ip, "8.8.8.8")

    def test_rate_limiting_is_not_retried_on_another_server(self):
        c = self.client()
        with patch("convey.rdap.fetch_json", side_effect=RdapRateLimited("429")) as f:
            self.assertRaises(RdapRateLimited, c.ip, "1.2.3.4")
        self.assertEqual(1, f.call_count)

    def test_domain(self):
        c = self.client()
        with patch(
            "convey.rdap.fetch_json", return_value=fixture("domain_com.json")
        ) as f:
            r = c.domain("example.com")
        f.assert_called_once_with(
            "https://rdap.verisign.com/com/v1/domain/example.com", 5
        )
        self.assertEqual("domainabuse@registrar.example", r.abusemail)

    def test_domain_without_rdap_service(self):
        """A ccTLD without RDAP must fail loudly so that the whois fallback takes over."""
        with patch("convey.rdap.fetch_json", side_effect=AssertionError("no network")):
            self.assertRaises(RdapError, self.client().domain, "nic.cz")


class TestWhoisBackends(TestAbstract):
    """The Whois object is the single entry point; RDAP is just one of its backends."""

    IP = "195.113.144.230"

    def setUp(self):
        self.verbosity = Config.verbosity
        Config.verbosity = (
            logging.WARNING
        )  # do not print "Whois 1.2.3.4... " while testing
        self.country2mail = getattr(Contacts, "country2mail", None)
        Contacts.country2mail = {}

    def tearDown(self):
        Config.verbosity = self.verbosity
        if self.country2mail is not None:
            Contacts.country2mail = self.country2mail

    def run_whois(self, backend, rdap=None, whois=None, ip=None, **env_kwargs):
        """Returns (AnalysisResult, rdap_mock, whois_mock)."""
        env = WhoisModule(backend=backend, asn_lookup=False, **env_kwargs)
        Whois.init(env, defaultdict(int), {}, {}, defaultdict(set))
        rdap_kwargs = (
            {"side_effect": rdap}
            if isinstance(rdap, Exception)
            else {"return_value": rdap}
        )
        with patch.object(
            Whois, "_analyze_rdap", **rdap_kwargs
        ) as rdap_mock, patch.object(
            Whois, "_analyze_whois", return_value=whois or Record()
        ) as whois_mock, redirect_stdout(
            StringIO()
        ):
            return Whois(ip or self.IP).get, rdap_mock, whois_mock

    def full_record(self):
        return Record(
            prefix=IPNetwork("195.113.128.0/18"),
            country="cz",
            netname="cesnet-cz",
            abusemail="abuse@cesnet.cz",
            asn="as2852",
        )

    def test_rdap_only(self):
        get, _, whois_mock = self.run_whois("rdap", rdap=self.full_record())
        prefix, location, contact, asn, netname, country, abusemail, _ = get
        self.assertEqual(IPNetwork("195.113.128.0/18"), prefix)
        self.assertEqual("local", location)
        self.assertEqual("abuse@cesnet.cz", contact)
        self.assertEqual(
            ("as2852", "cesnet-cz", "cz", "abuse@cesnet.cz"),
            (asn, netname, country, abusemail),
        )
        whois_mock.assert_not_called()

    def test_whois_only(self):
        get, rdap_mock, _ = self.run_whois("whois", whois=self.full_record())
        self.assertEqual("abuse@cesnet.cz", get[6])
        rdap_mock.assert_not_called()

    def test_auto_stops_at_a_complete_rdap_answer(self):
        _, _, whois_mock = self.run_whois("auto", rdap=self.full_record())
        whois_mock.assert_not_called()

    def test_auto_falls_back_when_rdap_fails(self):
        get, _, whois_mock = self.run_whois(
            "auto", rdap=RdapError("no RDAP server known"), whois=self.full_record()
        )
        self.assertEqual("abuse@cesnet.cz", get[6])
        whois_mock.assert_called_once()

    def test_auto_merges_an_incomplete_rdap_answer(self):
        """RDAP knew the prefix but no abuse contact - whois may still add it."""
        get, _, whois_mock = self.run_whois(
            "auto",
            rdap=Record(
                prefix=IPNetwork("195.113.128.0/18"), country="cz", netname="cesnet-cz"
            ),
            whois=Record(
                prefix=IPNetwork("195.0.0.0/8"),
                abusemail="abuse@cesnet.cz",
                asn="as2852",
            ),
        )
        whois_mock.assert_called_once()
        self.assertEqual(IPNetwork("195.113.128.0/18"), get[0])  # RDAP prefix kept
        self.assertEqual("abuse@cesnet.cz", get[6])
        self.assertEqual("as2852", get[3])

    def test_nothing_found(self):
        get, _, _ = self.run_whois("auto", rdap=RdapError("nope"))
        self.assertEqual(("", "local", "", "", "", "", ""), get[:7])

    def test_abroad_contact(self):
        Contacts.country2mail = {"us": "csirt@example.us"}
        get, _, _ = self.run_whois(
            "rdap",
            rdap=Record(
                prefix=IPNetwork("8.8.8.0/24"), country="us", abusemail="a@google.com"
            ),
            ip="8.8.8.8",
            local_country="cz",
        )
        self.assertEqual("abroad", get[1])
        self.assertEqual(f"us{Config.ABROAD_MARK}csirt@example.us", get[2])
        self.assertEqual(
            "a@google.com", get[6]
        )  # the abuse mail itself stays untouched

    def test_rate_limited_line_gets_queued(self):
        """A 429 behaves the same way as the LACNIC whois quota: the line is postponed."""
        self.assertRaises(
            Quota.QuotaExceeded, self.run_whois, "rdap", rdap=RdapRateLimited("429")
        )
        self.assertIn(self.IP, Whois.queued_ips)


if __name__ == "__main__":
    main()
