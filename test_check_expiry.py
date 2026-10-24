"""Tests for the pure parts of check_expiry.py (test_main.py runs main() end to end).
Run from this folder: python3 -m unittest"""

import unittest
from datetime import datetime, timedelta, timezone

import check_expiry as ce

NOW = datetime(2027, 3, 1, tzinfo=timezone.utc)


def cert(lifetime_days: float, left_days: float, setting: str = "auto") -> ce.Finding:
    not_after = NOW + timedelta(days=left_days)
    return ce.cert_finding(not_after - timedelta(days=lifetime_days), not_after, NOW, setting)


class LifetimeRule(unittest.TestCase):
    def test_short_lived_certificates_warn_under_an_eighth_of_their_life(self):
        self.assertEqual(ce.cert_warn_days(64, "auto"), 8)
        self.assertEqual(ce.cert_warn_days(100, "auto"), 12.5)
        self.assertEqual(cert(64, 8.5).level, ce.OK)
        self.assertEqual(cert(64, 7.5).level, ce.WARN)
        # A 90-day certificate at 20 days left is past its usual renewal point but not yet late.
        self.assertEqual(cert(90, 20).level, ce.OK)
        self.assertEqual(cert(90, 11).level, ce.WARN)

    def test_long_lived_certificates_warn_at_30_days(self):
        self.assertEqual(ce.cert_warn_days(101, "auto"), 30)
        self.assertEqual(cert(398, 31).level, ce.OK)
        self.assertEqual(cert(398, 29).level, ce.WARN)

    def test_a_number_overrides_the_rule(self):
        self.assertEqual(ce.cert_warn_days(64, "21"), 21)
        self.assertEqual(cert(64, 20, "21").level, ce.WARN)
        self.assertEqual(cert(398, 29, "14").level, ce.OK)
        with self.assertRaises(ValueError):
            ce.cert_warn_days(64, "soon")

    def test_an_expired_certificate_fails(self):
        finding = cert(90, -2)
        self.assertEqual(finding.level, ce.FAIL)
        self.assertIn("expired 2 days ago", finding.summary)


class Thresholds(unittest.TestCase):
    def test_only_whole_numbers_of_zero_or_more_days(self):
        self.assertEqual(ce.whole_days(" 30 "), 30)
        self.assertEqual(ce.whole_days("0"), 0)
        # A negative threshold would silently mean "never warn"; the rest are typos to point out.
        for text in ("-5", "+5", "7.5", "1_000", "30 days", "", "٣٠"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                ce.whole_days(text)
        with self.assertRaises(ValueError):
            ce.cert_warn_days(64, "-1")

    def test_zero_turns_warnings_off_but_expiry_still_fails(self):
        self.assertEqual(cert(64, 0.5, "0").level, ce.OK)
        self.assertEqual(cert(64, -0.5, "0").level, ce.FAIL)
        self.assertEqual(ce.domain_finding(NOW + timedelta(days=1), NOW, 0).level, ce.OK)
        self.assertEqual(ce.domain_finding(NOW - timedelta(days=1), NOW, 0).level, ce.FAIL)


class ExactName(unittest.TestCase):
    """A registry answer counts only when it is the domain record of exactly the host looked up."""

    def answer(self, **body: object) -> dict:
        return {"objectClassName": "domain", **body}

    def test_accepts_the_same_name_in_any_case_with_or_without_a_final_dot(self):
        self.assertTrue(ce.rdap_is_for(self.answer(ldhName="EXAMPLE.COM"), "example.com"))
        self.assertTrue(ce.rdap_is_for(self.answer(ldhName="example.co.at."), "example.co.at"))
        self.assertTrue(ce.rdap_is_for(self.answer(ldhName=None, unicodeName="example.com"), "example.com"))

    def test_refuses_a_parent_a_suffix_or_a_child(self):
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="example.com"), "www.example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="co.at"), "example.co.at"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="act.edu.au"), "example.act.edu.au"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="www.example.com"), "example.com"))

    def test_refuses_an_answer_that_is_not_a_domain_record_or_names_nothing(self):
        self.assertFalse(ce.rdap_is_for({"objectClassName": "nameserver", "ldhName": "example.com"}, "example.com"))
        self.assertFalse(ce.rdap_is_for({"ldhName": "example.com"}, "example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(), "example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName=None, unicodeName=None), "example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName=["example.com"]), "example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName=""), "example.com"))

    def test_refuses_an_answer_whose_names_disagree(self):
        # One name right and the other wrong: the record isn't clearly this host's.
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="example.com", unicodeName="example.net"), "example.com"))
        self.assertFalse(ce.rdap_is_for(self.answer(ldhName="example.net", unicodeName="example.com"), "example.com"))

    def test_compares_international_names_in_their_xn_form(self):
        host = ce.parse_domains("bücher.example")[0]
        self.assertEqual(host, "xn--bcher-kva.example")
        self.assertTrue(ce.rdap_is_for(self.answer(ldhName="XN--BCHER-KVA.EXAMPLE", unicodeName="bücher.example"), host))
        self.assertTrue(ce.rdap_is_for(self.answer(unicodeName="Bücher.example"), host))
        # The same name with ü as u and a combining diaeresis (NFD).
        self.assertTrue(ce.rdap_is_for(self.answer(unicodeName="bu\N{COMBINING DIAERESIS}cher.example"), host))
        self.assertFalse(ce.rdap_is_for(self.answer(unicodeName="bucher.example"), host))

    def test_never_reads_a_sharp_s_as_ss(self):
        # faß.example and fass.example are two registrations. IDNA 2003 would make them one.
        self.assertEqual(ce.rdap_name("faß.example"), "xn--fa-hia.example")
        record = self.answer(ldhName="xn--fa-hia.example", unicodeName="faß.example")
        self.assertTrue(ce.rdap_is_for(record, "xn--fa-hia.example"))
        self.assertFalse(ce.rdap_is_for(record, "fass.example"))
        self.assertFalse(ce.rdap_is_for(self.answer(unicodeName="faß.example"), "fass.example"))

    def test_refuses_a_name_longer_than_any_host(self):
        # A host name is at most 253 characters, counted without the final dot. A longer name in
        # an answer, in either form, can't be the host's.
        longest = ".".join(["a" * 63] * 3 + ["a" * 61])
        self.assertEqual(ce.rdap_name(longest + "."), longest)
        self.assertIsNone(ce.rdap_name(".".join(["a" * 63] * 3 + ["a" * 62])))
        self.assertIsNone(ce.rdap_name("ü" * 254))


class ParseDomains(unittest.TestCase):
    def test_splits_cleans_and_dedupes(self):
        text = "example.com, https://WWW.Example.com/login\n api.example.com:8443 \n\n# comment\nexample.com."
        self.assertEqual(ce.parse_domains(text), ["example.com", "www.example.com", "api.example.com"])

    def test_encodes_international_names(self):
        self.assertEqual(ce.parse_domains("bücher.de"), ["xn--bcher-kva.de"])
        self.assertEqual(ce.parse_domains("Bücher.de xn--bcher-kva.de https://BÜCHER.DE/"), ["xn--bcher-kva.de"])

    def test_leaves_names_idna_versions_disagree_on_as_typed_so_they_can_be_rejected(self):
        # Encoded the IDNA 2003 way, faß.de would be checked as fass.de: another domain.
        for name in ("faß.de", "shop.faß.de", "λας.example", "a\N{ZERO WIDTH JOINER}b.example", "a\N{ZERO WIDTH NON-JOINER}b.example"):
            with self.subTest(name=name):
                self.assertEqual(ce.parse_domains(name), [name])
                self.assertIsNone(ce.host_kind(name))
        self.assertEqual(ce.parse_domains("xn--fa-hia.de"), ["xn--fa-hia.de"])

    def test_reads_ip_addresses_with_or_without_brackets(self):
        text = "[2001:DB8::1]:443 https://[2001:db8::2]/status 192.0.2.1:8443"
        self.assertEqual(ce.parse_domains(text), ["2001:db8::1", "2001:db8::2", "192.0.2.1"])

    def test_keeps_an_entry_with_no_host_so_it_can_be_rejected(self):
        # Dropping it would leave the user believing it was checked.
        self.assertEqual(ce.parse_domains("https:// https://[2001:db8::1"), ["https://", "https://[2001:db8::1"])


class HostKind(unittest.TestCase):
    def test_accepts_host_names_and_ip_addresses(self):
        for host in ("example.com", "xn--bcher-kva.de", "a-b_c.example.org", "localhost"):
            self.assertEqual(ce.host_kind(host), "name", host)
        for host in ("192.0.2.1", "2001:db8::1"):
            self.assertEqual(ce.host_kind(host), "ip", host)

    def test_rejects_what_cannot_be_checked_or_could_inject_markup(self):
        rejected = (
            "*.example.com",
            "-example.com",
            "example..com",
            "a" * 64 + ".com",
            "1.2.3",
            "fe80::1%eth0",
            "https://",
            "exa`mple.com",
            "a|b.example.com",
            "<b>.example.com",
            "::warning::forged",
        )
        for host in rejected:
            self.assertIsNone(ce.host_kind(host), host)


class Rdap(unittest.TestCase):
    def test_reads_the_expiration_event(self):
        body = {
            "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00.123456789Z"},
            ]
        }
        self.assertEqual(ce.rdap_expiration(body), datetime(2027, 8, 13, 4, 0, 0, 123456, tzinfo=timezone.utc))

    def test_no_expiration_event_is_not_an_expiry(self):
        self.assertIsNone(ce.rdap_expiration({"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}]}))
        self.assertIsNone(ce.rdap_expiration({}))
        self.assertIsNone(ce.rdap_expiration(None))
        finding = ce.domain_finding(None, NOW, 30)
        self.assertEqual(finding.level, ce.UNKNOWN)
        self.assertIn("no expiry published", finding.summary)

    def test_malformed_answers_are_unknown_rather_than_a_crash(self):
        self.assertIsNone(ce.rdap_expiration({"events": 5}))
        self.assertIsNone(ce.rdap_server({"services": 5}, "example.com"))
        self.assertIsNone(ce.rdap_server({"services": [[5, 6], "com"]}, "example.com"))

    def test_offsets_are_converted_to_utc(self):
        self.assertEqual(ce.parse_rdap_date("2027-01-01T02:00:00+02:00"), datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertIsNone(ce.parse_rdap_date("not a date"))

    def test_offsets_past_the_calendar_are_unreadable_rather_than_a_crash(self):
        self.assertIsNone(ce.parse_rdap_date("9999-12-31T23:30:00-01:00"))
        self.assertIsNone(ce.parse_rdap_date("0001-01-01T00:30:00+01:00"))

    def test_domain_rule(self):
        self.assertEqual(ce.domain_finding(NOW + timedelta(days=31), NOW, 30).level, ce.OK)
        self.assertEqual(ce.domain_finding(NOW + timedelta(days=29), NOW, 30).level, ce.WARN)
        self.assertEqual(ce.domain_finding(NOW - timedelta(days=1), NOW, 30).level, ce.FAIL)

    def test_finds_the_registry_by_longest_suffix(self):
        bootstrap = {
            "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["uk"], ["http://rdap.nominet.uk/uk", "https://rdap.nominet.uk/uk"]],
            ]
        }
        self.assertEqual(ce.rdap_server(bootstrap, "example.com"), "https://rdap.verisign.com/com/v1/")
        self.assertEqual(ce.rdap_server(bootstrap, "example.co.uk"), "https://rdap.nominet.uk/uk/")
        self.assertIsNone(ce.rdap_server(bootstrap, "example.zz"))


class SafeOutput(unittest.TestCase):
    def test_workflow_commands_escape_their_title_and_message(self):
        line = ce.workflow_command("warning", "100% sure\r\nnext", "Domain a:b,c%")
        self.assertEqual(line, "::warning title=Domain a%3Ab%2Cc%25::100%25 sure%0D%0Anext")

    def test_a_finding_is_always_one_line(self):
        # A line break in an error message could otherwise start a workflow command of its own.
        finding = ce.Finding(ce.FAIL, "could not check:\n::error::forged\r\n")
        self.assertEqual(finding.summary, "could not check: ::error::forged")

    def test_summary_cells_cannot_break_the_table_or_add_markup(self):
        text = "a | b\nc <img> `x` [y](z) *w* _v_"
        self.assertEqual(ce.cell(text), r"a \| b c \<img\> \`x\` \[y\](z) \*w\* \_v\_")


if __name__ == "__main__":
    unittest.main()
