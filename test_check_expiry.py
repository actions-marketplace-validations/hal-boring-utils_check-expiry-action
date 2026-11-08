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


class ExpiryTimes(unittest.TestCase):
    """A finding gives the known expiry as an ISO 8601 time in UTC, ending Z, so on the last day it
    still shows the hour."""

    def test_a_certificate_on_its_last_day_shows_the_time_it_expires(self):
        not_after = datetime(2027, 3, 1, 7, 30, 15, tzinfo=timezone.utc)
        finding = ce.cert_finding(not_after - timedelta(days=6), not_after, NOW, "auto", ", TLS 1.3")
        self.assertEqual(finding.level, ce.WARN)
        self.assertEqual(finding.summary, "expires 2027-03-01T07:30:15Z (0 days left), 6-day certificate, TLS 1.3; warns under 0.75 days")

    def test_a_registration_on_its_last_day_shows_the_time_it_expires(self):
        finding = ce.domain_finding(datetime(2027, 3, 1, 23, 59, 59, tzinfo=timezone.utc), NOW, 30)
        self.assertEqual(finding.level, ce.WARN)
        self.assertEqual(finding.summary, "expires 2027-03-01T23:59:59Z (0 days left); warns under 30 days")

    def test_an_expiry_given_with_an_offset_is_shown_in_utc(self):
        # SYNTHETIC registry dates west and east of UTC: 22:00 at -08:00 on February 28 is 06:00 UTC on March 1.
        cases = {
            "2027-02-28T22:00:00-08:00": "expires 2027-03-01T06:00:00Z (0 days left); warns under 30 days",
            "2027-03-01T15:45:30+05:30": "expires 2027-03-01T10:15:30Z (0 days left); warns under 30 days",
        }
        for text, summary in cases.items():
            with self.subTest(text=text):
                self.assertEqual(ce.domain_finding(ce.parse_rdap_date(text), NOW, 30).summary, summary)
        # A time in another zone is converted to UTC, never labelled Z as it stands.
        not_after = datetime(2027, 3, 1, 15, 45, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        finding = ce.cert_finding(not_after - timedelta(days=6), not_after, NOW, "auto")
        self.assertEqual(finding.summary, "expires 2027-03-01T10:15:30Z (0 days left), 6-day certificate; warns under 0.75 days")

    def test_a_fraction_of_a_second_is_kept_to_the_microsecond(self):
        cases = {
            "2027-08-13T04:00:00Z": "2027-08-13T04:00:00Z",
            "2027-08-13T04:00:00.5Z": "2027-08-13T04:00:00.500000Z",
            # Cut to microseconds as it is read, never rounded up.
            "2027-08-13T04:00:00.123456789Z": "2027-08-13T04:00:00.123456Z",
            "2027-08-13t09:30:00.000001+05:30": "2027-08-13T04:00:00.000001Z",
        }
        for text, shown in cases.items():
            with self.subTest(text=text):
                self.assertEqual(ce.domain_finding(ce.parse_rdap_date(text), NOW, 30).summary, f"expires {shown} (165 days left)")


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

    def test_drops_one_final_dot_and_keeps_any_other_so_it_can_be_rejected(self):
        # Stripping every dot dropped a lone "." without a word and checked .example.com as example.com.
        cases = {
            "example.com\n.": ["example.com", "."],
            ".example.com": [".example.com"],
            "example.com..": ["example.com.."],
            "..": [".."],
            "https://.example.com/": [".example.com"],
            "https://example.com../": ["example.com.."],
        }
        for text, hosts in cases.items():
            with self.subTest(text=text):
                self.assertEqual(ce.parse_domains(text), hosts)
                self.assertIsNone(ce.host_kind(hosts[-1]))

    def test_keeps_brackets_that_are_not_a_whole_host_and_port_so_they_can_be_rejected(self):
        # None is one bracketed host with nothing or a numeric port after it, though most hold a
        # valid address. Some Python versions' urlsplit accepts this and gives hostname
        # 2001:db8::1; others raise. Rely on neither.
        entries = (
            "[2001:db8::1",
            "2001:db8::1]",
            "[2001:db8::1]]",
            "[[2001:db8::1]]",
            "[2001:db8::1][2001:db8::2]",
            "x[2001:db8::1]",
            "[2001:db8::1]unexpected",
            "[2001:db8::1].",
            "[2001:db8::1]:",
            "[2001:db8::1]:https",
            "[2001:db8::1]:443x",
            "[2001:db8::1]:443:443",
            "[]",
            "user@[2001:db8::1]unexpected",
            "https://[2001:db8::1]unexpected/",
            "https://[2001:db8::1]:/",
            "https://[2001:db8::1]:https/",
            "https://[2001:db8::1]]/",
            "https://user@x[2001:db8::1]/",
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertEqual(ce.parse_domains(entry), [entry])
                self.assertIsNone(ce.host_kind(entry))

    def test_keeps_an_empty_host_or_brackets_around_no_ipv6_address_so_they_can_be_rejected(self):
        # Before, the first four were dropped without a word, so a mixed list looked fully checked,
        # and brackets came off any contents: [example.com] was checked as example.com. Brackets
        # hold an IPv6 address and nothing else.
        entries = (
            "/",
            "?q",
            ":443",
            "user@",
            "[example.com]",
            "[example.com.]",
            "[192.0.2.1]",
            "[192.0.2.1]:443",
            "[2001:db8::g]",
            "user@[example.com]:443/x",
            "https://[example.com]/",
            "https://[192.0.2.1]:443/",
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertEqual(ce.parse_domains(entry), [entry])
                self.assertIsNone(ce.host_kind(entry))
        mixed = "example.com / [example.com] 192.0.2.1 :443 [2001:db8::1]"
        self.assertEqual(ce.parse_domains(mixed), ["example.com", "/", "[example.com]", "192.0.2.1", ":443", "2001:db8::1"])
        # A zone ("%eth0") names a local interface, in brackets or not.
        self.assertIsNone(ce.host_kind(ce.parse_domains("[fe80::1%eth0]")[0]))

    def test_still_reads_one_final_dot_user_info_ports_and_bracketed_ipv6(self):
        text = (
            "Example.com. https://user:pw@www.example.com.:8443/a?b=c 192.0.2.1. bücher.example. "
            "[2001:DB8::1] [2001:db8::2]:8443 user@[2001:db8::3]:443/x https://[2001:db8::4]:443/status "
            "https://u@[2001:db8::5]/ 2001:db8::6"
        )
        hosts = ["example.com", "www.example.com", "192.0.2.1", "xn--bcher-kva.example"]
        hosts += [f"2001:db8::{n}" for n in range(1, 7)]
        self.assertEqual(ce.parse_domains(text), hosts)
        self.assertTrue(all(ce.host_kind(host) for host in hosts), hosts)


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

    def test_reads_rfc_3339_date_times_in_either_case_and_with_any_offset(self):
        utc = datetime(2027, 8, 13, 4, 0, tzinfo=timezone.utc)
        for text in (
            "2027-08-13T04:00:00Z",
            "2027-08-13t04:00:00z",
            "2027-08-13T09:30:00+05:30",
            "2027-08-12T20:00:00-08:00",
            "2027-08-13T04:00:00-00:00",
        ):
            with self.subTest(text=text):
                self.assertEqual(ce.parse_rdap_date(text), utc)
        # A fraction is cut to microseconds, never rounded up into the next second.
        self.assertEqual(ce.parse_rdap_date("2027-08-13T04:00:00.5Z"), utc.replace(microsecond=500000))
        self.assertEqual(ce.parse_rdap_date("2027-08-13T04:00:00.9999999z"), utc.replace(microsecond=999999))
        self.assertEqual(ce.parse_rdap_date("2028-02-29T00:00:00Z"), datetime(2028, 2, 29, tzinfo=timezone.utc))

    def test_never_guesses_a_missing_part_or_reads_another_form(self):
        # SYNTHETIC values RFC 3339's date-time doesn't allow. Reading one would mean guessing what the
        # registry meant (midnight, UTC, a week number), and spaces around a date aren't trimmed away.
        for text in (
            "2027-08-13",
            "2027-08-13T04:00:00",
            "2027-08-13T04:00Z",
            "2027-08-13T04Z",
            "2027-08-13 04:00:00Z",
            "20270813T040000Z",
            "2027-W32-5T04:00:00Z",
            "2027-08-13T04:00:00.Z",
            "2027-08-13T04:00:00,5Z",
            "2027-08-13T04:00:00+0530",
            "2027-08-13T04:00:00+05",
            " 2027-08-13T04:00:00Z",
            "2027-08-13T04:00:00Z\n",
            "٢٠٢٧-08-13T04:00:00Z",
            "",
        ):
            with self.subTest(text=text):
                self.assertIsNone(ce.parse_rdap_date(text))

    def test_fields_out_of_range_are_unreadable_never_rolled_over(self):
        for text in (
            "2027-13-01T00:00:00Z",
            "2027-02-29T00:00:00Z",
            "2027-04-31T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "2027-08-13T24:00:00Z",
            "2027-08-13T04:60:00Z",
            # timedelta would read +01:60 as +02:00 without a word.
            "2027-08-13T04:00:00+01:60",
            "2027-08-13T04:00:00+24:00",
        ):
            with self.subTest(text=text):
                self.assertIsNone(ce.parse_rdap_date(text))

    def test_a_leap_second_is_unknown_rather_than_moved(self):
        # RFC 3339 allows :60 for a leap second. datetime can't hold one, and moving it to the next
        # second would report a time the registry didn't give, so it stays unreadable.
        self.assertIsNone(ce.parse_rdap_date("2016-12-31T23:59:60Z"))

    def test_a_date_that_is_not_text_is_unreadable(self):
        for value in (None, 20270813, 1.5, True, ["2027-08-13T04:00:00Z"], {"date": "2027-08-13T04:00:00Z"}, b"2027-08-13T04:00:00Z"):
            with self.subTest(value=value):
                self.assertIsNone(ce.parse_rdap_date(value))
        self.assertIsNone(ce.rdap_expiration({"events": [{"eventAction": "expiration", "eventDate": 20270813}]}))

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
