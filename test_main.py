"""main() end to end: action inputs in; the run log, annotations, job summary, outputs and exit code out.

The network is mocked. Every host, certificate, registry answer and date here is SYNTHETIC, made up
for these tests under reserved names (example.com and the .example and .test TLDs, RFC 2606; the
192.0.2.0/24 documentation addresses, RFC 5737), or under a real public suffix (co.at, co.uk,
act.edu.au) where a test needs that suffix's shape. Each registry answer names the domain it is the
record of, as real ones do. Nothing is looked up for real.
Run from this folder: python3 -m unittest
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

import check_expiry as ce

NOW = datetime.now(timezone.utc)
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_expiry.py")

# SYNTHETIC: a stand-in for IANA's bootstrap file with made-up registries.
BOOTSTRAP = {
    "services": [
        [["com"], ["https://rdap.example.net/com/"]],
        [["example"], ["https://rdap.example.net/example/"]],
        [["at"], ["https://rdap.example.net/at/"]],
        [["uk"], ["https://rdap.example.net/uk/"]],
        [["au"], ["https://rdap.example.net/au/"]],
    ]
}
# What a registration row adds when the registry has no record of exactly the name listed.
LIST_REGISTERED = "if it's a subdomain, also list its registered domain (such as example.com for www.example.com) in 'domains'"
NOT_FOUND = f"Unknown: not found in the registry under this exact name; {LIST_REGISTERED}"
NOT_THIS_NAME = f"Unknown: the registry's answer is not a domain record for this exact name; {LIST_REGISTERED}"


def rdap_url(name: str) -> str:
    """The made-up registry URL for a domain, by its TLD."""
    return f"https://rdap.example.net/{name.rsplit('.', 1)[-1]}/domain/{name}"


def certificate(lifetime_days: float, left_days: float) -> dict:
    """SYNTHETIC: what getpeercert() returns for a certificate with this lifetime and time left."""
    not_after = NOW + timedelta(days=left_days)
    not_before = not_after - timedelta(days=lifetime_days)
    return {"notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"), "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT")}


def expiring(left_days: float) -> list[dict]:
    """SYNTHETIC: the RDAP events of a registration that expires in this many days."""
    expires = NOW + timedelta(days=left_days)
    return [{"eventAction": "expiration", "eventDate": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}]


def registration(name: str, left_days: float, **names: str) -> tuple[int, dict]:
    """SYNTHETIC: a registry's RDAP record of the domain `name` (its ldhName), which expires in this
    many days. `names` adds a unicodeName."""
    return 200, {"objectClassName": "domain", "ldhName": name, **names, "events": expiring(left_days)}


def verify_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}")
    error.verify_code, error.verify_message = code, message
    return error


HEALTHY = certificate(90, 60.5)
EXAMPLE_COM = rdap_url("example.com")


class FakeNetwork:
    """SYNTHETIC answers for TLS connections and HTTP requests, and a record of each one made.
    A host or URL without an answer raises KeyError, so an unexpected request fails the test."""

    def __init__(self, certs: dict, urls: dict, bootstrap: object = (200, BOOTSTRAP)) -> None:
        self.certs = certs  # host -> getpeercert() dict, or the exception the connection raises
        self.urls = {ce.BOOTSTRAP_URL: bootstrap, **urls}  # URL -> (status, JSON or bytes), or an exception
        self.connections: list[tuple[str, int]] = []
        self.requests: list[str] = []
        self.errors: list[urllib.error.HTTPError] = []  # each HTTPError raised; run() closes them after main()

    def create_connection(self, address, timeout=None):
        self.connections.append(address)
        answer = self.certs[address[0]]
        if isinstance(answer, OSError) and not isinstance(answer, ssl.SSLError):
            raise answer
        return contextlib.nullcontext()

    def create_default_context(self):
        return self

    def wrap_socket(self, sock, server_hostname):
        answer = self.certs[server_hostname]
        if isinstance(answer, BaseException):
            raise answer
        return FakeTLS(answer)

    def urlopen(self, request, timeout=None):
        self.requests.append(request.full_url)
        answer = self.urls[request.full_url]
        if isinstance(answer, BaseException):
            raise answer
        status, body = answer
        if status >= 400:
            self.errors.append(urllib.error.HTTPError(request.full_url, status, "synthetic", {}, io.BytesIO()))
            raise self.errors[-1]
        return FakeResponse(status, body if isinstance(body, bytes) else json.dumps(body).encode())


class FakeTLS(contextlib.nullcontext):
    def __init__(self, cert: dict) -> None:
        super().__init__(self)
        self.cert = cert

    def getpeercert(self) -> dict:
        return self.cert

    def version(self) -> str:
        return "TLSv1.3"


class FakeResponse(contextlib.nullcontext):
    def __init__(self, status: int, raw: bytes) -> None:
        super().__init__(self)
        self.status, self.raw = status, raw

    def read(self, limit: int = -1) -> bytes:
        return self.raw if limit < 0 else self.raw[:limit]


@contextlib.contextmanager
def network(fake: FakeNetwork):
    with mock.patch.object(ce.socket, "create_connection", fake.create_connection), mock.patch.object(
        ce.ssl, "create_default_context", fake.create_default_context
    ), mock.patch.object(ce.urllib.request, "urlopen", fake.urlopen):
        yield


def run(fake: FakeNetwork, **inputs: str) -> tuple[int, str, str, str]:
    """main() with these action inputs (cert_days= becomes INPUT_CERT_DAYS) on the fake network.
    Returns the exit code, the run log, the job summary and the step outputs."""
    with tempfile.TemporaryDirectory() as folder:
        summary, outputs = os.path.join(folder, "summary.md"), os.path.join(folder, "outputs")
        env = {"GITHUB_STEP_SUMMARY": summary, "GITHUB_OUTPUT": outputs}
        env.update({f"INPUT_{name.upper()}": value for name, value in inputs.items()})
        log = io.StringIO()
        try:
            with mock.patch.dict(os.environ, env, clear=True), network(fake), contextlib.redirect_stdout(log):
                code = ce.main()
        finally:
            for error in fake.errors:
                error.close()
        return code, log.getvalue(), read(summary), read(outputs)


def read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


def table(summary: str) -> dict[str, tuple[str, str]]:
    """The summary's rows: host -> (certificate cell, registration cell)."""
    rows = {}
    for line in summary.splitlines():
        if line.startswith("| `"):
            host, cert, reg = (part.strip() for part in line.strip("|").split(" | "))
            rows[host.strip("`")] = (cert, reg)
    return rows


def commands(log: str) -> list[str]:
    """The lines of the log GitHub reads as workflow commands (it ignores leading spaces)."""
    return [line.strip() for line in log.splitlines() if line.strip().startswith("::")]


class HealthyRun(unittest.TestCase):
    def test_reports_every_host_and_passes(self):
        # The guide's example. The registry has no record of www.example.com, as with real registries.
        fake = FakeNetwork(
            {"example.com": HEALTHY, "www.example.com": HEALTHY},
            {EXAMPLE_COM: registration("example.com", 400.5), rdap_url("www.example.com"): (404, {})},
        )
        code, log, summary, outputs = run(fake, domains="example.com\nwww.example.com")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        rows = table(summary)
        self.assertEqual(list(rows), ["example.com", "www.example.com"])
        self.assertTrue(rows["example.com"][0].startswith("OK: expires "), rows)
        self.assertIn("(60 days left), 90-day certificate, TLS 1.3", rows["example.com"][0])
        self.assertTrue(rows["example.com"][1].startswith("OK: expires "), rows)
        self.assertTrue(rows["www.example.com"][0].startswith("OK: expires "), rows)
        self.assertEqual(rows["www.example.com"][1], NOT_FOUND)
        self.assertIn("0 failures, 0 warnings, 1 registration date unknown.", summary)
        self.assertEqual(fake.connections, [("example.com", 443), ("www.example.com", 443)])
        # One bootstrap fetch per run, one lookup per host, under its own name.
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL, EXAMPLE_COM, rdap_url("www.example.com")])


class Warnings(unittest.TestCase):
    def test_fail_the_step_only_when_asked(self):
        fake = FakeNetwork({"example.com": certificate(64, 5.5)}, {EXAMPLE_COM: registration("example.com", 400.5)})
        code, log, summary, outputs = run(fake, domains="example.com")
        self.assertEqual(code, 1)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")
        self.assertEqual(len(commands(log)), 1)
        self.assertTrue(commands(log)[0].startswith("::warning title=Certificate example.com::expires "))
        self.assertIn("warns under 8 days", table(summary)["example.com"][0])

        code, _, _, outputs = run(fake, domains="example.com", fail_on_warning="False")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")

    def test_shared_input_counts_once_and_subdomains_never_borrow_a_registration(self):
        # One domain written four ways and one international name written two ways, plus two
        # subdomains of the first. Both registrations warn; the subdomains are unknown, not warned.
        entries = "example.com, https://WWW.Example.com/login, EXAMPLE.COM., api.example.com\nbücher.example xn--bcher-kva.example http://example.com:8080/"
        hosts = ("example.com", "www.example.com", "api.example.com", "xn--bcher-kva.example")
        fake = FakeNetwork(
            {host: HEALTHY for host in hosts},
            {
                EXAMPLE_COM: registration("example.com", 10.5),
                rdap_url("www.example.com"): (404, {}),
                rdap_url("api.example.com"): (404, {}),
                rdap_url("xn--bcher-kva.example"): registration("xn--bcher-kva.example", 12.5, unicodeName="bücher.example"),
            },
        )
        code, log, summary, outputs = run(fake, domains=entries)
        self.assertEqual(code, 1)
        self.assertEqual(outputs, "warnings=2\nfailures=0\n")
        warned = [line.split("::")[1] for line in commands(log)]
        self.assertEqual(warned, ["warning title=Domain example.com", "warning title=Domain xn--bcher-kva.example"])
        rows = table(summary)
        self.assertEqual(list(rows), list(hosts))
        self.assertTrue(rows["example.com"][1].startswith("Warning: expires "), rows)
        self.assertTrue(rows["xn--bcher-kva.example"][1].startswith("Warning: expires "), rows)
        self.assertEqual((rows["www.example.com"][1], rows["api.example.com"][1]), (NOT_FOUND, NOT_FOUND))
        self.assertIn("0 failures, 2 warnings, 2 registration dates unknown.", summary)
        self.assertEqual(fake.connections, [(host, 443) for host in hosts])
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in hosts])


class NetworkFailures(unittest.TestCase):
    def test_a_certificate_that_cannot_be_checked_fails_and_is_never_called_expired(self):
        certs = {
            "gone.example.com": socket.gaierror(-2, "Name or service not known"),
            "slow.example.com": TimeoutError("timed out"),
            "closed.example.com": ConnectionRefusedError(111, "Connection refused"),
            "self.example.com": verify_error(19, "self-signed certificate in certificate chain"),
            "old.example.com": verify_error(10, "certificate has expired"),
        }
        fake = FakeNetwork(certs, {rdap_url(host): (404, {}) for host in certs})
        code, log, summary, outputs = run(fake, domains=" ".join(certs))
        self.assertEqual(code, 1)
        self.assertEqual(outputs, "warnings=0\nfailures=5\n")
        rows = table(summary)
        self.assertEqual(rows["gone.example.com"][0], "Failure: could not check: DNS lookup failed (Name or service not known)")
        self.assertEqual(rows["slow.example.com"][0], "Failure: could not check: no TLS answer on port 443 within 10 s")
        self.assertEqual(rows["closed.example.com"][0], "Failure: could not check: connection refused on port 443")
        self.assertEqual(rows["self.example.com"][0], "Failure: not trusted: self-signed certificate in certificate chain")
        self.assertEqual(rows["old.example.com"][0], "Failure: not trusted: certificate has expired")
        self.assertEqual([host for host, (cert, _) in rows.items() if "expired" in cert], ["old.example.com"])
        self.assertEqual(len([line for line in commands(log) if line.startswith("::error title=Certificate ")]), 5)

    def test_registry_trouble_is_unknown_and_never_fails_the_run(self):
        names = ("gone.example", "refused.example", "busy.example", "garbled.example", "quiet.example", "broken.example", "local.test")
        fake = FakeNetwork(
            {name: HEALTHY for name in names},
            {
                rdap_url("gone.example"): (404, {}),
                rdap_url("refused.example"): (400, {}),
                rdap_url("busy.example"): (503, {}),
                rdap_url("garbled.example"): (200, b"<html>Service paused</html>"),
                rdap_url("quiet.example"): (200, {"objectClassName": "domain", "ldhName": "quiet.example", "events": []}),
                rdap_url("broken.example"): http.client.IncompleteRead(b"{"),
            },
        )
        code, log, summary, outputs = run(fake, domains=" ".join(names))
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        registrations = {host: reg for host, (_, reg) in table(summary).items()}
        self.assertEqual(
            registrations,
            {
                "gone.example": NOT_FOUND,
                "refused.example": f"Unknown: lookup failed: the registry answered HTTP 400; {LIST_REGISTERED}",
                "busy.example": "Unknown: lookup failed: the registry answered HTTP 503",
                "garbled.example": "Unknown: lookup failed: the registry's answer is not RDAP JSON",
                "quiet.example": "Unknown: no expiry published by the registry",
                "broken.example": "Unknown: lookup failed: IncompleteRead(1 bytes read)",
                "local.test": "Unknown: no RDAP service for this TLD",
            },
        )
        self.assertIn("0 failures, 0 warnings, 7 registration dates unknown.", summary)

    def test_a_rate_limit_is_unknown_without_advice_about_subdomains(self):
        # 429 asks for fewer requests; it says nothing about whether the name is registered.
        fake = FakeNetwork({"example.com": HEALTHY}, {EXAMPLE_COM: (429, {})})
        code, log, summary, outputs = run(fake, domains="example.com")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        self.assertEqual(table(summary)["example.com"][1], "Unknown: lookup failed: the registry answered HTTP 429")

    def test_an_unreachable_bootstrap_file_is_fetched_once_and_reported(self):
        outage = urllib.error.URLError(TimeoutError("timed out"))
        fake = FakeNetwork({"example.com": HEALTHY, "example.test": HEALTHY}, {}, bootstrap=outage)
        code, _, summary, outputs = run(fake, domains="example.com example.test")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        reason = "Unknown: not checked: IANA's RDAP bootstrap file is unavailable (timed out)"
        self.assertEqual([reg for _, reg in table(summary).values()], [reason, reason])
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL])


class ExactNames(unittest.TestCase):
    """Each host's registration is looked up under exactly its own name, never a guessed parent,
    and only the registry's record of that same name counts. Before, shop.example.co.at was
    looked up as co.at and reported with co.at's date."""

    def test_a_name_under_co_at_never_gets_the_date_of_co_at(self):
        hosts = ("example.co.at", "shop.example.co.at")
        fake = FakeNetwork(
            {host: HEALTHY for host in hosts},
            {
                # The registry keeps a record of co.at itself, which expires soon. It isn't the user's.
                rdap_url("co.at"): registration("co.at", 10.5),
                rdap_url("example.co.at"): registration("example.co.at", 400.5),
                rdap_url("shop.example.co.at"): (404, {}),
            },
        )
        code, log, summary, outputs = run(fake, domains=" ".join(hosts))
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        rows = table(summary)
        self.assertTrue(rows["example.co.at"][1].startswith("OK: expires "), rows)
        self.assertEqual(rows["shop.example.co.at"][1], NOT_FOUND)
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in hosts])

    def test_com_and_co_uk_names_are_looked_up_as_listed(self):
        hosts = ("example.com", "www.example.com", "example.co.uk", "www.example.co.uk")
        fake = FakeNetwork(
            {host: HEALTHY for host in hosts},
            {
                # Some registries write the name in upper case; it is still the same name.
                EXAMPLE_COM: registration("EXAMPLE.COM", 400.5),
                rdap_url("www.example.com"): (404, {}),
                rdap_url("example.co.uk"): registration("example.co.uk", 10.5),
                rdap_url("www.example.co.uk"): (404, {}),
            },
        )
        code, log, summary, outputs = run(fake, domains=" ".join(hosts), fail_on_warning="false")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")
        self.assertEqual([line.split("::")[1] for line in commands(log)], ["warning title=Domain example.co.uk"])
        rows = table(summary)
        self.assertTrue(rows["example.com"][1].startswith("OK: expires "), rows)
        self.assertTrue(rows["example.co.uk"][1].startswith("Warning: expires "), rows)
        self.assertEqual((rows["www.example.com"][1], rows["www.example.co.uk"][1]), (NOT_FOUND, NOT_FOUND))
        self.assertIn("0 failures, 1 warning, 2 registration dates unknown.", summary)
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in hosts])

    def test_names_under_deeper_public_suffixes_are_looked_up_as_listed(self):
        # act.edu.au is a public suffix of three labels: schools register names under it.
        hosts = ("example.act.edu.au", "www.example.act.edu.au")
        fake = FakeNetwork(
            {host: HEALTHY for host in hosts},
            {
                rdap_url("act.edu.au"): registration("act.edu.au", 5.5),
                rdap_url("example.act.edu.au"): registration("example.act.edu.au", 400.5),
                rdap_url("www.example.act.edu.au"): (404, {}),
            },
        )
        code, log, summary, outputs = run(fake, domains=" ".join(hosts))
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        rows = table(summary)
        self.assertTrue(rows["example.act.edu.au"][1].startswith("OK: expires "), rows)
        self.assertEqual(rows["www.example.act.edu.au"][1], NOT_FOUND)
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in hosts])

    def test_international_names_are_looked_up_in_their_xn_form(self):
        fake = FakeNetwork(
            {"xn--bcher-kva.example": HEALTHY, "shop.xn--bcher-kva.example": HEALTHY, "xn--caf-dma.example": HEALTHY},
            {
                rdap_url("xn--bcher-kva.example"): registration("XN--BCHER-KVA.EXAMPLE", 400.5, unicodeName="bücher.example"),
                rdap_url("shop.xn--bcher-kva.example"): (404, {}),
                # A registry that gives only the Unicode name.
                rdap_url("xn--caf-dma.example"): (200, {"objectClassName": "domain", "unicodeName": "café.example", "events": expiring(400.5)}),
            },
        )
        code, _, summary, outputs = run(fake, domains="BÜCHER.example shop.bücher.example café.example")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        rows = table(summary)
        self.assertEqual(list(rows), ["xn--bcher-kva.example", "shop.xn--bcher-kva.example", "xn--caf-dma.example"])
        self.assertTrue(rows["xn--bcher-kva.example"][1].startswith("OK: expires "), rows)
        self.assertTrue(rows["xn--caf-dma.example"][1].startswith("OK: expires "), rows)
        self.assertEqual(rows["shop.xn--bcher-kva.example"][1], NOT_FOUND)
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in rows])

    def test_an_answer_for_another_name_or_no_name_is_unknown_and_never_warns(self):
        # Every record here expires in 10.5 days and would warn if it were taken as the host's.
        answers = {
            # The registry answers with the record of a public suffix, or of the parent domain.
            "shop.example.co.at": registration("co.at", 10.5),
            "www.example.com": registration("example.com", 10.5),
            # faß.example's record, which IDNA 2003 would read as fass.example.
            "fass.example": registration("xn--fa-hia.example", 10.5, unicodeName="faß.example"),
            # Not a domain record, or one that names no domain.
            "ns.example": (200, {"objectClassName": "nameserver", "ldhName": "ns.example", "events": expiring(10.5)}),
            "nameless.example": (200, {"objectClassName": "domain", "events": expiring(10.5)}),
            "classless.example": (200, {"ldhName": "classless.example", "events": expiring(10.5)}),
        }
        fake = FakeNetwork({host: HEALTHY for host in answers}, {rdap_url(host): answer for host, answer in answers.items()})
        code, log, summary, outputs = run(fake, domains=" ".join(answers))
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        self.assertEqual({host: reg for host, (_, reg) in table(summary).items()}, {host: NOT_THIS_NAME for host in answers})
        self.assertIn("0 failures, 0 warnings, 6 registration dates unknown.", summary)
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL] + [rdap_url(host) for host in answers])


class IpAddresses(unittest.TestCase):
    def test_get_the_certificate_check_and_no_registration_lookup(self):
        fake = FakeNetwork({"192.0.2.10": certificate(6, 3.5)}, {})
        code, _, summary, outputs = run(fake, domains="https://192.0.2.10/health")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(table(summary)["192.0.2.10"][1], "Skipped: an IP address has no domain registration")
        self.assertEqual(fake.connections, [("192.0.2.10", 443)])
        self.assertEqual(fake.requests, [])


class InvalidInputs(unittest.TestCase):
    def test_stop_the_step_before_anything_is_checked(self):
        cases = {
            "cert-days": {"domains": "example.com", "cert_days": "-5"},
            "domain-days": {"domains": "example.com", "domain_days": "7.5"},
            "fail-on-warning": {"domains": "example.com", "fail_on_warning": "no"},
            "'domains' has entries that are not domain names": {"domains": "example.com\n*.example.com"},
            "No domains given": {"domains": "# all commented out"},
            # Checked as fass.example, it would report another domain's certificate and registration.
            "two different domains: faß.example, λας.example. List each in its xn-- form.": {"domains": "example.com faß.example λας.example"},
        }
        for named, inputs in cases.items():
            with self.subTest(named):
                fake = FakeNetwork({}, {})
                code, log, summary, outputs = run(fake, **inputs)
                self.assertEqual(code, 2)
                self.assertEqual(len(commands(log)), 1)
                self.assertTrue(commands(log)[0].startswith("::error::"))
                self.assertIn(named, commands(log)[0])
                self.assertEqual((fake.connections, fake.requests, summary, outputs), ([], [], "", ""))

    def test_a_domain_entry_cannot_forge_a_workflow_command(self):
        fake = FakeNetwork({}, {})
        code, log, _, _ = run(fake, domains="::warning title=All clear::nothing expires\n%0A::notice::hi")
        self.assertEqual(code, 2)
        self.assertEqual(len(commands(log)), 1)
        self.assertTrue(commands(log)[0].startswith("::error::'domains' has entries"))
        # The entry is echoed (lowercased) with its % escaped, so GitHub can't decode it into a line break.
        self.assertIn("%250a::notice::hi", commands(log)[0])


class Script(unittest.TestCase):
    def test_the_action_entry_point_exits_2_on_invalid_input(self):
        # The way action.yml runs it: python3 -I, nothing imported from the working directory.
        # Invalid input stops it before any network use, so this needs no mock.
        env = {"INPUT_DOMAINS": "example.com", "INPUT_CERT_DAYS": "-1"}
        result = subprocess.run([sys.executable, "-I", SCRIPT], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "::error::'cert-days' must be 'auto' or a whole number of days, 0 or more, not '-1'.\n")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
