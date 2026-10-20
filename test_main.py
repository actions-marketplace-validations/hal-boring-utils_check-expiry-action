"""main() end to end: action inputs in; the run log, annotations, job summary, outputs and exit code out.

The network is mocked. Every host, certificate, registry answer and date here is SYNTHETIC, made up
for these tests under reserved names (example.com and the .example and .test TLDs, RFC 2606; the
192.0.2.0/24 documentation addresses, RFC 5737). Nothing is looked up for real.
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

# SYNTHETIC: a stand-in for IANA's bootstrap file with two made-up registries.
BOOTSTRAP = {
    "services": [
        [["com"], ["https://rdap.example.net/com/"]],
        [["example"], ["https://rdap.example.net/example/"]],
    ]
}


def certificate(lifetime_days: float, left_days: float) -> dict:
    """SYNTHETIC: what getpeercert() returns for a certificate with this lifetime and time left."""
    not_after = NOW + timedelta(days=left_days)
    not_before = not_after - timedelta(days=lifetime_days)
    return {"notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"), "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT")}


def registration(left_days: float) -> tuple[int, dict]:
    """SYNTHETIC: a registry's RDAP answer for a domain that expires in this many days."""
    expires = NOW + timedelta(days=left_days)
    return 200, {"objectClassName": "domain", "events": [{"eventAction": "expiration", "eventDate": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}]}


def verify_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}")
    error.verify_code, error.verify_message = code, message
    return error


HEALTHY = certificate(90, 60.5)
EXAMPLE_COM = "https://rdap.example.net/com/domain/example.com"


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
        fake = FakeNetwork({"example.com": HEALTHY, "www.example.com": HEALTHY}, {EXAMPLE_COM: registration(400.5)})
        code, log, summary, outputs = run(fake, domains="example.com\nwww.example.com")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        self.assertEqual(commands(log), [])
        rows = table(summary)
        self.assertEqual(list(rows), ["example.com", "www.example.com"])
        self.assertTrue(rows["example.com"][0].startswith("OK: expires "), rows)
        self.assertIn("(60 days left), 90-day certificate, TLS 1.3", rows["example.com"][0])
        self.assertTrue(rows["www.example.com"][1].startswith("OK: expires "), rows)
        self.assertTrue(rows["www.example.com"][1].endswith("(`example.com`)"), rows)
        self.assertIn("0 failures, 0 warnings, 0 registration dates unknown.", summary)
        self.assertEqual(fake.connections, [("example.com", 443), ("www.example.com", 443)])
        # One bootstrap fetch per run, one lookup per registered domain.
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL, EXAMPLE_COM])


class Warnings(unittest.TestCase):
    def test_fail_the_step_only_when_asked(self):
        fake = FakeNetwork({"example.com": certificate(64, 5.5)}, {EXAMPLE_COM: registration(400.5)})
        code, log, summary, outputs = run(fake, domains="example.com")
        self.assertEqual(code, 1)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")
        self.assertEqual(len(commands(log)), 1)
        self.assertTrue(commands(log)[0].startswith("::warning title=Certificate example.com::expires "))
        self.assertIn("warns under 8 days", table(summary)["example.com"][0])

        code, _, _, outputs = run(fake, domains="example.com", fail_on_warning="False")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")

    def test_a_registration_shared_by_several_hosts_counts_and_annotates_once(self):
        hosts = ("example.com", "www.example.com", "api.example.com")
        fake = FakeNetwork({host: HEALTHY for host in hosts}, {EXAMPLE_COM: registration(10.5)})
        code, log, summary, outputs = run(fake, domains=", ".join(hosts))
        self.assertEqual(code, 1)
        self.assertEqual(outputs, "warnings=1\nfailures=0\n")
        self.assertEqual([line for line in commands(log) if line.startswith("::warning")], [commands(log)[0]])
        self.assertTrue(commands(log)[0].startswith("::warning title=Domain example.com::expires "))
        for host in hosts:
            self.assertTrue(table(summary)[host][1].startswith("Warning: expires "), host)
        self.assertEqual(fake.requests.count(EXAMPLE_COM), 1)


class NetworkFailures(unittest.TestCase):
    def test_a_certificate_that_cannot_be_checked_fails_and_is_never_called_expired(self):
        fake = FakeNetwork(
            {
                "gone.example.com": socket.gaierror(-2, "Name or service not known"),
                "slow.example.com": TimeoutError("timed out"),
                "closed.example.com": ConnectionRefusedError(111, "Connection refused"),
                "self.example.com": verify_error(19, "self-signed certificate in certificate chain"),
                "old.example.com": verify_error(10, "certificate has expired"),
            },
            {EXAMPLE_COM: registration(400.5)},
        )
        hosts = "gone.example.com slow.example.com closed.example.com self.example.com old.example.com"
        code, log, summary, outputs = run(fake, domains=hosts)
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
        names = ("gone.example", "busy.example", "garbled.example", "quiet.example", "broken.example", "local.test")
        fake = FakeNetwork(
            {name: HEALTHY for name in names},
            {
                "https://rdap.example.net/example/domain/gone.example": (404, {}),
                "https://rdap.example.net/example/domain/busy.example": (503, {}),
                "https://rdap.example.net/example/domain/garbled.example": (200, b"<html>Service paused</html>"),
                "https://rdap.example.net/example/domain/quiet.example": (200, {"objectClassName": "domain", "events": []}),
                "https://rdap.example.net/example/domain/broken.example": http.client.IncompleteRead(b"{"),
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
                "gone.example": "Unknown: not found in the registry",
                "busy.example": "Unknown: lookup failed: the registry answered HTTP 503",
                "garbled.example": "Unknown: lookup failed: the registry's answer is not RDAP JSON",
                "quiet.example": "Unknown: no expiry published by the registry",
                "broken.example": "Unknown: lookup failed: IncompleteRead(1 bytes read)",
                "local.test": "Unknown: no RDAP service for this TLD",
            },
        )
        self.assertIn("0 failures, 0 warnings, 6 registration dates unknown.", summary)

    def test_an_unreachable_bootstrap_file_is_fetched_once_and_reported(self):
        outage = urllib.error.URLError(TimeoutError("timed out"))
        fake = FakeNetwork({"example.com": HEALTHY, "example.test": HEALTHY}, {}, bootstrap=outage)
        code, _, summary, outputs = run(fake, domains="example.com example.test")
        self.assertEqual(code, 0)
        self.assertEqual(outputs, "warnings=0\nfailures=0\n")
        reason = "Unknown: not checked: IANA's RDAP bootstrap file is unavailable (timed out)"
        self.assertEqual([reg for _, reg in table(summary).values()], [reason, reason])
        self.assertEqual(fake.requests, [ce.BOOTSTRAP_URL])


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
