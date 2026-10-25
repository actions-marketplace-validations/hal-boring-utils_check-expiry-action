#!/usr/bin/env python3
"""Check TLS certificate and domain registration expiry for a list of domains.

Made by Boring Utils (https://boringutils.com). Python 3 standard library only. It runs where it is
started (a GitHub runner) and connects only to the hosts listed (port 443), IANA's RDAP bootstrap
file and the registries' RDAP servers. Nothing is sent to Boring Utils.

Inputs come from environment variables (set by action.yml):
  INPUT_DOMAINS          domains or IP addresses, separated by newlines, commas or spaces (URLs work too)
  INPUT_CERT_DAYS        "auto" (default) or a whole number of days, 0 or more
  INPUT_DOMAIN_DAYS      days before registration expiry to warn, 0 or more (default 30)
  INPUT_FAIL_ON_WARNING  "true" (default) or "false"

Results go to stdout, GitHub annotations, $GITHUB_STEP_SUMMARY and $GITHUB_OUTPUT.
Exit code 1 when anything failed, or when anything warned and fail-on-warning is true;
2 when an input is invalid, before anything is checked.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

USER_AGENT = "boringutils-expiry-action/1.1 (+https://boringutils.com/expiry-watch)"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CONNECT_TIMEOUT = 10
RDAP_TIMEOUT = 15
MAX_BODY = 1024 * 1024
DAY = 86400.0

# Certificates this short-lived or shorter use the lifetime rule under cert-days: auto.
SHORT_LIVED_DAYS = 100
LONG_LIVED_WARN_DAYS = 30

# Characters Python's "idna" codec (IDNA 2003) maps away but IDNA 2008 and browsers keep: ß, final
# sigma, zero-width non-joiner and joiner. faß.de is fass.de to one and xn--fa-hia.de to the other,
# two different registrations.
IDNA_DEVIATIONS = frozenset(
    "\N{LATIN SMALL LETTER SHARP S}\N{GREEK SMALL LETTER FINAL SIGMA}\N{ZERO WIDTH NON-JOINER}\N{ZERO WIDTH JOINER}"
)
# The registry has no record of exactly this name. Names are never guessed up to a parent, so a
# listed subdomain usually ends here.
LIST_REGISTERED = "if it's a subdomain, also list its registered domain (such as example.com for www.example.com) in 'domains'"

# A host name label: letters, digits, hyphens and underscores, 1 to 63 long, no hyphen at either end.
HOST_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
# Characters Markdown or HTML could read as markup inside a table cell.
MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|~&!#$])")
# What a registry lookup can raise: network and TLS errors, broken HTTP, a URL urllib refuses.
LOOKUP_ERRORS = (OSError, ValueError, http.client.HTTPException)

OK, WARN, FAIL, UNKNOWN, SKIP = "ok", "warning", "failure", "unknown", "skipped"
ICON = {OK: "OK", WARN: "Warning", FAIL: "Failure", UNKNOWN: "Unknown", SKIP: "Skipped"}


@dataclass
class Finding:
    level: str
    summary: str

    def __post_init__(self) -> None:
        # Error text from the OS or the network can hold line breaks. Every report is one line, so
        # nothing in it can start a workflow command in the log or a new row in the summary.
        self.summary = " ".join(self.summary.split())


@dataclass
class Settings:
    domains: list[str]
    cert_setting: str
    domain_days: int
    fail_on_warning: bool


# ---------- pure helpers (unit tested) ----------


def parse_domains(text: str) -> list[str]:
    """Splits on newlines, commas and spaces; skips # comments; strips schemes, paths, ports and
    IPv6 brackets; lowercases; writes international names in their xn-- form; dedupes. An entry
    with no host in it, or with a character IDNA versions encode differently, stays as typed, so
    the input check can name it rather than drop it or check another domain."""
    seen: list[str] = []
    words = [word for line in text.splitlines() for word in line.split("#", 1)[0].replace(",", " ").split()]
    for host in words:
        if "://" in host:
            try:
                host = urllib.parse.urlsplit(host).hostname or host
            except ValueError:
                pass
        else:
            host = host.split("/", 1)[0].split("?", 1)[0]
            host = host.rsplit("@", 1)[-1]
            if host.startswith("["):
                host = host[1:].split("]", 1)[0]
            elif host.count(":") == 1:
                host = host.split(":", 1)[0]
        host = host.strip(".").lower()
        if host and not IDNA_DEVIATIONS.intersection(host):
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                pass
        if host and host not in seen:
            seen.append(host)
    return seen


def host_kind(host: str) -> str | None:
    """Returns "ip" for an IP address, "name" for a host name, None for anything that can't be checked."""
    # An IPv6 zone ("fe80::1%eth0") names a local interface, not a host to check.
    if "%" not in host:
        try:
            ipaddress.ip_address(host)
            return "ip"
        except ValueError:
            pass
    labels = host.split(".")
    if len(host) <= 253 and not labels[-1].isdigit() and all(HOST_LABEL.fullmatch(label) for label in labels):
        return "name"
    return None


def whole_days(text: str) -> int:
    """A whole number of days, 0 or more, in ASCII digits. Anything else (-5, 7.5, 1_000) raises ValueError."""
    text = text.strip()
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError(f"not a whole number of days: {text!r}")
    return int(text)


def cert_warn_days(lifetime_days: float, setting: str) -> float:
    """Days left at which a certificate warns.

    auto: certificates of 100 days or less warn when less than an eighth of their lifetime is
    left (automated renewal normally happens with a third left, so this is well past it);
    longer certificates warn at 30 days. A whole number of days is used as is; 0 never warns.
    """
    setting = setting.strip().lower()
    if setting in ("", "auto"):
        return lifetime_days / 8 if lifetime_days <= SHORT_LIVED_DAYS else LONG_LIVED_WARN_DAYS
    return float(whole_days(setting))


def parse_rdap_date(value: str) -> datetime | None:
    """Parses an RDAP eventDate (RFC 3339) into an aware UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    if "." in text:
        # Trim fractional seconds to microseconds, which older Pythons require.
        head, rest = text.split(".", 1)
        digits = ""
        while rest and rest[0].isdigit():
            digits, rest = digits + rest[0], rest[1:]
        text = f"{head}.{digits[:6].ljust(6, '0')}{rest}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        # An offset that pushes the date past year 1 or 9999 in UTC; unreadable, not a reason to stop the run.
        return None


def rdap_expiration(body: object) -> datetime | None:
    """The date of the event with eventAction "expiration", or None when not published."""
    if not isinstance(body, dict) or not isinstance(body.get("events"), list):
        return None
    for event in body["events"]:
        if isinstance(event, dict) and str(event.get("eventAction", "")).lower() == "expiration":
            return parse_rdap_date(event.get("eventDate", ""))
    return None


def rdap_name(value: object) -> str | None:
    """An RDAP ldhName or unicodeName written the way hosts are: lowercase, no final dot, each
    international label in its xn-- form. Labels are encoded as given, without IDNA 2003's mapping
    (which reads faß as fass), so only the same name compares equal."""
    if not isinstance(value, str):
        return None
    name = unicodedata.normalize("NFC", value.strip()).lower()
    if name.endswith("."):
        name = name[:-1]
    # A host name is at most 253 characters, and its Unicode form is never longer than its xn--
    # form, so a longer name can't be the host. Measured before encoding: punycode's time grows
    # with the square of a label's length, and an answer can be a megabyte.
    if len(name) > 253:
        return None
    return ".".join(label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii") for label in name.split("."))


def rdap_is_for(body: dict, host: str) -> bool:
    """Whether an RDAP answer is the domain record of exactly this host: objectClassName "domain",
    and every name it gives (ldhName, unicodeName) is the host. A record of anything else, such as
    a parent or a public suffix, holds another registration's dates."""
    if body.get("objectClassName") != "domain":
        return False
    names = [body[key] for key in ("ldhName", "unicodeName") if body.get(key) is not None]
    return bool(names) and all(rdap_name(name) == host for name in names)


def rdap_server(bootstrap: object, domain: str) -> str | None:
    """The registry's RDAP base URL for a domain from IANA's bootstrap file (longest suffix wins)."""
    services = bootstrap.get("services") if isinstance(bootstrap, dict) else None
    if not isinstance(services, list):
        return None
    servers: dict[str, str] = {}
    for service in services:
        if isinstance(service, list) and len(service) == 2 and all(isinstance(part, list) for part in service):
            urls = [u for u in service[1] if isinstance(u, str)]
            url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
            for suffix in service[0]:
                if url and isinstance(suffix, str):
                    servers[suffix.lower()] = url
    labels = domain.split(".")
    for i in range(1, len(labels)):
        base = servers.get(".".join(labels[i:]))
        if base:
            return base if base.endswith("/") else base + "/"
    return None


def days_left(when: datetime, now: datetime) -> float:
    return (when - now).total_seconds() / DAY


def describe_days(days: float) -> str:
    whole = int(days // 1) if days >= 0 else -int(-days // 1)
    if days < 0:
        return f"expired {abs(whole)} day{'s' if abs(whole) != 1 else ''} ago" if whole else "expired today"
    return f"{whole} day{'s' if whole != 1 else ''} left"


def cert_finding(not_before: datetime, not_after: datetime, now: datetime, setting: str, detail: str = "") -> Finding:
    lifetime = (not_after - not_before).total_seconds() / DAY
    left = days_left(not_after, now)
    threshold = cert_warn_days(lifetime, setting)
    text = f"expires {not_after:%Y-%m-%d} ({describe_days(left)}), {round(lifetime)}-day certificate{detail}"
    if left < 0:
        return Finding(FAIL, text)
    if left < threshold:
        return Finding(WARN, f"{text}; warns under {threshold:g} days")
    return Finding(OK, text)


def domain_finding(expires: datetime | None, now: datetime, warn_days: int) -> Finding:
    if expires is None:
        return Finding(UNKNOWN, "no expiry published by the registry")
    left = days_left(expires, now)
    text = f"expires {expires:%Y-%m-%d} ({describe_days(left)})"
    if left < 0:
        return Finding(FAIL, text)
    if left < warn_days:
        return Finding(WARN, f"{text}; warns under {warn_days} days")
    return Finding(OK, text)


def lookup_reason(error: Exception) -> str:
    """Why a request failed, in a few words: the socket error inside a URLError, without its errno."""
    reason = getattr(error, "reason", None) or error
    return str(getattr(reason, "strerror", None) or reason)


# ---------- network ----------


def cert_time(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def check_certificate(host: str, now: datetime, setting: str) -> Finding:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                version = tls.version() or ""
    except ssl.SSLCertVerificationError as error:
        reason = (error.verify_message or str(error)).rstrip(".")
        if error.verify_code == 10:
            reason = "certificate has expired"
        return Finding(FAIL, f"not trusted: {reason}")
    except socket.gaierror as error:
        return Finding(FAIL, f"could not check: DNS lookup failed ({error.strerror or error})")
    except (socket.timeout, TimeoutError):
        return Finding(FAIL, f"could not check: no TLS answer on port 443 within {CONNECT_TIMEOUT} s")
    except ConnectionRefusedError:
        return Finding(FAIL, "could not check: connection refused on port 443")
    except ssl.SSLError as error:
        return Finding(FAIL, f"could not check: TLS handshake failed ({error.reason or error})")
    except OSError as error:
        return Finding(FAIL, f"could not check: {error.strerror or error}")
    detail = f", {version.replace('TLSv', 'TLS ')}" if version else ""
    try:
        return cert_finding(cert_time(cert["notBefore"]), cert_time(cert["notAfter"]), now, setting, detail)
    except (KeyError, ValueError):
        return Finding(FAIL, "could not read the certificate dates")


def fetch_json(url: str) -> tuple[int, object]:
    """The status and JSON body of a GET. The body is None after an HTTP error or when it isn't JSON."""
    request = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=RDAP_TIMEOUT) as response:
            status, raw = response.status, response.read(MAX_BODY)
    except urllib.error.HTTPError as error:
        return error.code, None
    try:
        return status, json.loads(raw)
    except (ValueError, RecursionError):
        return status, None


def load_bootstrap() -> tuple[object, str]:
    """IANA's RDAP bootstrap file, or None and why it can't be used."""
    try:
        status, body = fetch_json(BOOTSTRAP_URL)
    except LOOKUP_ERRORS as error:
        return None, f"IANA's RDAP bootstrap file is unavailable ({lookup_reason(error)})"
    if status != 200:
        return None, f"IANA's RDAP bootstrap file is unavailable (HTTP {status})"
    if not isinstance(body, dict):
        return None, "IANA's RDAP bootstrap file is unreadable"
    return body, ""


class Registry:
    """Registration lookups for one run. IANA's bootstrap file is fetched at most once. Each host
    is looked up under its own name and nothing else: guessing which part of a name was registered
    can land on another registration and report its dates as the host's."""

    def __init__(self, now: datetime, warn_days: int) -> None:
        self.now = now
        self.warn_days = warn_days
        self.bootstrap: tuple[object, str] | None = None

    def check(self, host: str) -> Finding:
        """What the registry says about exactly this host."""
        if host_kind(host) == "ip":
            return Finding(SKIP, "an IP address has no domain registration")
        if self.bootstrap is None:
            self.bootstrap = load_bootstrap()
        bootstrap, problem = self.bootstrap
        if problem:
            return Finding(UNKNOWN, f"not checked: {problem}")
        base = rdap_server(bootstrap, host)
        if base is None:
            return Finding(UNKNOWN, "registration lookup unavailable for this ending")
        try:
            status, body = fetch_json(urllib.parse.urljoin(base, "domain/" + urllib.parse.quote(host)))
        except LOOKUP_ERRORS as error:
            return Finding(UNKNOWN, f"lookup failed: {lookup_reason(error)}")
        # Not found is unknown, not a warning: a listed subdomain usually isn't a registration of its
        # own, and a host whose domain really is gone fails its certificate check.
        if status == 404:
            return Finding(UNKNOWN, f"not found in the registry under this exact name; {LIST_REGISTERED}")
        # A rate limit (429) says nothing about the name, so it gets no advice about subdomains.
        if 400 <= status < 500 and status != 429:
            return Finding(UNKNOWN, f"lookup failed: the registry answered HTTP {status}; {LIST_REGISTERED}")
        if status != 200:
            return Finding(UNKNOWN, f"lookup failed: the registry answered HTTP {status}")
        if not isinstance(body, dict):
            return Finding(UNKNOWN, "lookup failed: the registry's answer is not RDAP JSON")
        if not rdap_is_for(body, host):
            return Finding(UNKNOWN, f"the registry's answer is not a domain record for this exact name; {LIST_REGISTERED}")
        return domain_finding(rdap_expiration(body), self.now, self.warn_days)


# ---------- reporting ----------


def escape_data(text: str) -> str:
    """A workflow command's message, escaped the way GitHub's toolkit escapes it."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    """A workflow command's property value (title=...), escaped the way GitHub's toolkit escapes it."""
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def workflow_command(name: str, message: str, title: str = "") -> str:
    properties = f" title={escape_property(title)}" if title else ""
    return f"::{name}{properties}::{escape_data(message)}"


def annotate(level: str, title: str, message: str) -> None:
    command = {FAIL: "error", WARN: "warning"}.get(level)
    if command:
        print(workflow_command(command, message, title))


def write_file(variable: str, text: str) -> None:
    path = os.environ.get(variable)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def cell(text: str) -> str:
    """Text for a Markdown table cell: one line, with anything Markdown or HTML could read as markup escaped."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", " ".join(text.split()))


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def tally(failures: int, warnings: int, unknown: int) -> str:
    return f"{plural(failures, 'failure')}, {plural(warnings, 'warning')}, {plural(unknown, 'registration date')} unknown."


def read_settings() -> tuple[Settings, list[str]]:
    """The action's inputs, and a message for each one that is invalid."""
    errors: list[str] = []
    domains = parse_domains(os.environ.get("INPUT_DOMAINS", ""))
    invalid = [host for host in domains if host_kind(host) is None]
    ambiguous = [host for host in invalid if IDNA_DEVIATIONS.intersection(host)]
    unreadable = [host for host in invalid if host not in ambiguous]
    if unreadable:
        errors.append(f"'domains' has entries that are not domain names or IP addresses: {', '.join(unreadable)}")
    if ambiguous:
        errors.append(
            f"'domains' has international names with ß, ς or a zero-width joiner or non-joiner, which tools convert to "
            f"two different domains: {', '.join(ambiguous)}. List each in its xn-- form."
        )
    if not domains:
        errors.append("No domains given. Set the 'domains' input.")
    cert_setting = os.environ.get("INPUT_CERT_DAYS", "").strip().lower() or "auto"
    try:
        cert_warn_days(90, cert_setting)
    except ValueError:
        errors.append(f"'cert-days' must be 'auto' or a whole number of days, 0 or more, not '{cert_setting}'.")
    domain_text = os.environ.get("INPUT_DOMAIN_DAYS", "").strip() or "30"
    try:
        domain_days = whole_days(domain_text)
    except ValueError:
        domain_days = 0
        errors.append(f"'domain-days' must be a whole number of days, 0 or more, not '{domain_text}'.")
    fail_text = os.environ.get("INPUT_FAIL_ON_WARNING", "").strip().lower() or "true"
    if fail_text not in ("true", "false"):
        errors.append(f"'fail-on-warning' must be 'true' or 'false', not '{fail_text}'.")
    return Settings(domains, cert_setting, domain_days, fail_text == "true"), errors


def main() -> int:
    settings, errors = read_settings()
    if errors:
        for error in errors:
            print(workflow_command("error", error))
        return 2

    now = datetime.now(timezone.utc)
    registry = Registry(now, settings.domain_days)
    rows: list[tuple[str, Finding, Finding]] = []
    for host in settings.domains:
        cert = check_certificate(host, now, settings.cert_setting)
        registration = registry.check(host)
        rows.append((host, cert, registration))
        print(host)
        print(f"  certificate: {ICON[cert.level]}: {cert.summary}")
        print(f"  registration: {ICON[registration.level]}: {registration.summary}")
        annotate(cert.level, f"Certificate {host}", cert.summary)
        annotate(registration.level, f"Domain {host}", registration.summary)

    # Hosts are deduplicated and each registration is looked up under its host's own name, so each
    # host counts once for its certificate and once for its registration.
    findings = [finding for _, cert, reg in rows for finding in (cert, reg)]
    failures = sum(f.level == FAIL for f in findings)
    warnings = sum(f.level == WARN for f in findings)
    unknown = sum(f.level == UNKNOWN for f in findings)

    if settings.cert_setting == "auto":
        cert_rule = "auto (an eighth of the lifetime for certificates of 100 days or less, else 30 days)"
    else:
        cert_rule = f"{whole_days(settings.cert_setting)} days"
    lines = [
        "## Certificate and domain expiry",
        "",
        "| Domain | Certificate | Registration |",
        "| --- | --- | --- |",
    ]
    for host, cert, reg in rows:
        lines.append(f"| `{host}` | {ICON[cert.level]}: {cell(cert.summary)} | {ICON[reg.level]}: {cell(reg.summary)} |")
    lines += [
        "",
        f"{tally(failures, warnings, unknown)} Certificate rule: {cert_rule}; domain rule: {settings.domain_days} days.",
        "",
    ]
    write_file("GITHUB_STEP_SUMMARY", "\n".join(lines) + "\n")
    write_file("GITHUB_OUTPUT", f"warnings={warnings}\nfailures={failures}\n")
    print(f"\n{tally(failures, warnings, unknown)}")

    if failures or (settings.fail_on_warning and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
