# Check certificate and domain expiry

A GitHub Action for a scheduled workflow: it checks the TLS certificate and the domain registration of each domain you list, and fails the run when one is close to expiring, or when a certificate can’t be verified or reached. Every result goes to the run log and the job summary.

It runs on your runner and needs no account, API key or token. It’s one Python 3 script that uses only the standard library: GitHub fetches the action like any other, but no extra packages are installed and no dependency code is downloaded at runtime. The only data it fetches is the RDAP data described below, and it sends nothing to us: no telemetry. GitHub’s Ubuntu and macOS runners already have `python3`; Windows runners are untested.

Made by Boring Utils ([boringutils.com](https://boringutils.com)), the studio behind the hosted [Expiry Watch](https://boringutils.com/expiry-watch). This action doesn’t use Expiry Watch or any Boring Utils server.

## Usage

```yaml
# .github/workflows/expiry.yml
name: Expiry check

on:
  schedule:
    - cron: '17 6 * * *' # every day at 06:17 UTC
  workflow_dispatch:

permissions: {}

jobs:
  expiry:
    runs-on: ubuntu-latest
    steps:
      - uses: hal-boring-utils/check-expiry-action@v1
        with:
          domains: |
            example.com
            www.example.com
            example.co.uk
            api.example.co.uk
```

List each registered domain itself, not only its subdomains: a registration is looked up under exactly the name you list (see [What it checks](#what-it-checks)).

Every name you list also gets the TLS certificate check on port 443; there’s no registration-only option. A registered domain that doesn’t serve HTTPS therefore fails as “could not check”.

`v1` is a release branch that only moves forward, to each 1.x release; its history is never rewritten. Each release also gets a version tag that never moves, starting with `v1.0.0`. To review every change before it runs, pin a version tag or a full commit SHA instead.

## How you hear about a failure

A failed run is the only alert this action gives, and it can’t promise that alert reaches you:

- GitHub notifies one person about a scheduled workflow. At first that’s whoever created it. When someone edits its cron line, notifications switch to that person, and when someone re-enables it after it was turned off, they switch to whoever re-enabled it. That person hears about it only if their notification settings include Actions ([GitHub’s docs on notifications](https://docs.github.com/en/actions/concepts/workflows-and-actions/notifications-for-workflow-runs)).
- GitHub can delay scheduled runs when Actions is busy, and may drop some at times of high load. They run only from the default branch.
- In a public repository, GitHub turns scheduled workflows off after 60 days without repository activity.

See [GitHub’s docs on scheduled events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule). A quiet inbox doesn’t mean a run passed: look at the workflow’s runs now and then.

## What it checks

For each domain:

- **Certificate.** The action connects to port 443, sends the host name (SNI) and verifies the chain and the host name with Python’s `ssl.create_default_context()` and the runner’s trust store. Then it reads the certificate’s start and expiry dates. If verification fails, that’s a failure, with the reason: an expired certificate, a hostname mismatch, a self-signed certificate, or a chain it can’t complete (`unable to get local issuer certificate`). If it can’t connect at all, that’s a failure too, reported as “could not check” and never as “expired”.
- **Domain registration.** It asks the registry for the name’s TLD, found in IANA’s bootstrap file (`https://data.iana.org/rdap/dns.json`), about exactly the name you list, over RDAP, and reads the expiry date: the event whose `eventAction` is `expiration`. It uses an answer only when it is the registry’s domain record of that same name: its `objectClassName` is `domain`, and each name it gives (`ldhName`, `unicodeName`) is the name you listed. A subdomain such as `www.example.com` usually has no record of its own, so its registration shows as “Unknown” with a note to list its registered domain too: list `example.com` as well, and the `example.com` row has the date. When the registry is down, doesn’t know the name, answers about a different name, publishes no expiry date (`.nl` doesn’t, for example) or the TLD has no RDAP service, the registration shows as “Unknown” with the reason, and the run doesn’t fail for it. Each name is looked up and counted once, however you write it: as a URL, in capitals, with a final dot, or an international name in Unicode or in its `xn--` form.
- **IP addresses** get the certificate check only.

Results go to the run log and to the job summary, a table with a row for each host and a count of failures, warnings and unknown registration dates. Failures and warnings also appear as annotations; GitHub shows only a limited number of annotations per step, so the log and the summary are the full record.

**Not a browser.** Browsers use their own root stores and rules: some fetch an intermediate certificate the server didn’t send, and they check things this action doesn’t, such as revocation and Certificate Transparency. A browser and this check can disagree, in either direction.

## Where it connects

Everything runs on the runner, which connects to:

- each host you list, on port 443: a TLS handshake, and no page is requested
- `data.iana.org`, once per run, for the bootstrap file (data that lists each TLD’s RDAP server)
- each registry’s RDAP server, once per domain name you list, and any address it redirects to

Requests to IANA and the registries name the action in their user agent, `boringutils-expiry-action/1.1 (+https://boringutils.com/expiry-watch)`, so their operators can see what is asking. Each name is looked up as itself, so the registries see every domain name you list, subdomains included.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `domains` | (required) | Domains or IP addresses, separated by newlines, commas or spaces. URLs work too; only the host name is used, and the check always uses port 443. Text after `#` is ignored. A registration is looked up under exactly the name listed, so list a subdomain’s registered domain too to check that registration. Every name listed also gets the TLS certificate check. |
| `cert-days` | `auto` | When a certificate warns. `auto` uses the lifetime rule below. A whole number warns when fewer than that many days are left; `0` never warns. An expired certificate always fails. |
| `domain-days` | `30` | Warn when a registration expires in fewer than this many days. A whole number; `0` never warns. An expired registration always fails. |
| `fail-on-warning` | `true` | `true` or `false`. With `false`, warnings are reported without failing the step. Failures always fail it. |

An input the action can’t read, such as `cert-days: -5`, an entry in `domains` that isn’t a domain name or IP address, an international name it could read as two different domains (see [Limits](#limits)), or `fail-on-warning: no`, fails the step with an error that names it, before anything is checked.

## Outputs

| Output | Meaning |
| --- | --- |
| `warnings` | Number of warnings. |
| `failures` | Number of failures: an expired, untrusted or unreachable certificate, or an expired registration. |

Each host counts once for its certificate and once for its registration.

## The lifetime rule (`cert-days: auto`)

- **Certificates of 100 days or less** warn once **less than an eighth of their lifetime** is left: 8 days for a 64-day certificate, about 11 for a 90-day one, under 6 for a 45-day one.
- **Longer certificates** warn at **30 days**.

Why the rule follows lifetime: certificates are getting shorter. Let’s Encrypt’s default profile moves from 90-day to 64-day certificates on February 10, 2027, and to 45 days in 2028 ([Let’s Encrypt, October 7, 2026](https://letsencrypt.org/2026/10/07/64-day-certs/)). Automated renewal (certbot, Caddy, most hosts and CDNs) normally replaces a short-lived certificate when about a third of its lifetime is left: about 15 days before a 45-day certificate expires. A fixed 30-day warning would go off for about two weeks of every healthy 45-day certificate’s life, before its renewal is even due. By the time only an eighth is left, renewal is well past due: a 45-day certificate warns once fewer than 5.625 days remain. The time until your next scheduled run comes out of that notice, so how much is left when you see the warning depends on your schedule.

Certificates valid for only a few days have hours left by this rule, so a daily run can go straight from OK to expired. For those, schedule the workflow more often than once a day.

## Limits

- **Exact names only, on purpose.** Earlier releases guessed a host’s registered domain from its last two or three labels, and the guess could be someone else’s registration: `shop.example.co.at` was looked up as `co.at`, and any date the registry gave for `co.at` was reported on that row. The action now looks up exactly the name you list and uses only the registry’s record of that name, so it doesn’t report another registration’s date as yours. In exchange, a subdomain’s registration is “Unknown” unless you list its registered domain too, and the registries see each name you list.
- **International names with ß, ς, or a zero-width joiner or non-joiner** go in their `xn--` form. IDNA 2008 encodes `faß.de` as `xn--fa-hia.de`, while the older IDNA 2003, which [Python’s built-in codec](https://docs.python.org/3/library/codecs.html#module-encodings.idna) follows, makes it `fass.de`: two different domains. Rather than check the wrong one, the action stops with an error that names the entry.
- **One address.** The certificate check connects to whichever address the runner resolves. Behind a CDN or load balancer, other edges or nodes can serve a different certificate.
- **Expired certificates.** When verification fails, the action reports the reason but not the dates, because Python only reads the dates of a certificate it verified.
- **Port 443 only**, and the runner’s network: a host that is private or firewalled from GitHub’s runners shows as “could not check”.
- It informs; it doesn’t guarantee. A passing run means the checks found nothing at that moment.

## Email alerts without CI

If you’d rather get an email than a failed run, our hosted [Expiry Watch](https://boringutils.com/expiry-watch) checks the same things daily and emails you alerts, free for up to 10 domains.

## Development

```sh
python3 -m unittest -v                                  # unit and end-to-end tests; the network is mocked
INPUT_DOMAINS="example.com" python3 -I check_expiry.py  # a real check from your machine
```

`examples/verify.yml` is a workflow template, and this repository doesn’t run it: GitHub runs only the workflows in `.github/workflows/`. To use it, copy it to `.github/workflows/verify.yml` in a GitHub repository that holds this action’s code, such as a fork, and start it by hand (Actions, Verify, Run workflow) once a release is published. It runs the unit tests and two checks of what is published: the job the [expiry guide](https://boringutils.com/guides/check-ssl-certificate-expiry) gives readers to copy, as written, with `@v1`, and a job that installs the version tag you name from this repository on Ubuntu and macOS runners, checks real hosts and makes sure an unreachable one fails.

## License

MIT. See [LICENSE](LICENSE). Made by Boring Utils.
