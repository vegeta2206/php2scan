# php2scan

External assessment helper for CVE-2026-109618 and CVE-2026-109619.

This project is based on
[Assetnote's php2shell-scanner](https://github.com/assetnote/php2shell-scanner)
and retains its MIT licence. This version adds conservative verdicts, discovery
and active modes, per-IP testing for multi-address hostnames, safer evidence
storage, and automated tests.

## Important safety notice

Active mode is **not a passive vulnerability scan**. It sends crafted multipart
requests designed to create memory pressure in PHP. One path can receive up to
three probes totalling roughly 29 MiB. The probes can trigger HTTP 500 errors,
worker restarts, resource alerts, or service degradation.

Only use `--active` against explicitly authorised targets, preferably during a
maintenance window. Start with one thread, monitor the service, and retain the
supplier's PHP and web-server logs.

## What php2scan can and cannot establish

php2scan is an **external assessment helper**, not a definitive vulnerability
proof. Its active probes exercise PHP's multipart parser and look for a
request-local memory exhaustion or worker-failure pattern:

```text
successful control request
        -> crafted multipart probe
        -> crash-like HTTP response
        -> successful recovery control request
```

A positive result is useful evidence for opening a supplier investigation. It
does not demonstrate arbitrary code execution and it does not prove which of
the two CVEs is exploitable on that server.

The scanner cannot remotely establish:

- the package and security revision actually loaded by the web worker;
- whether an older-looking version contains a distribution or vendor backport;
- whether a version disclosed by an HTTP header matches the executing runtime;
- the exact SAPI when the supplier does not disclose it;
- whether two requests reached the same persistent PHP worker;
- whether a hidden backend behind a load balancer was reached;
- whether an observed HTTP 500, 502, 503 or 504 came from PHP, a proxy, a WAF,
  a rate limit, or an unrelated outage;
- whether a crash-like condition can be developed into code execution.

Conversely, no signal does not prove safety. A WAF, reverse proxy, request-size
limit, load balancer, worker pool, allocator difference, patched-but-old version
string, hidden error response, or untested application path may prevent the
observable signal.

### What the two CVEs mean

- **CVE-2026-109618 — OOM corruption:** memory exhaustion can interrupt PHP
  while request state is only partially initialised. Request shutdown may then
  process invalid state. The multipart probes primarily exercise this externally
  observable OOM surface.
- **CVE-2026-109619 — stale global state:** request-owned state can survive in a
  persistent worker after its memory is released. A later request handled by the
  same worker may consume that stale state before normal initialisation resets
  it. Reliable external confirmation is harder because it depends on producer,
  consumer, worker reuse, configuration and heap state.

Official advisories:

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

### SAPI-specific interpretation

SAPI is the interface between the web server and PHP:

- `mod_php`: PHP runs inside the Apache worker. This is the highest-risk and
  best-confirmed exploitation environment in the PHP advisory.
- `fpm`: Nginx or Apache forwards the request to a persistent PHP-FPM worker.
  A failed worker may appear externally as an empty response or HTTP
  502/503/504 and is normally replaced by the FPM master.
- `auto`: applies both families of external heuristics. It has broader coverage
  but more ambiguity and therefore a higher false-positive risk.

Use `--sapi mod_php` or `--sapi fpm` when the supplier has confirmed the SAPI.
Do not infer the SAPI solely from the `Server` HTTP header.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `LIKELY_VULNERABLE` | Active crash-like signal observed; supplier-side logs and runtime must confirm it. |
| `SUSPICIOUS_SIGNAL` | Crash-like signal conflicts with an advertised patched version; possible resource-limit or proxy false positive. |
| `AT_RISK_VERSION` | HTTP advertises a supported PHP branch below the upstream fixed release; vendor backports remain possible. |
| `LEGACY_VERSION_REVIEW` | HTTP advertises an end-of-life PHP branch; request vendor backport evidence. |
| `PATCHED_VERSION_ADVERTISED` | HTTP advertises a fixed upstream version; this is evidence, not proof of the actual runtime. |
| `PARTIAL_MULTI_IP_COVERAGE` | A multi-address hostname was not tested on every resolved node. |
| `REDIRECT_OUT_OF_SCOPE` | Discovery stopped because a redirect changed the hostname. No probe was sent to the destination. |
| `REDIRECT_DURING_PROBE` | The final endpoint redirected an active probe; the large body was not replayed. |
| `INCONCLUSIVE` | No reliable external conclusion can be drawn. |
| `ERROR` | The assessment could not be completed. |

Absence of a crash-like signal is never reported as "not vulnerable".

## Requirements

- Python 3.9+
- `h11`
- `tqdm`

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Usage

Low-impact discovery (one small multipart POST; it is not a purely passive
network observation):

```bash
python3 scanner.py -u https://example.com
```

Authorised active assessment of one hostname:

```bash
python3 scanner.py -u https://example.com --active -o result.json
```

Same-host redirects are followed by default. HTTP to HTTPS and path changes are
allowed when the hostname is unchanged. A redirect to another hostname is
stopped and reported as `REDIRECT_OUT_OF_SCOPE`; add that destination as a
separate authorised target if required. Here, "same equipment" is deliberately
defined as the exact same canonical hostname (case-insensitive, with a trailing
dot ignored). Sharing an IP address is not enough: that address may host several
customers or services. A port or scheme change on the same hostname is allowed,
but authentication headers are removed when the origin changes. Disable all
redirect following with:

```bash
python3 scanner.py -u https://example.com --no-follow-redirects
```

Only the small discovery/control request follows allowed redirects. Active
memory-pressure probes are sent directly to the discovered same-host final URL
and are never replayed through a new redirect.

Test every resolved A/AAAA address while preserving the FQDN in the HTTP Host
header and TLS SNI:

```bash
python3 scanner.py -u https://example.com --active --scan-each-ip -o result.json
```

Test selected PHP paths:

```bash
python3 scanner.py -u https://example.com --active \
  --path /index.php --path /admin/index.php
```

Multiple hosts, with deliberately limited concurrency:

```bash
python3 scanner.py -l hosts.txt --active --scan-each-ip \
  --threads 2 --output results.json
```

Response bodies are omitted from stored evidence by default. If they are
required for an authorised investigation, enable them explicitly:

```bash
python3 scanner.py -u https://example.com --active --include-response-body
```

Bodies can contain sensitive application data. Authentication headers are
redacted in reports, but passing secrets on a command line can still expose
them through shell history or the process list.

## TLS assessment and fallback

TLS validation is attempted automatically for every HTTPS endpoint. If the
certificate is expired, self-signed, untrusted or does not match the hostname,
php2scan records the failure and retries without certificate validation so the
authorised PHP assessment can continue. The report clearly states that the test
continued insecurely. A protocol/cipher negotiation failure can still prevent
the HTTP assessment.

| TLS state | Meaning and guidance |
| --- | --- |
| `TLS_VALID` | Certificate validation succeeded. Protocols, ciphers and lifetime still require a dedicated TLS review. |
| `SELF_SIGNED_CERTIFICATE` | Test continued insecurely. Use a trusted public certificate or the approved private trust anchor. |
| `EXPIRED_CERTIFICATE` | Test continued insecurely. Renew the certificate and deploy the correct intermediate chain. |
| `HOSTNAME_MISMATCH` | Test continued insecurely. Add the tested FQDN to the certificate SAN. |
| `UNTRUSTED_CERTIFICATE` | Test continued insecurely. Repair the chain or use the approved enterprise CA. |
| `TLS_VERIFICATION_DISABLED` | `--insecure` prevented normal validation; rerun without it for usable TLS evidence. |
| `TLS_HANDSHAKE_FAILED` | No HTTP test was possible. Investigate protocols, ciphers, SNI and server logs. |
| `TLS_CONNECTION_FAILED` | Check listener, firewall, proxy and HTTPS reachability. |
| `HTTPS_TO_HTTP_DOWNGRADE` | Remove the downgrade and keep the complete path encrypted. |
| `PLAINTEXT_HTTP` | Enable HTTPS and redirect HTTP to HTTPS on the same hostname. |
| `MIXED` | Resolved endpoints have different TLS states; remediate and retest every IP. |

`--insecure` remains available for compatibility, but it skips the initial
validation attempt and therefore produces weaker evidence. The default
automatic validate-then-fallback behaviour is recommended.

Every result includes human-readable `guidelines` for both its vulnerability
verdict and TLS state. Standard output shows the TLS state for each host, while
the final summary counts TLS states across tested endpoints.

## Exit codes

- `0`: every result advertised a patched upstream version
- `1`: at least one active `LIKELY_VULNERABLE` result
- `2`: review required, inconclusive/error result, or output-write failure

## Multi-IP behaviour

Normal DNS resolution may select only one backend. If a hostname has multiple
addresses and `--scan-each-ip` is not used, php2scan refuses to clear the whole
hostname and returns `PARTIAL_MULTI_IP_COVERAGE`.

`--scan-each-ip` connects directly to every resolved address while retaining
the original FQDN for virtual hosting and TLS certificate validation. It does
not discover unknown FQDNs hosted on an IP address.

The address set is a DNS snapshot from the scanner's resolver and network
location. Geo-DNS, short TTLs and split-horizon DNS may return different
addresses elsewhere. Testing every resolved address still does not enumerate:

- multiple application servers hidden behind one load-balancer VIP;
- CDN or reverse-proxy origin servers;
- anycast sites sharing one IP address;
- backends selected by cookies, client address, health state or session
  persistence.

For multi-address hostnames, run with `--scan-each-ip --verbose` and retain all
`endpoint_results`. If only one address is tested, php2scan returns
`PARTIAL_MULTI_IP_COVERAGE` instead of clearing the FQDN.

## Interpreting external findings

External evidence should be combined with information from the hosting
supplier:

1. the PHP runtime actually serving the tested URL;
2. the package version and vendor security revision;
3. whether the vendor applied a backport;
4. the SAPI in use (`mod_php`, PHP-FPM, CGI, etc.);
5. web-server and PHP logs at the probe timestamp;
6. worker restart or crash evidence.

The upstream fixed releases are PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
Version strings alone cannot identify distribution or vendor backports.

### Supplier confirmation checklist

Send the supplier the tested FQDN, resolved IP, path, UTC timestamp, scan mode,
probe number, HTTP sequence and JSON evidence. Ask the supplier to confirm:

1. the PHP binary and package actually used by the tested web pool;
2. the SAPI and frontend architecture;
3. the distribution/vendor security revision and backport status for both CVEs;
4. PHP, web-server, WAF and reverse-proxy logs at the probe timestamp;
5. worker termination, restart, OOM or health-check events;
6. every backend serving the FQDN, not only the public frontend address;
7. the remediation applied and the post-remediation runtime evidence.

Suggested wording:

> Our authorised external assessment observed behaviour compatible with the
> PHP2Shell attack surface. This is not proof of exploitation. Please confirm
> the effective PHP runtime, SAPI, package/vendor backport status and server
> logs for CVE-2026-109618 and CVE-2026-109619.

## Remediation

Updating is the only complete remediation. Fixed upstream releases are:

| Branch | Fixed release |
| --- | --- |
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

PHP 8.1 and older are end-of-life upstream. Upgrade to a supported branch or
obtain explicit evidence of a vendor/LTS backport. Do not decide from the base
version string alone.

After updating or applying a vendor package:

1. restart every PHP and web-server worker;
2. verify the runtime used by the real web pool, not only the CLI binary;
3. record the package version, vendor advisory and backport revision;
4. test every relevant SAPI, pool, path and backend;
5. investigate possible compromise if the service was exposed before patching.

### Temporary risk reduction for CVE-2026-109618

These controls reduce specific paths but do **not** replace updating:

- administratively enforce `memory_limit=-1` so applications cannot restore a
  finite PHP limit;
- enforce conservative decoded request, multipart part, header, upload, input
  and nesting limits at the frontend;
- block `multipart/form-data` before PHP where uploads are not required;
- use container/cgroup limits only as an additional availability boundary;
- do not use `RLIMIT_AS` or `RLIMIT_DATA` as a workaround, because allocation
  failure can reach the vulnerable path.

### Temporary risk reduction for CVE-2026-109619

These controls reduce confirmed producer/consumer paths but are incomplete:

- set `session.upload_progress.enabled=0` in administrative configuration that
  applies before request parsing, then restart every worker;
- do not rely on application `ini_set()` or FPM `.user.ini` for this mitigation;
- on PHP 8.5, set `fatal_error_backtraces=0` and restart workers;
- remove invalid, deprecated or conflicting per-request INI settings that emit
  diagnostics during early initialisation;
- fix attacker-reachable fatal errors, timeouts and failures in upload/import or
  cleanup paths.

The current PHP project guidance is maintained on
[php.net](https://www.php.net/) and in the two official advisories linked above.

## Docker

```bash
docker build -t php2scan .
docker run --rm php2scan -u https://example.com
docker run --rm php2scan -u https://example.com --active
```

To read input files and write JSON results:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/data" -w /data php2scan \
  -l hosts.txt --active --scan-each-ip -o results.json
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
