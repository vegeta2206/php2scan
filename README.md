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

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `LIKELY_VULNERABLE` | Active crash-like signal observed; supplier-side logs and runtime must confirm it. |
| `SUSPICIOUS_SIGNAL` | Crash-like signal conflicts with an advertised patched version; possible resource-limit or proxy false positive. |
| `AT_RISK_VERSION` | HTTP advertises a supported PHP branch below the upstream fixed release; vendor backports remain possible. |
| `LEGACY_VERSION_REVIEW` | HTTP advertises an end-of-life PHP branch; request vendor backport evidence. |
| `PATCHED_VERSION_ADVERTISED` | HTTP advertises a fixed upstream version; this is evidence, not proof of the actual runtime. |
| `PARTIAL_MULTI_IP_COVERAGE` | A multi-address hostname was not tested on every resolved node. |
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

## Docker

```bash
docker build -t php2scan .
docker run --rm php2scan -u https://example.com
docker run --rm php2scan -u https://example.com --active
```

To read input files and write JSON results:

```bash
docker run --rm -v "$PWD:/data" -w /data php2scan \
  -l hosts.txt --active --scan-each-ip -o results.json
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
