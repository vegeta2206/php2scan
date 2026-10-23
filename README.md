# php2shell-scanner

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A target is reported vulnerable when the probe produces a PHP memory-exhaustion error, a differential empty HTTP 500, a PHP-FPM worker failure, or an advertised PHP version known to be unpatched. Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed unless `--follow-redirects` is set.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

## Requirements

- Python 3.9+
- h11
- tqdm

## Installation

```
pip install -r requirements.txt
```

### Docker

Build the image:

```
docker build -t php2shell-scanner .
```

Run it with the same options as `scanner.py`:

```
docker run --rm php2shell-scanner -u https://example.com
```

Mount the current directory to read host lists and write results:

```
docker run --rm -v "$PWD:/data" -w /data php2shell-scanner -l hosts.txt -o results.json
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use only PHP-FPM verdict rules:

```
python3 scanner.py -u https://example.com --sapi fpm
```

## Options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 60)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable TLS certificate verification
--follow-redirects Follow HTTP redirects (up to 10 hops)
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show verdict reasons and response snippets
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--sapi            Verdict rules: auto, mod_php, or fpm (default: auto)
--path            Custom path to test (can be used multiple times)
--path-file       File containing paths to test (one per line)
```

## Credits

The first, original discovery of php2shell is attributed to the Calif team. You can read their write up here: [https://calif.io/php2shell/](https://calif.io/php2shell/).

The scanner was built by the Assetnote Security Research Team using logic built for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence.

## Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports
