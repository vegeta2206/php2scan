import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, patch

import scanner


def response(status=200, body=b"OK", powered_by=""):
    headers = {"X-Powered-By": powered_by} if powered_by else {}
    return scanner.HTTPResult(status_code=status, headers=headers, body=body)


class VersionVerdictTests(unittest.TestCase):
    def test_supported_branches(self):
        self.assertEqual(scanner.version_verdict("PHP/8.2.34"), "VULNERABLE")
        self.assertEqual(scanner.version_verdict("PHP/8.2.35"), "FIXED")
        self.assertEqual(scanner.version_verdict("PHP/8.5.12"), "FIXED")

    def test_legacy_and_unknown_versions(self):
        self.assertEqual(scanner.version_verdict("PHP/8.1.34"), "LEGACY")
        self.assertIsNone(scanner.version_verdict("PHP/9.0.0"))
        self.assertIsNone(scanner.version_verdict("hidden"))


class RedirectPolicyTests(unittest.TestCase):
    @patch("scanner.timed_exchange_post", new_callable=AsyncMock)
    def test_same_hostname_redirect_is_followed(self, exchange):
        redirected = response(status=302, body=b"", powered_by="")
        redirected.headers = {"Location": "https://example.test/app"}
        exchange.side_effect = [redirected, response(status=200, body=b"OK")]
        result = scanner.send_post(
            "http://example.test/", b"x", "x", {}, 5, True, True
        )
        self.assertEqual(exchange.await_count, 2)
        self.assertEqual(result.final_url, "https://example.test/app")
        self.assertIsNone(result.blocked_redirect)

    @patch("scanner.timed_exchange_post", new_callable=AsyncMock)
    def test_different_hostname_redirect_is_blocked(self, exchange):
        redirected = response(status=302, body=b"", powered_by="")
        redirected.headers = {"Location": "https://identity.example.net/login"}
        exchange.return_value = redirected
        result = scanner.send_post(
            "https://example.test/", b"x", "x", {}, 5, True, True
        )
        self.assertEqual(exchange.await_count, 1)
        self.assertEqual(
            result.blocked_redirect, "https://identity.example.net/login"
        )
        self.assertEqual(result.final_url, "https://example.test/")

    def test_redirects_are_enabled_by_default(self):
        parser = scanner.build_parser()
        self.assertTrue(parser.parse_args(["-u", "example.test"]).follow_redirects)
        self.assertFalse(
            parser.parse_args(
                ["-u", "example.test", "--no-follow-redirects"]
            ).follow_redirects
        )


class TLSPolicyTests(unittest.TestCase):
    def test_certificate_failures_have_specific_states_and_guidance(self):
        cases = {
            "certificate verify failed: self-signed certificate": (
                "SELF_SIGNED_CERTIFICATE"
            ),
            "certificate verify failed: certificate has expired": (
                "EXPIRED_CERTIFICATE"
            ),
            "certificate verify failed: hostname mismatch": "HOSTNAME_MISMATCH",
            "certificate verify failed: unable to get local issuer certificate": (
                "UNTRUSTED_CERTIFICATE"
            ),
        }
        for error, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(scanner.classify_tls_error(error), expected)
                self.assertIn(expected, scanner.TLS_GUIDANCE)

    @patch("scanner.send_post")
    def test_self_signed_certificate_is_recorded_and_retried(self, send_post):
        send_post.side_effect = [
            scanner.HTTPResult(
                error=(
                    "SSL error: certificate verify failed: self-signed certificate"
                ),
                final_url="https://example.test/",
            ),
            scanner.HTTPResult(
                status_code=200,
                body=b"OK",
                final_url="https://example.test/",
            ),
        ]
        control, status, error, insecure, effective_verify = (
            scanner.send_control_with_tls_policy(
                "https://example.test/", {}, 5, True, True, None
            )
        )
        self.assertEqual(control.status_code, 200)
        self.assertEqual(status, "SELF_SIGNED_CERTIFICATE")
        self.assertIn("self-signed", error)
        self.assertTrue(insecure)
        self.assertFalse(effective_verify)

    @patch("scanner.send_post")
    def test_valid_certificate_is_recorded(self, send_post):
        send_post.return_value = scanner.HTTPResult(
            status_code=200,
            body=b"OK",
            final_url="https://example.test/",
        )
        _control, status, error, insecure, effective_verify = (
            scanner.send_control_with_tls_policy(
                "https://example.test/", {}, 5, True, True, None
            )
        )
        self.assertEqual(status, "TLS_VALID")
        self.assertIsNone(error)
        self.assertFalse(insecure)
        self.assertTrue(effective_verify)

    @patch("scanner.send_post")
    def test_http_error_after_insecure_retry_keeps_certificate_state(self, send_post):
        send_post.side_effect = [
            scanner.HTTPResult(
                error=(
                    "SSL error: certificate verify failed: self-signed certificate"
                ),
                final_url="https://example.test/",
            ),
            scanner.HTTPResult(
                error="request timed out",
                final_url="https://example.test/",
            ),
        ]
        _control, status, _error, insecure, effective_verify = (
            scanner.send_control_with_tls_policy(
                "https://example.test/", {}, 5, True, True, None
            )
        )
        self.assertEqual(status, "SELF_SIGNED_CERTIFICATE")
        self.assertTrue(insecure)
        self.assertFalse(effective_verify)


class VerdictTests(unittest.TestCase):
    @patch("scanner.send_post", return_value=response())
    def test_passive_without_version_is_inconclusive(self, _send):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
        )
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(result["probes"], [])

    @patch("scanner.send_post", return_value=response(powered_by="PHP/8.1.34"))
    def test_passive_legacy_version_requires_review(self, _send):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
        )
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "LEGACY_VERSION_REVIEW")

    @patch("scanner.build_probe_body", return_value=b"probe")
    @patch(
        "scanner.send_post",
        side_effect=[
            response(body=b"control", powered_by="PHP/8.2.35"),
            response(status=500, body=b"", powered_by="PHP/8.2.35"),
            response(body=b"healthy", powered_by="PHP/8.2.35"),
        ],
    )
    def test_fixed_version_crash_signal_is_not_confirmed(self, _send, _build):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
            active=True,
        )
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "SUSPICIOUS_SIGNAL")
        self.assertIn("post_signal_control", result)

    @patch("scanner.build_probe_body", return_value=b"probe")
    @patch(
        "scanner.send_post",
        side_effect=[
            response(body=b"control", powered_by="PHP/8.2.34"),
            response(status=500, body=b"", powered_by="PHP/8.2.34"),
            response(body=b"healthy", powered_by="PHP/8.2.34"),
        ],
    )
    def test_unpatched_version_plus_signal_is_likely_vulnerable(
        self, _send, _build
    ):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
            active=True,
        )
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "LIKELY_VULNERABLE")
        self.assertEqual(result["confidence"], "high")

    @patch("scanner.build_probe_body", return_value=b"probe")
    @patch("scanner.send_post", return_value=response(body=b"normal"))
    def test_no_active_signal_is_inconclusive(self, _send, _build):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
            active=True,
        )
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        for probe_call in _send.call_args_list[1:]:
            self.assertFalse(probe_call.args[6])

    @patch("scanner.build_probe_body", return_value=b"probe")
    @patch(
        "scanner.send_post",
        side_effect=[
            response(body=b"control"),
            scanner.HTTPResult(
                status_code=307,
                headers={"Location": "/moved"},
                final_url="https://example.test/",
            ),
        ],
    )
    def test_active_probe_redirect_is_not_replayed(self, send_post, _build):
        result = scanner.check_url(
            "https://example.test/",
            "https://example.test/",
            5,
            True,
            {},
            "auto",
            active=True,
        )
        self.assertEqual(result["verdict"], "REDIRECT_DURING_PROBE")
        self.assertEqual(result["redirect_blocked"], "https://example.test/moved")
        self.assertEqual(send_post.call_count, 2)
        self.assertFalse(send_post.call_args_list[1].args[6])

    @patch("scanner.build_probe_body", return_value=b"probe")
    @patch(
        "scanner.send_post",
        side_effect=[
            response(body=b"control", powered_by="PHP/8.2.34"),
            response(status=500, body=b"", powered_by="PHP/8.2.34"),
            scanner.HTTPResult(error="connection refused"),
        ],
    )
    def test_signal_without_recovery_is_suspicious(self, _send, _build):
        result = scanner.check_url(
            "http://example.test/",
            "http://example.test/",
            5,
            True,
            {},
            "auto",
            active=True,
        )
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "SUSPICIOUS_SIGNAL")


class MultiAddressTests(unittest.TestCase):
    @patch("scanner.resolve_dns_addresses", return_value=(["192.0.2.1", "192.0.2.2"], []))
    @patch("scanner.check_url")
    def test_scan_each_ip_pins_every_address(self, check_url, _resolve):
        check_url.side_effect = lambda host, target, *args, **kwargs: {
            **scanner.base_result(host),
            "tested_url": target,
            "connect_ip": kwargs["connect_ip"],
            "vulnerable": False,
            "verdict": "PATCHED_VERSION_ADVERTISED",
        }
        result = scanner.check_vulnerability(
            "https://example.test/", scan_each_ip=True
        )
        self.assertEqual(
            [call.kwargs["connect_ip"] for call in check_url.call_args_list],
            ["192.0.2.1", "192.0.2.2"],
        )
        self.assertEqual(len(result["endpoint_results"]), 2)
        self.assertFalse(result["vulnerable"])

    @patch("scanner.resolve_dns_addresses", return_value=(["192.0.2.1", "192.0.2.2"], []))
    @patch("scanner.check_url")
    def test_single_node_cannot_clear_multi_address_host(self, check_url, _resolve):
        check_url.return_value = {
            **scanner.base_result("https://example.test/"),
            "vulnerable": False,
            "verdict": "PATCHED_VERSION_ADVERTISED",
        }
        result = scanner.check_vulnerability("https://example.test/")
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "PARTIAL_MULTI_IP_COVERAGE")


class OutputSafetyTests(unittest.TestCase):
    def test_response_bodies_are_omitted_by_default(self):
        dumped = scanner.response_dump(response(body=b"secret"))
        self.assertNotIn("secret", dumped)
        self.assertIn("body omitted", dumped)

    def test_printed_inconclusive_is_not_green(self):
        result = scanner.base_result("https://example.test/")
        result["verdict"] = "INCONCLUSIVE"
        scanner.Colors.YELLOW = scanner.Colors.GREEN = scanner.Colors.RESET = ""
        output = io.StringIO()
        with redirect_stdout(output):
            scanner.print_result(result)
        self.assertIn("[INCONCLUSIVE]", output.getvalue())


if __name__ == "__main__":
    unittest.main()
