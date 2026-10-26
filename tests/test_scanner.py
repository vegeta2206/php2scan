import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

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
