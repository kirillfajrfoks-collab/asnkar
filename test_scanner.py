import asyncio
import ipaddress
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import dns.exception
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scanner import Scanner, load_networks, normalize_cn, target_ranges


def make_certificate(domain=None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]) if domain else x509.Name([])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class InputTests(unittest.TestCase):
    def test_shards_cover_every_ip_once_including_small_networks(self):
        networks = [ipaddress.IPv4Network(value) for value in (
            "192.0.2.0/29", "192.0.2.10/31", "192.0.2.15/32",
        )]
        expected = {int(ip) for network in networks for ip in network}
        for shard_count in (1, 3, 4, 16):
            with self.subTest(shard_count=shard_count):
                parts = [
                    {ip for addresses in target_ranges(networks, index, shard_count) for ip in addresses}
                    for index in range(shard_count)
                ]
                self.assertEqual(set().union(*parts), expected)
                self.assertEqual(sum(map(len, parts)), len(expected))
        for index, count in ((-1, 4), (4, 4), (0, 0)):
            with self.subTest(index=index, count=count), self.assertRaises(ValueError):
                list(target_ranges(networks, index, count))

    def test_overlaps_are_deduplicated_without_dropping_boundary_addresses(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            path = Path(directory) / "ranges.txt"
            path.write_text(
                "\ufeff# ranges\n192.0.2.0/30\n192.0.2.0/31\n192.0.2.1/32\n192.0.2.4 # single\n",
                encoding="utf-8",
            )
            networks = load_networks(path)
        self.assertEqual(
            [str(ip) for network in networks for ip in network],
            ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
        )

    def test_bad_input_reports_line_number(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            path = Path(directory) / "ranges.txt"
            path.write_text("192.0.2.1\n2001:db8::/32\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, ":2:"):
                load_networks(path)

    def test_cn_is_a_concrete_dns_name(self):
        self.assertEqual(normalize_cn("RuTube.RU."), "rutube.ru")
        self.assertEqual(normalize_cn("пример.рф"), "xn--e1afmkfd.xn--p1ai")
        for value in ("*.rutube.ru", "192.0.2.1", "localhost", "-bad.example", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_cn(value)


class DetectionTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.der = make_certificate("rutube.test")

    def setUp(self):
        self.scanner = Scanner()
        self.scanner.resolve_a = AsyncMock(return_value=("203.0.113.10",))
        self.tls_patch = patch("scanner.tls_certificate", new_callable=AsyncMock)
        self.tls = self.tls_patch.start()
        self.addCleanup(self.tls_patch.stop)
        self.tls.return_value = self.der

    async def test_candidate_requires_same_certificate_and_public_ca_hostname_check(self):
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "detected")
        self.assertEqual(result.record["ip"], "198.51.100.10")
        self.assertEqual(result.record["cn"], "rutube.test")
        self.assertEqual(result.record["a_records"], ["203.0.113.10"])
        probe, verification = self.tls.await_args_list
        self.assertEqual(probe.args[3], "")
        self.assertEqual(verification.args[3], "rutube.test")
        self.assertIs(verification.args[2], self.scanner.verify_context)
        self.assertTrue(self.scanner.verify_context.check_hostname)
        self.assertEqual(self.scanner.verify_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertFalse(self.scanner.verify_context.hostname_checks_common_name)

    async def test_ip_in_a_records_skips_second_handshake(self):
        result = await self.scanner.scan("203.0.113.10")
        self.assertEqual(result.status, "original")
        self.assertIsNone(result.record)
        self.assertEqual(self.tls.await_count, 1)

    async def test_dns_failure_is_not_a_detection(self):
        self.scanner.resolve_a.side_effect = dns.exception.DNSException("timeout")
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "dns_error")
        self.assertEqual(self.tls.await_count, 1)
        self.assertIsNone(result.record)

    async def test_no_a_records_is_not_a_detection(self):
        self.scanner.resolve_a.return_value = ()
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "no_a")
        self.assertEqual(self.tls.await_count, 1)

    async def test_failed_ca_hostname_or_time_verification_is_not_a_detection(self):
        failure = ssl.SSLCertVerificationError(1, "certificate verify failed")
        failure.verify_message = "certificate verify failed"
        self.tls.side_effect = [self.der, failure]
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "invalid_certificate")
        self.assertIsNone(result.record)

    async def test_sni_switching_to_another_certificate_is_not_a_detection(self):
        self.tls.side_effect = [self.der, make_certificate("rutube.test")]
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "certificate_changed")
        self.assertIsNone(result.record)

    async def test_closed_port_is_not_a_detection(self):
        self.tls.side_effect = ConnectionRefusedError("closed")
        result = await self.scanner.scan("198.51.100.10")
        self.assertEqual(result.status, "no_certificate")
        self.scanner.resolve_a.assert_not_awaited()

    async def test_missing_and_wildcard_cn_do_not_trigger_dns_queries(self):
        for domain, expected in ((None, "no_cn"), ("*.rutube.test", "invalid_cn")):
            with self.subTest(domain=domain):
                self.tls.return_value = make_certificate(domain)
                result = await self.scanner.scan("198.51.100.10")
                self.assertEqual(result.status, expected)
                self.scanner.resolve_a.assert_not_awaited()


class DnsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.scanner = Scanner()

    async def test_concurrent_queries_for_one_domain_share_one_lookup(self):
        scanner = self.scanner
        started, release = asyncio.Event(), asyncio.Event()

        async def lookup(domain):
            started.set()
            await release.wait()
            return ("203.0.113.10",)

        scanner._lookup_a = AsyncMock(side_effect=lookup)
        first = asyncio.create_task(scanner.resolve_a("rutube.test"))
        second = asyncio.create_task(scanner.resolve_a("rutube.test"))
        await asyncio.wait_for(started.wait(), timeout=1)
        release.set()
        self.assertEqual(await asyncio.gather(first, second), [("203.0.113.10",)] * 2)
        self.assertEqual(scanner._lookup_a.await_count, 1)
        self.assertEqual(scanner.pending_dns, {})


if __name__ == "__main__":
    unittest.main()
