#!/usr/bin/env python3
"""Find IPv4 TLS endpoints whose valid certificate CN resolves elsewhere."""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import re
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import certifi
import dns.asyncresolver
import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID
from loguru import logger


@dataclass
class Result:
    status: str
    detail: str = ""
    record: dict | None = None


def load_networks(path):
    networks = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.IPv4Network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: неверный IPv4/CIDR: {value}") from exc
    if not networks:
        raise ValueError(f"{path}: нет IPv4-адресов или CIDR")
    return list(ipaddress.collapse_addresses(networks))


def normalize_cn(value):
    domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"CN не является конкретным DNS-именем: {value!r}")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError(f"CN содержит IP вместо домена: {value!r}")


def target_ranges(networks, shard_index=0, shard_count=1):
    """Partition IPv4 by integer modulo without expanding entire networks."""
    if shard_count < 1 or not 0 <= shard_index < shard_count:
        raise ValueError("shard-index должен быть от 0 до shard-count - 1")
    for network in networks:
        first = int(network.network_address)
        first += (shard_index - first) % shard_count
        yield range(first, int(network.broadcast_address) + 1, shard_count)


async def tls_certificate(ip, port, context, server_hostname, timeout):
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, port, ssl=context, server_hostname=server_hostname,
                ssl_handshake_timeout=timeout, ssl_shutdown_timeout=1,
            ),
            timeout=timeout,
        )
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        if not der:
            raise ValueError("сервер не прислал сертификат")
        return der
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (OSError, TimeoutError):
                pass


class Scanner:
    def __init__(self, port=443, timeout=5, dns_timeout=5):
        self.port = port
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.probe_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.probe_context.check_hostname = False
        self.probe_context.verify_mode = ssl.CERT_NONE
        self.verify_context = ssl.create_default_context(cafile=certifi.where())
        self.verify_context.hostname_checks_common_name = False
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.cache = dns.resolver.LRUCache(max_size=10000)
        self.pending_dns = {}

    async def _lookup_a(self, domain):
        answer = await self.resolver.resolve(
            domain, "A", lifetime=self.dns_timeout,
            search=False, raise_on_no_answer=False,
        )
        return tuple(sorted({record.address for record in answer}, key=ipaddress.IPv4Address))

    async def resolve_a(self, domain):
        # Coalesce concurrent lookups; the resolver cache respects DNS TTLs.
        task = self.pending_dns.get(domain)
        if task is None:
            task = asyncio.create_task(self._lookup_a(domain))
            self.pending_dns[domain] = task
        try:
            return await task
        finally:
            if task.done() and self.pending_dns.get(domain) is task:
                del self.pending_dns[domain]

    async def scan(self, ip):
        try:
            # An empty string explicitly disables SNI in asyncio.
            der = await tls_certificate(ip, self.port, self.probe_context, "", self.timeout)
            certificate = x509.load_der_x509_certificate(der)
            names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        except (OSError, ValueError, TimeoutError) as exc:
            return Result("no_certificate", str(exc))
        if len(names) != 1:
            return Result("no_cn", f"CN count: {len(names)}")
        try:
            domain = normalize_cn(names[0].value)
        except (UnicodeError, ValueError) as exc:
            return Result("invalid_cn", str(exc))

        try:
            addresses = await self.resolve_a(domain)
        except (dns.exception.DNSException, OSError, TimeoutError) as exc:
            return Result("dns_error", f"{domain}: {exc}")
        if not addresses:
            return Result("no_a", domain)
        if ip in addresses:
            return Result("original", f"{domain} A={','.join(addresses)}")

        try:
            verified_der = await tls_certificate(
                ip, self.port, self.verify_context, domain, self.timeout,
            )
        except ssl.SSLCertVerificationError as exc:
            return Result("invalid_certificate", f"{domain}: {exc.verify_message}")
        except (OSError, ValueError, TimeoutError) as exc:
            return Result("verification_error", f"{domain}: {exc}")
        if verified_der != der:
            return Result("certificate_changed", f"{domain}: SNI changed the certificate")

        record = {
            "ip": ip,
            "port": self.port,
            "cn": domain,
            "a_records": list(addresses),
            "certificate_sha256": hashlib.sha256(der).hexdigest(),
            "issuer": certificate.issuer.rfc4514_string(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": "DETECTED",
        }
        return Result("detected", domain, record)


async def run_scan(networks, args):
    scanner = Scanner(args.port, args.timeout, args.dns_timeout)
    ranges = list(target_ranges(networks, args.shard_index, args.shard_count))
    total = sum(len(addresses) for addresses in ranges)
    queue = asyncio.Queue(maxsize=args.workers * 2)
    counts = Counter()
    started = time.monotonic()

    async def produce():
        for addresses in ranges:
            # Include every address, also /31, /32 and subnet boundary addresses.
            for ip in addresses:
                await queue.put(str(ipaddress.IPv4Address(ip)))
        for _ in range(args.workers):
            await queue.put(None)

    async def progress():
        while True:
            await asyncio.sleep(5)
            elapsed = max(time.monotonic() - started, 0.001)
            done = sum(counts.values())
            logger.info(
                "Проверено {}/{} | DETECTED={} | {:.1f} IP/с",
                done, total, counts["detected"], done / elapsed,
            )

    # Flush each detection so an interrupted scan retains completed results.
    with args.output.open("w", encoding="utf-8", newline="\n") as ips_file, \
            args.details.open("w", encoding="utf-8", newline="\n") as details_file:
        async def worker():
            while True:
                ip = await queue.get()
                if ip is None:
                    return
                result = await scanner.scan(ip)
                if result.status == "detected":
                    details_file.write(json.dumps(result.record, ensure_ascii=False) + "\n")
                    details_file.flush()
                    ips_file.write(ip + "\n")
                    ips_file.flush()
                    logger.success(
                        "DETECTED {}:{} | CN={} | A={}", ip, args.port,
                        result.record["cn"], ",".join(result.record["a_records"]),
                    )
                else:
                    logger.debug("{} | {} | {}", ip, result.status, result.detail)
                counts[result.status] += 1

        logger.info(
            "Старт: {} IPv4, {} диапазонов, {} workers, порт {}, shard {}/{}",
            total, len(networks), args.workers, args.port,
            args.shard_index + 1, args.shard_count,
        )
        ticker = asyncio.create_task(progress())
        try:
            # A failure in a worker cancels the producer instead of hanging it.
            async with asyncio.TaskGroup() as group:
                group.create_task(produce())
                for _ in range(args.workers):
                    group.create_task(worker())
        finally:
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
            logger.info(
                "Итого: {}/{} IP | DETECTED={} | {:.1f} с | {}",
                sum(counts.values()), total, counts["detected"],
                time.monotonic() - started, dict(counts),
            )
    return counts


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("значение должно быть больше 0")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("значение должно быть конечным числом больше 0")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Сканировать IPv4/CIDR: CN → A → проверка публичной CA-цепочки и имени."
    )
    parser.add_argument("input", type=Path, help="файл с IPv4/CIDR, по одному на строку")
    parser.add_argument("-o", "--output", type=Path, default=Path("detected.txt"), help="IP детектов")
    parser.add_argument("--details", type=Path, default=Path("detected.jsonl"), help="данные детектов")
    parser.add_argument("--log", type=Path, default=Path("scanner.log"), help="файл loguru")
    parser.add_argument("-w", "--workers", type=positive_int, default=100, help="параллельность (100)")
    parser.add_argument("--timeout", type=positive_float, default=5, help="таймаут одного TLS-запроса, с (5)")
    parser.add_argument("--dns-timeout", type=positive_float, default=5, help="таймаут DNS, с (5)")
    parser.add_argument("--port", type=positive_int, default=443, help="TLS-порт (443)")
    parser.add_argument("--shard-index", type=int, default=0, help="индекс части скана, начиная с 0")
    parser.add_argument("--shard-count", type=positive_int, default=1, help="общее число частей (1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="логировать причины пропуска IP")
    args = parser.parse_args(argv)
    if args.port > 65535:
        parser.error("порт должен быть от 1 до 65535")
    if not 0 <= args.shard_index < args.shard_count:
        parser.error("shard-index должен быть от 0 до shard-count - 1")
    paths = [args.input, args.output, args.details, args.log]
    if len({path.resolve() for path in paths}) != len(paths):
        parser.error("вход, detected.txt, JSONL и лог должны быть разными файлами")
    try:
        networks = load_networks(args.input)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    logger.remove()
    log_format = "<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    logger.add(sys.stderr, level="DEBUG" if args.verbose else "INFO", format=log_format)
    try:
        logger.add(
            args.log, level="DEBUG" if args.verbose else "INFO", encoding="utf-8",
            rotation="10 MB", retention=3, enqueue=True, backtrace=False, diagnose=False,
        )
        asyncio.run(run_scan(networks, args))
    except KeyboardInterrupt:
        logger.warning("Остановлено. Уже записанные детекты сохранены.")
        return 130
    except Exception as exc:
        logger.opt(exception=args.verbose).error("Сканирование прервано: {}", exc)
        return 1
    finally:
        logger.complete()
    logger.info("Результаты: {} | {}", args.output, args.details)
    return 0


if __name__ == "__main__":
    sys.exit(main())
