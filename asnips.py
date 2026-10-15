#!/usr/bin/env python3
"""Save an ASN's announced IPv4 prefixes to asn<ASN>_cidr.txt."""

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_URL = "https://stat.ripe.net/data/ris-prefixes/data.json"


def parse_asn(value):
    match = re.fullmatch(r"(?:AS)?([0-9]{1,10})", value.strip(), re.IGNORECASE)
    if not match or not 1 <= int(match[1]) <= 4294967295:
        raise argparse.ArgumentTypeError("укажите ASN от 1 до 4294967295, например 9123")
    return int(match[1])


def fetch_prefixes(asn):
    params = urlencode({
        "resource": f"AS{asn}",
        "list_prefixes": "true",
        "types": "o",
        "af": "v4",
        "noise": "keep",
    })
    request = Request(
        f"{API_URL}?{params}",
        headers={"Accept": "application/json", "User-Agent": "asnips/1.0"},
    )
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)

    try:
        if payload["status"] != "ok":
            raise ValueError("RIPEstat вернул ошибку")
        entries = payload["data"]["prefixes"]["v4"]["originating"]
        if not isinstance(entries, list) or any(not isinstance(p, str) for p in entries):
            raise ValueError("неверный формат списка подсетей")
        prefixes = {ipaddress.IPv4Network(prefix) for prefix in entries}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Некорректный ответ RIPEstat: {exc}") from exc

    return sorted(prefixes, key=lambda p: (int(p.network_address), p.prefixlen))


def save_prefixes(path, prefixes):
    # Replace the destination only after the complete file has been written.
    temporary_path = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n",
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            for prefix in prefixes:
                temporary_file.write(f"{prefix}\n")
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="Получить IPv4-подсети ASN и сохранить в asn<номер>_cidr.txt."
    )
    parser.add_argument("asn", type=parse_asn, help="номер ASN, например 9123 или AS9123")
    args = parser.parse_args()
    output = Path(f"asn{args.asn}_cidr.txt")

    try:
        prefixes = fetch_prefixes(args.asn)
        save_prefixes(output, prefixes)
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    print(f"AS{args.asn}: сохранено IPv4-подсетей: {len(prefixes)} -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
