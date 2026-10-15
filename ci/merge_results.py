"""Merge GitHub Actions shards and explicitly report partial scans."""

import argparse
import ipaddress
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


def merge_results(parts, source, output, shard_count):
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output / "asn9123_cidr.txt")
    records = {}
    errors = []
    shards = []
    for index in range(shard_count):
        shard = parts / f"asn9123-shard-{index}"
        code = None
        count = 0
        try:
            code = int((shard / "exit_code.txt").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            errors.append(f"Shard {index}: missing exit code")
        if code is not None and code != 0:
            errors.append(f"Shard {index}: exit code {code}")
        details = shard / "detected.jsonl"
        shard_ips = set()
        if details.exists():
            for number, line in enumerate(details.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    ip = str(ipaddress.IPv4Address(record["ip"]))
                    port = int(record["port"])
                    if record["status"] != "DETECTED" or not 1 <= port <= 65535:
                        raise ValueError("invalid detection record")
                    record["ip"], record["port"] = ip, port
                    records[(ip, port)] = record
                    shard_ips.add(ip)
                    count += 1
                except (ValueError, KeyError, TypeError) as exc:
                    errors.append(f"Shard {index}, JSONL line {number}: {exc}")
        else:
            errors.append(f"Shard {index}: missing detected.jsonl")
        try:
            text_ips = {
                str(ipaddress.IPv4Address(line.strip()))
                for line in (shard / "detected.txt").read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            if text_ips != shard_ips:
                errors.append(f"Shard {index}: TXT/JSONL detections differ")
        except (OSError, ValueError) as exc:
            errors.append(f"Shard {index}: cannot read detected.txt: {exc}")
        if shard.exists():
            shutil.copytree(shard, output / "shards" / f"shard-{index}", dirs_exist_ok=True)
        shards.append({"index": index, "exit_code": code, "records": count})

    ordered = sorted(records.values(), key=lambda r: (int(ipaddress.IPv4Address(r["ip"])), r["port"]))
    ips = sorted({record["ip"] for record in ordered}, key=ipaddress.IPv4Address)
    (output / "detected.txt").write_text("".join(ip + "\n" for ip in ips), encoding="utf-8")
    (output / "detected.jsonl").write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in ordered), encoding="utf-8",
    )
    summary = {
        "asn": 9123,
        "complete": not errors,
        "detected_ips": len(ips),
        "expected_shards": shard_count,
        "shards": shards,
        "errors": errors,
        "merged_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    markdown = [
        "# AS9123 scan", "",
        f"Status: **{'COMPLETE' if summary['complete'] else 'PARTIAL'}**", "",
        f"Detected IPv4: **{len(ips)}**", "",
        "The artifact includes the fetched CIDRs, merged detections and per-shard logs.", "",
    ]
    markdown.extend(f"- {error}" for error in errors)
    (output / "summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parts", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shards", type=int, default=4)
    args = parser.parse_args()
    if args.shards < 1:
        parser.error("shards must be positive")
    summary = merge_results(args.parts, args.input, args.output, args.shards)
    print(json.dumps(summary, indent=2))
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
