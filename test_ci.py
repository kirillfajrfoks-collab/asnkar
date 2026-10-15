import json
import tempfile
import unittest
from pathlib import Path

from ci.merge_results import merge_results


class MergeResultsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.parts = self.root / "parts"
        self.output = self.root / "output"
        self.source = self.root / "asn9123_cidr.txt"
        self.source.write_text("192.0.2.0/24\n", encoding="utf-8")

    def write_shard(self, index, ips, code=0):
        path = self.parts / f"asn9123-shard-{index}"
        path.mkdir(parents=True)
        (path / "exit_code.txt").write_text(str(code), encoding="utf-8")
        (path / "detected.txt").write_text("".join(ip + "\n" for ip in ips), encoding="utf-8")
        (path / "detected.jsonl").write_text(
            "".join(json.dumps({"ip": ip, "port": 443, "status": "DETECTED"}) + "\n" for ip in ips),
            encoding="utf-8",
        )
        (path / "scanner.log").write_text("test log\n", encoding="utf-8")
        return path

    def test_complete_scan_merges_deduplicates_sorts_and_keeps_input_and_logs(self):
        self.write_shard(0, ["192.0.2.10", "192.0.2.2"])
        self.write_shard(1, ["192.0.2.2"])
        summary = merge_results(self.parts, self.source, self.output, 2)
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["detected_ips"], 2)
        self.assertEqual((self.output / "detected.txt").read_text(), "192.0.2.2\n192.0.2.10\n")
        self.assertEqual((self.output / "asn9123_cidr.txt").read_bytes(), self.source.read_bytes())
        self.assertTrue((self.output / "shards" / "shard-1" / "scanner.log").exists())

    def test_missing_or_failed_shards_keep_detections_and_mark_partial(self):
        self.write_shard(0, ["192.0.2.10"], code=124)
        summary = merge_results(self.parts, self.source, self.output, 2)
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["detected_ips"], 1)
        self.assertEqual(summary["shards"][0]["exit_code"], 124)
        self.assertIsNone(summary["shards"][1]["exit_code"])
        self.assertIn("PARTIAL", (self.output / "summary.md").read_text())

    def test_zero_detections_is_a_complete_scan(self):
        self.write_shard(0, [])
        summary = merge_results(self.parts, self.source, self.output, 1)
        self.assertTrue(summary["complete"])
        self.assertEqual((self.output / "detected.txt").read_text(), "")

    def test_truncated_record_and_inconsistent_files_do_not_look_complete(self):
        shard = self.write_shard(0, ["192.0.2.10"])
        with (shard / "detected.jsonl").open("a", encoding="utf-8") as stream:
            stream.write('{"ip":')
        (shard / "detected.txt").write_text("192.0.2.2\n", encoding="utf-8")
        summary = merge_results(self.parts, self.source, self.output, 1)
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["detected_ips"], 1)
        self.assertEqual(len(summary["errors"]), 2)


if __name__ == "__main__":
    unittest.main()
