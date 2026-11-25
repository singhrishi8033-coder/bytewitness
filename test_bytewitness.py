import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from bytewitness import collect, identify, WINDOW


class EvidenceTests(unittest.TestCase):
    def test_empty(self):
        record = collect("empty", b"", set())
        self.assertEqual(record["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(record["high_entropy_window_count"], 0)

    def test_offsets_and_cap(self):
        data = b"abc https://example.invalid/ " * 40
        record = collect("abc", data, set())
        self.assertEqual(record["url_count"], 40)
        self.assertEqual(len(record["urls"]), 32)
        self.assertEqual(record["urls"][0]["offset"], 4)

    def test_entropy_window_boundaries(self):
        data = bytes(WINDOW) + bytes(range(256)) * 16 + bytes(17)
        record = collect("abc", data, set())
        self.assertEqual(record["high_entropy_windows"], [
            {"offset": WINDOW, "length": WINDOW, "bits_per_byte": 8.0}])

    def test_header_offsets(self):
        data = bytearray(88)
        data[:2] = b"MZ"
        data[60:64] = (64).to_bytes(4, "little")
        data[64:68] = b"PE\0\0"
        record = collect("picture.png", data, set())
        self.assertEqual(record["findings"][0]["rule"], "unexpected_pe_extension")
        self.assertFalse(collect("app.EXE", data, set())["findings"])
        self.assertEqual(identify(data[:-1]), "MZ prefix")
        data[60:64] = bytes([255]) * 4
        self.assertEqual(identify(data), "MZ prefix")

    def test_partial_batch(self):
        result = subprocess.run([sys.executable, "bytewitness.py", "--watchlist",
                                 "examples/watchlist.txt", "examples/invoice.txt",
                                 "examples/missing"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(report["reports"][0]["findings"][0]["rule"], "local_hash_match")

    def test_malformed_watchlist(self):
        result = subprocess.run([sys.executable, "bytewitness.py", "--watchlist",
                                 "examples/invoice.txt", "examples/invoice.txt"],
                                capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"line 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
