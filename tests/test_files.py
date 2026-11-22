from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrolarium_disassembler.files import sha256_file

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "retrolarium_disassembler"


class FileDigestTests(unittest.TestCase):
    def test_digest_of_a_file_larger_than_one_block(self) -> None:
        payload = bytes(range(256)) * (3 * 4096) + b"tail"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.bin"
            path.write_bytes(payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), sha256_file(path))

    def test_the_package_streams_file_digests_in_one_place(self) -> None:
        streaming = sorted(
            path.relative_to(PACKAGE).as_posix()
            for path in PACKAGE.rglob("*.py")
            if "iter(lambda: stream.read(" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(["files.py"], streaming)


if __name__ == "__main__":
    unittest.main()
