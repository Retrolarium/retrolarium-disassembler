from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from extract_sega_cd import SYNC, data_track_from_cue, mode1_raw_to_iso


class ExtractSegaCdTests(unittest.TestCase):
    def test_raw_mode1_sectors_are_stripped_without_audio_or_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            track = root / "disc-track1.bin"
            payloads = [bytes([1]) * 2048, bytes([2]) * 2048]
            track.write_bytes(b"".join(SYNC + b"\0\0\0\1" + payload + bytes(288)
                                       for payload in payloads))
            cue = root / "disc.cue"
            cue.write_text('FILE "disc-track1.bin" BINARY\n  TRACK 01 MODE1/2352\n', encoding="utf-8")
            output = root / "disc.iso"
            self.assertEqual(track, data_track_from_cue(cue))
            self.assertEqual(2, mode1_raw_to_iso(track, output))
            self.assertEqual(b"".join(payloads), output.read_bytes())

    def test_invalid_sector_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            track = root / "bad.bin"
            track.write_bytes(bytes(2352))
            with self.assertRaisesRegex(ValueError, "invalid Mode 1 sector"):
                mode1_raw_to_iso(track, root / "bad.iso")


if __name__ == "__main__":
    unittest.main()
