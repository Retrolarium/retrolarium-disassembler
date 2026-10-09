"""Opt-in real Ghidra smoke: RETROLARIUM_RUN_GHIDRA_TESTS=1."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "src"))
from retrolarium_disasm.ghidra import find_headless


@unittest.skipUnless(os.environ.get("RETROLARIUM_RUN_GHIDRA_TESTS") == "1", "real Ghidra smoke is opt-in")
class PlannedSeedRestoreIntegrationTests(unittest.TestCase):
    def test_restoration_preserves_existing_code_and_data(self):
        ghidra = Path(os.environ.get("RETROLARIUM_GHIDRA_HOME", KIT / ".tools" / "ghidra"))
        with tempfile.TemporaryDirectory(prefix="m68k_restore_smoke_") as temporary:
            root = Path(temporary)
            image = bytearray(b"\xff" * 0x400)
            for offset, raw in {
                0x200: "70004E75", 0x220: "203C11224E75", 0x240: "203C11223344",
                0x260: "303C4E75", 0x280: "4E75", 0x2A0: "4E75",
                0x2C0: "7000203C11223344", 0x2E0: "7000203C11223344",
                0x300: "70004E75", 0x340: "70004E75", 0x360: "203C11223344",
                0x380: "4E4000424E75",
            }.items():
                image[offset:offset + len(raw) // 2] = bytes.fromhex(raw)
            rom = root / "fixture.bin"
            rom.write_bytes(image)
            plan = root / "seeds.txt"
            plan.write_text("DATA 0002A0 2\nDATA 0002C4 2\nDATA 000364 2\nDATA 000382 2\n"
                            + "\n".join(f"{a:06X}" for a in (
                                0x200, 0x220, 0x240, 0x262, 0x280, 0x2A0, 0x2C0,
                                0x2E0, 0x300, 0x343, 0x360, 0x380, 0x382, 0x384)) + "\n")
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy2(KIT / "src/retrolarium_disasm/ghidra/scripts/RestoreM68kPlannedSeeds.java", scripts)
            shutil.copy2(KIT / "tests/ghidra_scripts/VerifyM68kPlannedSeeds.java", scripts)
            command = [str(find_headless(ghidra)), str(root), "restore_smoke", "-import", str(rom),
                       "-loader", "BinaryLoader", "-loader-blockName", "ROM", "-loader-baseAddr", "0",
                       "-processor", "68000:BE:32:default", "-noanalysis", "-scriptPath", str(scripts),
                       "-postScript", "VerifyM68kPlannedSeeds.java", str(plan), "-deleteProject"]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", timeout=180)
            self.assertEqual(0, result.returncode, result.stdout[-12000:])
            self.assertNotIn("REPORT SCRIPT ERROR:", result.stdout, result.stdout[-12000:])
            self.assertIn("[PASS] planned-seed restoration respects", result.stdout, result.stdout[-12000:])


if __name__ == "__main__":
    unittest.main()
