"""Normal-return roots persist unless a stronger inline-DATA proof replaces them."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from megadrive.pipeline_harness import _M68kHarness, _StopAfterLoop
from retrolarium_disassembler.megadrive import pipeline
from retrolarium_disassembler.m68k.seeds import DecoderSeed
from retrolarium_disassembler.m68k.dispatch.ram import InlineTrapCall


class NormalReturnPlanTests(unittest.TestCase):
    def run_plan(self, passes):
        harness = _M68kHarness(passes)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.multiple(pipeline, **harness.patches()):
                with self.assertRaises(_StopAfterLoop):
                    pipeline.analyze_megadrive(root / "game.bin", root / "out", root / "ghidra")
            return harness.plans_seen, (root / "out/m68k/normal-return-calls.txt").read_text()

    def test_new_return_continuation_is_always_seeded_for_next_backend_pass(self):
        seed = DecoderSeed(0x206, "normal_return_continuation", "proven", "balanced RTS", 0x200)
        plans, returns = self.run_plan([{"returning": (seed,)}, {"returning": (seed,)}])
        self.assertEqual(2, len(plans))
        self.assertIn("000206", plans[1].splitlines())
        self.assertEqual("000200 000206\n", returns)

    def test_later_inline_data_supersedes_stale_normal_return_root(self):
        seed = DecoderSeed(0x206, "normal_return_continuation", "proven", "balanced RTS", 0x200)
        inline = InlineTrapCall(0x200, 0x206, 0x208, None, 0x300)
        plans, returns = self.run_plan(
            [{"returning": (seed,)}, {"inline_subroutine": (inline,)}, {"inline_subroutine": (inline,)}]
        )
        self.assertEqual(3, len(plans))
        self.assertIn("000206", plans[1].splitlines())
        self.assertNotIn("000206", plans[2].splitlines())
        self.assertIn("DATA 000206 2", plans[2].splitlines())
        self.assertEqual("000200 000206\n", returns)


if __name__ == "__main__":
    unittest.main()
