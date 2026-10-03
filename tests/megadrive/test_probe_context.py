"""Probe validators share work only while their rooted instruction set is fixed."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retrolarium_kit import megadrive_pipeline as pipeline


class PassProbeContextTests(unittest.TestCase):
    def test_all_validators_share_probes_and_protection_but_next_pass_recomputes(self):
        image, trusted = object(), {0x200: object()}
        decoded = {0x202: object()}
        speculative = {0x202: object(), 0x204: object()}
        artifacts = SimpleNamespace(orphan_facts=Path('probes.tsv'))
        pointers = [SimpleNamespace(status='accepted', physical_start=0x400, physical_end=0x408),
                    SimpleNamespace(status='rejected', physical_start=0x500, physical_end=0x508)]
        copies = [SimpleNamespace(source_start=0x600, source_end=0x607)]
        calls = []

        def consume(*args, **kwargs):
            calls.append((args[2], kwargs['protected_ranges']))
            return ()

        def witness(*args, **kwargs):
            consume(*args, **kwargs)
            return lambda address: False

        with (patch.object(pipeline, 'load_megadrive_ghidra_facts', return_value=speculative) as load,
              patch.object(pipeline, 'detect_pointer_candidates', return_value=pointers) as detect,
              patch.object(pipeline, 'detect_z80_copies', return_value=copies) as z80,
              patch.object(pipeline, 'discover_packed_orphan_closure', side_effect=consume),
              patch.object(pipeline, 'discover_validated_unused_candidates', side_effect=consume),
              patch.object(pipeline, 'make_dispatch_handler_validator', side_effect=witness)):
            context = pipeline._PassProbeContext(image, trusted, decoded, artifacts)
            self.assertEqual(0, detect.call_count)  # Lazy until a validator needs it.
            pipeline._discover_packed_code(image, trusted, decoded, artifacts, context)
            pipeline._discover_unused_code(image, trusted, decoded, artifacts, context)
            validator = pipeline._dispatch_handler_validator(image, trusted, decoded, artifacts, context)
            self.assertFalse(validator(0x300))
            self.assertFalse(validator(0x302))
            self.assertEqual((1, 1, 1), (load.call_count, detect.call_count, z80.call_count))
            self.assertEqual(3, len(calls))
            self.assertTrue(all(facts is context.decoded for facts, _ in calls))
            self.assertIs(context.decoded[0x202], decoded[0x202])
            self.assertIs(context.decoded[0x204], speculative[0x204])
            self.assertTrue(all(protected == ((0x400, 0x408), (0x600, 0x608))
                                for _, protected in calls))

            later = pipeline._PassProbeContext(image, {**trusted, **decoded}, decoded, artifacts)
            pipeline._discover_unused_code(image, later.trusted_facts, decoded, artifacts, later)
            self.assertEqual((2, 2, 2), (load.call_count, detect.call_count, z80.call_count))
            self.assertIsNot(context.decoded, later.decoded)


if __name__ == '__main__':
    unittest.main()
