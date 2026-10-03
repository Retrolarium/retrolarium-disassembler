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
            self.assertEqual(((0x600, 0x608),), context.z80_ranges)
            self.assertEqual(1, z80.call_count)
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

    def test_relative_callbacks_keep_inline_data_logical_and_translate_rom_ranges(self):
        image = SimpleNamespace(header=SimpleNamespace(rom_start=0x1000))
        trusted, decoded = {0x200: object()}, {0x202: object()}
        context = SimpleNamespace(protected=((0x400, 0x408), (0x600, 0x608)),
                                  z80_ranges=((0x600, 0x608),), decoded=decoded)
        observer = object()
        with patch.object(pipeline, 'discover_relative_record_callback_seeds', return_value=()) as discover:
            pipeline._discover_relative_callbacks(image, trusted, {}, object(), context,
                                                   decode_request=observer, inline_data={0x1800: 6})
        self.assertIs(discover.call_args.args[1], trusted)
        self.assertIs(discover.call_args.args[2], decoded)
        self.assertIs(discover.call_args.kwargs['decode_request'], observer)
        self.assertEqual(((0x1400, 0x1408), (0x1600, 0x1608), (0x1800, 0x1806)),
                         discover.call_args.kwargs['protected_ranges'])
        self.assertEqual(((0x1600, 0x1608),), discover.call_args.kwargs['protected_record_ranges'])

    def test_cleared_pool_states_receive_physical_ranges_including_inline_data(self):
        image = SimpleNamespace(header=SimpleNamespace(rom_start=0x1000))
        trusted, decoded = {0x1200: object()}, {0x1202: object()}
        context = SimpleNamespace(protected=((0x400, 0x408),), decoded=decoded)
        with patch.object(pipeline, 'discover_cleared_pool_state_seeds', return_value=()) as discover:
            pipeline._discover_cleared_states(image, trusted, {}, object(), context, inline_data={0x1800: 6})
        self.assertIs(discover.call_args.args[1], trusted)
        self.assertIs(discover.call_args.args[2], decoded)
        self.assertEqual(((0x400, 0x408), (0x800, 0x806)), discover.call_args.kwargs['protected_ranges'])

    def test_absolute_and_finite_callbacks_separate_rooted_facts_and_logical_protection(self):
        image = SimpleNamespace(header=SimpleNamespace(rom_start=0x1000))
        trusted, decoded = {0x1200: object()}, {0x1202: object()}
        context = SimpleNamespace(protected=((0x400, 0x408), (0x600, 0x608)),
                                  z80_ranges=((0x600, 0x608),), decoded=decoded)
        observer = object()
        with patch.object(pipeline, 'discover_absolute_ram_callback_seeds', return_value=()) as discover:
            pipeline._discover_absolute_callbacks(image, trusted, {}, object(), context,
                                                   decode_request=observer, inline_data={0x1800: 6})
        self.assertIs(discover.call_args.args[1], trusted)
        self.assertIs(discover.call_args.args[2], decoded)
        self.assertIs(discover.call_args.kwargs['decode_request'], observer)
        expected = ((0x1400, 0x1408), (0x1600, 0x1608), (0x1800, 0x1806))
        self.assertEqual(expected, discover.call_args.kwargs['protected_ranges'])
        with patch.object(pipeline, 'discover_finite_record_callback_seeds', return_value=()) as discover:
            pipeline._discover_finite_callbacks(image, trusted, {}, object(), context,
                                                 decode_request=observer, inline_data={0x1800: 6})
        self.assertIs(discover.call_args.args[1], decoded)
        self.assertIs(discover.call_args.kwargs['execution_facts'], trusted)
        self.assertIs(discover.call_args.kwargs['decode_request'], observer)
        self.assertEqual(expected, discover.call_args.kwargs['protected_ranges'])
        self.assertEqual(((0x1600, 0x1608),), discover.call_args.kwargs['forbidden_reads'])

    def test_cursor_callbacks_receive_logical_protection_and_only_trusted_consumers(self):
        image = SimpleNamespace(header=SimpleNamespace(rom_start=0x1000))
        trusted, decoded = {0x200: object()}, {0x202: object()}
        context = SimpleNamespace(protected=((0x400, 0x408), (0x600, 0x608)),
                                  z80_ranges=((0x600, 0x608),))
        with patch.object(pipeline, 'discover_bytecode_cursor_seeds', return_value=()) as discover:
            pipeline._discover_cursor_callbacks(image, trusted, decoded, object(), context)
        self.assertIs(discover.call_args.args[1], decoded)
        self.assertIs(discover.call_args.kwargs['execution_facts'], trusted)
        self.assertEqual(((0x1400, 0x1408), (0x1600, 0x1608)),
                         discover.call_args.kwargs['protected_ranges'])
        self.assertEqual(((0x1600, 0x1608),),
                         discover.call_args.kwargs['protected_stream_ranges'])
        with patch.object(pipeline, 'discover_tail_allocator_callback_seeds', return_value=()) as discover:
            pipeline._discover_tail_callbacks(image, trusted, decoded, object(), context)
        self.assertIs(discover.call_args.args[1], decoded)
        self.assertIs(discover.call_args.kwargs['execution_facts'], trusted)
        self.assertEqual(((0x1400, 0x1408), (0x1600, 0x1608)),
                         discover.call_args.kwargs['protected_ranges'])


if __name__ == '__main__':
    unittest.main()
