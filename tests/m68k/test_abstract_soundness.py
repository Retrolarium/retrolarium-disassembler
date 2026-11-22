from __future__ import annotations

from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from retrolarium_disassembler.m68k.abstract import AbstractValue


def values(value: AbstractValue) -> set[int]:
    concrete = value.concrete_values(limit=1 << value.bits)
    return set(range(1 << value.bits)) if concrete is None else set(concrete)


class WidenSoundnessTests(unittest.TestCase):
    def test_widening_keeps_values_when_the_lower_alignment_changes(self):
        left = AbstractValue.interval(4, 12, 8, bits=8)
        right = AbstractValue.constant(2, bits=8)
        self.assertTrue({2, 4, 12} <= values(left.widen(right)))

    def test_widening_keeps_a_new_residue_inside_the_original_bounds(self):
        left = AbstractValue.interval(4, 20, 8, bits=8)
        right = AbstractValue.constant(6, bits=8)
        self.assertTrue({4, 6, 12, 20} <= values(left.widen(right)))

    def test_widening_keeps_joined_values_for_small_domains(self):
        rng = random.Random(20261121)
        for _ in range(600):
            lower = rng.randrange(255)
            left = AbstractValue.interval(lower, rng.randrange(lower + 1, 256), rng.randrange(1, 17), bits=8)
            other_lower = rng.randrange(256)
            right = AbstractValue.interval(
                other_lower,
                rng.randrange(other_lower, 256),
                rng.randrange(1, 17),
                bits=8,
            )
            with self.subTest(left=left, right=right):
                joined = left.join(right)
                self.assertTrue(values(left) | values(right) <= values(joined))
                self.assertTrue(values(joined) <= values(left.widen(right)))

    def test_an_aligned_widening_preserves_its_stride(self):
        left = AbstractValue.interval(4, 12, 4, bits=8)
        result = left.widen(AbstractValue.interval(0, 16, 4, bits=8))
        self.assertEqual((0, 255, 4), (result.lower, result.upper, result.step))

    def test_widening_with_unknown_stays_unknown(self):
        left = AbstractValue.interval(4, 12, 8, bits=8)
        self.assertEqual(set(range(256)), values(left.widen(AbstractValue.unknown(bits=8))))


class ArithmeticSoundnessTests(unittest.TestCase):
    def test_wraparound_and_range_compression_keep_every_concrete_result(self):
        cases = [
            (
                AbstractValue.interval(240, 255, 3, bits=8),
                AbstractValue.interval(0, 30, 5, bits=8),
            ),
            (
                AbstractValue.interval(0, 31, bits=8),
                AbstractValue.constant(255, bits=8),
            ),
            (
                AbstractValue.interval(1, 255, 7, bits=8),
                AbstractValue.interval(0, 255, 16, bits=8),
            ),
            (AbstractValue.interval(0, 255, bits=8), AbstractValue.unknown(bits=8)),
        ]
        rng = random.Random(20261122)
        for _ in range(500):
            lower = rng.randrange(256)
            left = AbstractValue.interval(lower, rng.randrange(lower, 256), rng.randrange(1, 24), bits=8)
            lower = rng.randrange(256)
            right = AbstractValue.interval(lower, rng.randrange(lower, 256), rng.randrange(1, 24), bits=8)
            cases.append((left, right))
        for left, right in cases:
            with self.subTest(left=left, right=right):
                a, b = values(left), values(right)
                self.assertTrue({(x + y) & 255 for x in a for y in b} <= values(left.add(right)))
                self.assertTrue({(x - y) & 255 for x in a for y in b} <= values(left.subtract(right)))

    def test_masks_keep_every_value_of_strided_ranges(self):
        rng = random.Random(20261123)
        for _ in range(500):
            lower = rng.randrange(256)
            value = AbstractValue.interval(lower, rng.randrange(lower, 256), rng.randrange(1, 24), bits=8)
            mask = rng.randrange(256)
            with self.subTest(value=value, mask=mask):
                self.assertTrue({x & mask for x in values(value)} <= values(value.bitwise_and(mask)))
