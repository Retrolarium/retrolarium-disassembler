from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retrolarium-core" / "python"))
from retrolarium_disassembler.facts import InstructionReference
from retrolarium_disassembler.m68k.dispatch.closure import make_dispatch_closure_validator
from retrolarium_disassembler.m68k.dispatch.witness import make_dispatch_handler_validator
from retrolarium_core.megadrive import parse_megadrive
from retrolarium_disassembler.megadrive.emit import _asm_instruction
from megadrive.builders import cartridge
from m68k.builders import instruction


def call(address, target):
    return instruction(address, "4eb9" + f"{target:08x}", "JSR", f"0x{target:x}.l", "UNCONDITIONAL_CALL", (target,))


def jump(address, target):
    return instruction(address, "4ef9" + f"{target:08x}", "JMP", f"0x{target:x}.l", "UNCONDITIONAL_JUMP", (target,))


class DispatchClosureTests(unittest.TestCase):
    def setUp(self):
        self.known = {0x900: instruction(0x900, "4e75", "RTS", flow="TERMINATOR")}
        self.decoded = {
            f.cpu_address: f
            for f in (
                call(0x400, 0x300),
                instruction(0x406, "4a40", "TST.W", "D0w"),
                instruction(0x408, "5240", "ADDQ.W", "0x1|D0w"),
                instruction(0x40A, "4e75", "RTS", flow="TERMINATOR"),
                call(0x300, 0x900),
                instruction(0x306, "4e75", "RTS", flow="TERMINATOR"),
            )
        }

    def validator(self, *, origin=0, factory=make_dispatch_closure_validator, trap5=None, **kwargs):
        data = bytearray(cartridge(size=0x2000))
        if trap5 is not None:
            data[37 * 4 : 38 * 4] = trap5.to_bytes(4, "big")
        for fact in (*self.known.values(), *self.decoded.values()):
            offset = fact.cpu_address - origin
            data[offset : offset + fact.length] = fact.raw
        image = parse_megadrive(bytes(data))
        if origin:
            image = replace(image, header=replace(image.header, rom_start=origin, rom_end=origin + len(data) - 1))
        return factory(image, self.known, self.decoded, render_instruction=_asm_instruction, **kwargs)

    def test_unknown_direct_callee_and_public_fallback(self):
        self.assertTrue(self.validator()(0x400))
        self.assertTrue(self.validator(factory=make_dispatch_handler_validator)(0x400))

    def test_unknown_tail_has_its_own_complete_cfg(self):
        self.decoded[0x400] = call(0x400, 0x900)
        self.decoded[0x40A] = jump(0x40A, 0x300)
        self.assertTrue(self.validator()(0x400))
        self.decoded.pop(0x306)
        self.assertFalse(self.validator()(0x400))

    def test_every_branch_path_needs_a_decode(self):
        self.decoded[0x300] = instruction(0x300, "661e", "BNE.B", "0x320", "CONDITIONAL_JUMP", (0x320,))
        self.decoded[0x302] = call(0x302, 0x900)
        self.decoded[0x308] = instruction(0x308, "4e75", "RTS", flow="TERMINATOR")
        self.decoded.pop(0x306)
        requests = []
        self.assertFalse(self.validator(decode_request=lambda *args: requests.append(args))(0x400))
        self.assertIn(0x320, {item[0] for item in requests})
        self.decoded[0x320] = instruction(0x320, "4e75", "RTS", flow="TERMINATOR")
        self.assertTrue(self.validator()(0x400))

    def test_protected_operand_span_and_data_read_block_callee(self):
        self.assertFalse(self.validator(protected_ranges=((0x304, 0x306),))(0x400))
        self.known[0x900] = replace(self.known[0x900], references=(InstructionReference(0x304, "READ", 0),))
        self.assertFalse(self.validator()(0x400))

    def test_known_instruction_interior_is_never_a_callee(self):
        self.known[0x2FE] = instruction(0x2FE, "303c4eb9", "MOVE.W", "#0x4eb9|D0w")
        self.assertFalse(self.validator()(0x400))

    def test_callee_and_caller_cannot_disagree_on_byte_ownership(self):
        # $302/$304 form legal instructions inside another legal MOVE.L.
        self.decoded = {
            f.cpu_address: f
            for f in (
                call(0x400, 0x300),
                call(0x406, 0x302),
                call(0x40C, 0x900),
                instruction(0x412, "4e75", "RTS", flow="TERMINATOR"),
                instruction(0x300, "203c70004e75", "MOVE.L", "#0x70004e75|D0"),
                instruction(0x302, "7000", "MOVEQ", "0x0|D0"),
                instruction(0x304, "4e75", "RTS", flow="TERMINATOR"),
                instruction(0x306, "4e75", "RTS", flow="TERMINATOR"),
            )
        }
        self.assertFalse(self.validator()(0x400))

    def test_independent_overlapping_cfgs_fail_in_both_query_orders(self):
        self.decoded = {
            f.cpu_address: f
            for f in (
                instruction(0x300, "203c70014a40", "MOVE.L", "#0x70014a40|D0"),
                instruction(0x302, "7001", "MOVEQ", "0x1|D0"),
                instruction(0x304, "4a40", "TST.W", "D0w"),
                instruction(0x306, "5240", "ADDQ.W", "0x1|D0w"),
                call(0x308, 0x900),
                instruction(0x30E, "4e75", "RTS", flow="TERMINATOR"),
            )
        }
        for factory in (make_dispatch_closure_validator, make_dispatch_handler_validator):
            for entries in ((0x300, 0x302), (0x302, 0x300)):
                validator = self.validator(factory=factory)
                self.assertEqual([validator(a) for a in entries], [False, False])
        # Merely having a competing decode is insufficient to veto code: the
        # alternative must itself pass complete CFG and rooted-connection checks.
        self.decoded[0x302] = replace(self.decoded[0x302], mnemonic="UNSUPPORTED")
        self.decoded[0x304] = replace(self.decoded[0x304], mnemonic="UNSUPPORTED")
        self.assertTrue(self.validator()(0x300))
        self.assertTrue(self.validator(factory=make_dispatch_handler_validator)(0x300))

    def test_self_and_mutual_call_cycles_fail_closed(self):
        self.decoded[0x300] = call(0x300, 0x300)
        self.assertFalse(self.validator()(0x400))
        self.decoded[0x300] = call(0x300, 0x400)
        self.assertFalse(self.validator()(0x400))

    def test_recursion_budget_and_missing_callee_do_not_publish_partial_closure(self):
        for address in range(0x1000, 0x10A0, 0x10):
            self.decoded[address] = call(address, address + 0x10)
            self.decoded[address + 6] = instruction(address + 6, "4e75", "RTS", flow="TERMINATOR")
        self.decoded[0x10A0] = call(0x10A0, 0x900)
        self.decoded[0x10A6] = instruction(0x10A6, "4e75", "RTS", flow="TERMINATOR")
        self.decoded[0x300] = call(0x300, 0x1000)
        self.assertFalse(self.validator()(0x400))
        warmed = self.validator()
        for address in reversed(range(0x1000, 0x10B0, 0x10)):
            warmed(address)
        self.assertFalse(warmed(0x400))

    def test_independent_closed_code_needs_rooted_outgoing_connection(self):
        self.decoded = {
            f.cpu_address: f
            for f in (
                instruction(0x400, "7001", "MOVEQ", "0x1|D0"),
                instruction(0x402, "4a40", "TST.W", "D0w"),
                instruction(0x404, "5240", "ADDQ.W", "0x1|D0w"),
                instruction(0x406, "4e75", "RTS", flow="TERMINATOR"),
            )
        }
        self.assertFalse(self.validator()(0x400))

    def test_return_address_pop_and_unproven_exception_rejected(self):
        self.decoded[0x300] = instruction(0x300, "201f", "MOVE.L", "(SP)+|D0")
        self.decoded[0x302] = instruction(0x302, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.validator()(0x400))
        self.decoded[0x300] = instruction(0x300, "4e40", "TRAP", "0x0", flow="CALL_TERMINATOR")
        self.assertFalse(self.validator()(0x400))

    def test_supervisor_immediate_is_only_a_normal_path_code_witness(self):
        from retrolarium_disassembler.m68k.records.constructor import _unsupported_frame_or_exception

        self.decoded.pop(0x306)
        self.decoded[0x304] = call(0x304, 0x900)
        self.decoded[0x30A] = instruction(0x30A, "4e75", "RTS", flow="TERMINATOR")
        for value in (0x2000, 0x2500, 0x2700, 0x271F):
            fact = instruction(0x300, f"46fc{value:04x}", "MOVE", f"#0x{value:x}|SR")
            self.decoded[0x300] = fact
            self.assertTrue(self.validator()(0x400), hex(value))
            # Return/constructor/inline proofs must retain their stricter gate.
            self.assertTrue(_unsupported_frame_or_exception(fact), hex(value))

    def test_status_stack_switch_trace_reserved_bits_and_unknown_source_rejected(self):
        self.decoded.pop(0x306)
        self.decoded[0x304] = call(0x304, 0x900)
        self.decoded[0x30A] = instruction(0x30A, "4e75", "RTS", flow="TERMINATOR")
        for value in (0, 0x700, 0xA000, 0x3000, 0x2800, 0x2020):
            self.decoded[0x300] = instruction(0x300, f"46fc{value:04x}", "MOVE", f"#0x{value:x}|SR")
            self.assertFalse(self.validator()(0x400), hex(value))
        self.decoded[0x300] = instruction(0x300, "46f80000", "MOVE", "(0x0).w|SR")
        self.assertFalse(self.validator()(0x400))

    def test_supervisor_witness_rejects_mismatching_metadata(self):
        from retrolarium_disassembler.m68k.dispatch.closure import _supervisor_immediate_in_code

        fact = instruction(0x300, "46fc2700", "MOVE", "#0x2700|SR")
        self.assertTrue(_supervisor_immediate_in_code(fact))
        for changed in (
            replace(fact, operands="#0x2000|SR"),
            replace(fact, raw=bytes.fromhex("46fc0700")),
            replace(fact, length=2),
            replace(fact, flow_type="TERMINATOR"),
            replace(fact, operands="D0w|SR"),
        ):
            self.assertFalse(_supervisor_immediate_in_code(changed))

    def test_rooted_connection_does_not_justify_an_unresolved_computed_call(self):
        self.decoded[0x300] = call(0x300, 0x900)
        self.decoded[0x306] = instruction(0x306, "4e90", "JSR", "(A0)", flow="COMPUTED_CALL")
        self.decoded[0x308] = instruction(0x308, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.validator()(0x400))
        self.assertFalse(self.validator(factory=make_dispatch_handler_validator)(0x400))

    def test_width_qualified_stack_alias_cannot_modify_return_address(self):
        self.decoded.pop(0x306)
        self.decoded.update(
            {
                f.cpu_address: f
                for f in (
                    instruction(0x300, "304f", "MOVEA.W", "A7w|A0"),
                    instruction(0x302, "5890", "ADDQ.L", "0x4|(A0)"),
                    call(0x304, 0x900),
                    instruction(0x30A, "4e75", "RTS", flow="TERMINATOR"),
                )
            }
        )
        self.assertFalse(self.validator()(0x400))
        self.assertFalse(self.validator(factory=make_dispatch_handler_validator)(0x400))

    def test_rooted_inline_trap_abi_in_unknown_callee_and_argument_ownership(self):
        from m68k.dispatch.test_witness import InlineTrapWitnessTests

        fixture = InlineTrapWitnessTests()
        fixture.setUp()
        self.known = fixture.known
        self.decoded = {
            f.cpu_address: f
            for f in (
                call(0x400, 0x300),
                instruction(0x406, "4e75", "RTS", flow="TERMINATOR"),
                instruction(0x300, "4e45", "TRAP", "0x5", flow="CALL_TERMINATOR"),
                instruction(0x302, "4e71", "NOP"),
                instruction(0x304, "7001", "MOVEQ", "0x1|D0"),
                instruction(0x306, "4a40", "TST.W", "D0w"),
                call(0x308, 0x500),
                instruction(0x30E, "4e75", "RTS", flow="TERMINATOR"),
            )
        }
        self.assertTrue(self.validator(factory=make_dispatch_handler_validator, trap5=0x200)(0x400))
        self.decoded[0x406] = call(0x406, 0x302)
        self.decoded[0x40C] = instruction(0x40C, "4e75", "RTS", flow="TERMINATOR")
        self.assertFalse(self.validator(factory=make_dispatch_handler_validator, trap5=0x200)(0x400))

    def test_validation_cache_is_scoped_to_facts_snapshot(self):
        old = self.validator()
        self.assertTrue(old(0x400))
        self.decoded.pop(0x306)
        self.assertTrue(old(0x400))
        self.assertFalse(self.validator()(0x400))

    def test_nonzero_rom_origin_uses_logical_addresses_and_physical_bytes(self):
        base = 0x800000
        self.known = {base + 0x900: instruction(base + 0x900, "4e75", "RTS", flow="TERMINATOR")}
        self.decoded = {
            f.cpu_address: f
            for f in (
                call(base + 0x400, base + 0x300),
                instruction(base + 0x406, "4a40", "TST.W", "D0w"),
                instruction(base + 0x408, "5240", "ADDQ.W", "0x1|D0w"),
                instruction(base + 0x40A, "4e75", "RTS", flow="TERMINATOR"),
                call(base + 0x300, base + 0x900),
                instruction(base + 0x306, "4e75", "RTS", flow="TERMINATOR"),
            )
        }
        self.assertTrue(self.validator(origin=base)(base + 0x400))
        self.assertTrue(self.validator(origin=base, factory=make_dispatch_handler_validator)(base + 0x400))
        # Public witness API protection ranges are ROM offsets.
        self.assertFalse(
            self.validator(origin=base, factory=make_dispatch_handler_validator, protected_ranges=((0x304, 0x306),))(
                base + 0x400
            )
        )


if __name__ == "__main__":
    unittest.main()
