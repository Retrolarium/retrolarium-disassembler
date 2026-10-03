"""Prove variable-length inline operands consumed by a called handler.

Runtimes such as software floating point or script interpreters place their
operands directly after ``JSR``/``BSR``. The handler decodes those ROM bytes
and advances its saved return PC by an amount that depends on them, so the
continuation cannot be found by assuming a fixed argument size.

The length is a property of ROM bytes, so it is derived per call site with a
partial 68000 emulator: ROM is concrete, registers and RAM are unknown, the
stack is symbolic and both successors of an unknown condition are explored.
Data registers track individual known bits, because operand decoders extract
fields with byte moves, shifts and masks from registers whose upper bits are
unknown. States reaching the same instruction in the same internal call
context are joined, so loops over unknown data terminate. A site is accepted
only when every explored return to the caller lands on one even address after
the call and within ``MAX_INLINE_BYTES``. Any unsupported instruction, unknown
control target or exhausted budget rejects the site instead of guessing.

Writes through unknown or absolute addresses are assumed not to alias the
handler's own stack frame; the return slot is only reachable through SP or a
frame pointer derived from it.
"""
from __future__ import annotations

from collections import deque
from typing import NamedTuple

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .m68k_ram_dispatch import InlineTrapCall


MAX_INLINE_BYTES = 32
MAX_SITE_STEPS = 40_000
MAX_PROBE_STEPS = 96
MAX_CALL_DEPTH = 8
MAX_WALK_INSTRUCTIONS = 50_000

FULL = 0xFFFFFFFF
_MASK = {1: 0xFF, 2: 0xFFFF, 4: FULL}
_SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000}
SP = 15


class Sym(NamedTuple):
    """An address relative to a symbolic base: initial SP or return PC."""
    base: str
    offset: int


class Part(NamedTuple):
    """A value of which only the bits set in ``mask`` are known."""
    value: int
    mask: int


class Unsupported(Exception):
    """The emulator cannot model this path; no claim is made."""


def _signed(value, size):
    value &= _MASK[size]
    return value - (_MASK[size] + 1) if value & _SIGN[size] else value


def _bits(value):
    if isinstance(value, int):
        return value & FULL, FULL
    if isinstance(value, Part):
        return value.value, value.mask
    return 0, 0


def _make(value, mask):
    mask &= FULL
    if mask == FULL:
        return value & FULL
    if mask == 0:
        return None
    return Part(value & mask, mask)


def _full(value):
    return value if isinstance(value, (int, Sym)) else None


def _low(value, size):
    """The low ``size`` bytes when all of them are known."""
    bits, mask = _bits(value)
    return bits & _MASK[size] if mask & _MASK[size] == _MASK[size] else None


def _join_value(left, right):
    if left == right:
        return left
    if isinstance(left, Sym) or isinstance(right, Sym):
        return None
    (lv, lm), (rv, rm) = _bits(left), _bits(right)
    return _make(lv, lm & rm & ~(lv ^ rv))


def _add(value, delta):
    value, delta = _full(value), _full(delta)
    if value is None or delta is None:
        return None
    if isinstance(value, Sym):
        if isinstance(delta, Sym):
            return None
        return Sym(value.base, value.offset + _signed(delta, 4))
    if isinstance(delta, Sym):
        return _add(delta, value)
    return (value + delta) & FULL


def _sub(value, delta):
    value, delta = _full(value), _full(delta)
    if isinstance(value, Sym) and isinstance(delta, Sym):
        return (value.offset - delta.offset) & FULL if value.base == delta.base else None
    if isinstance(delta, Sym) or delta is None:
        return None
    return _add(value, (-delta) & FULL)


def _logic(kind, left, right, size):
    """AND/OR/EOR over known bits, restricted to ``size``."""
    (lv, lm), (rv, rm) = _bits(left), _bits(right)
    if kind == "and":
        value, mask = lv & rv, (lm & rm) | (lm & ~lv) | (rm & ~rv)
    elif kind == "or":
        value, mask = lv | rv, (lm & rm) | (lm & lv) | (rm & rv)
    else:
        value, mask = lv ^ rv, lm & rm
    return _make(value & _MASK[size], mask & _MASK[size])


def _store(stack, offset, size, value):
    """Store bytes; a symbolic value survives only as a whole long."""
    for i in range(size):
        if isinstance(value, Sym):
            cell = (value, i) if size == 4 else None
        else:
            low = _low(value, size)
            cell = None if low is None else (low >> (8 * (size - 1 - i))) & 0xFF
        if cell is None:
            stack.pop(offset + i, None)
        else:
            stack[offset + i] = cell


class State:
    __slots__ = ("regs", "flags", "stack", "chain")

    def __init__(self, regs, flags, stack, chain):
        self.regs = regs
        self.flags = flags
        self.stack = stack
        self.chain = chain

    def copy(self):
        return State(list(self.regs), dict(self.flags), dict(self.stack), self.chain)

    def key(self):
        return (tuple(self.regs), tuple(sorted(self.flags.items())),
                tuple(sorted(self.stack.items())))

    def join(self, other):
        regs = [_join_value(a, b) for a, b in zip(self.regs, other.regs)]
        # Address registers are used whole; partial knowledge is no address.
        regs[8:] = [_full(value) for value in regs[8:]]
        flags = {k: v if other.flags.get(k) == v else None for k, v in self.flags.items()}
        stack = {k: v for k, v in self.stack.items() if other.stack.get(k) == v}
        return State(regs, flags, stack, self.chain)


class _Operand:
    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind = kind  # "d", "a", "mem", "imm"
        self.value = value  # register index, address or immediate


class _Emulator:
    def __init__(self, image: MegaDriveImage):
        self.data = image.data
        self.origin = image.header.rom_start
        self.reads_return_stream = False

    # -- memory -----------------------------------------------------------
    def word(self, address):
        offset = address - self.origin
        if address & 1 or not 0 <= offset <= len(self.data) - 2:
            raise Unsupported(f"instruction fetch at {address:06X}")
        return int.from_bytes(self.data[offset:offset + 2], "big")

    def read(self, state, address, size):
        if isinstance(address, Sym):
            if address.base == "R":
                self.reads_return_stream = True
                return None
            cells = [state.stack.get(address.offset + i) for i in range(size)]
            if size == 4 and all(isinstance(c, tuple) for c in cells):
                symbol = cells[0][0]
                if all(c == (symbol, i) for i, c in enumerate(cells)):
                    return symbol
            if all(isinstance(c, int) for c in cells):
                return int.from_bytes(bytes(cells), "big")
            return None
        if not isinstance(address, int):
            return None
        address &= 0xFFFFFF
        offset = address - self.origin
        if 0 <= offset <= len(self.data) - size and address < 0x400000:
            return int.from_bytes(self.data[offset:offset + size], "big")
        return None

    def write(self, state, address, size, value):
        if isinstance(address, Sym) and address.base == "S":
            _store(state.stack, address.offset, size, value)

    def push(self, state, value):
        state.regs[SP] = _add(state.regs[SP], (-4) & FULL)
        if not isinstance(state.regs[SP], Sym):
            raise Unsupported("stack pointer lost")
        self.write(state, state.regs[SP], 4, value)

    def pop(self, state):
        if not isinstance(state.regs[SP], Sym):
            raise Unsupported("stack pointer lost")
        value = self.read(state, state.regs[SP], 4)
        state.regs[SP] = _add(state.regs[SP], 4)
        return value

    # -- registers --------------------------------------------------------
    def set_dreg(self, state, index, size, value):
        if size == 4:
            state.regs[index] = value if isinstance(value, (Sym, Part)) or value is None else value & FULL
            return
        new_value, new_mask = _bits(value)
        old_value, old_mask = _bits(state.regs[index])
        keep = FULL & ~_MASK[size]
        state.regs[index] = _make((old_value & keep) | (new_value & _MASK[size]),
                                  (old_mask & keep) | (new_mask & _MASK[size]))

    def set_areg(self, state, index, size, value):
        if size == 2:
            low = _low(value, 2)
            value = None if low is None else _signed(low, 2) & FULL
        state.regs[8 + index] = _full(value)

    # -- effective addresses ---------------------------------------------
    def ea(self, state, pc, mode, reg, size):
        """Resolve an EA; returns (operand, next extension address)."""
        if mode == 0:
            return _Operand("d", reg), pc
        if mode == 1:
            return _Operand("a", reg), pc
        if mode == 2:
            return _Operand("mem", state.regs[8 + reg]), pc
        if mode == 3:
            address = state.regs[8 + reg]
            step = 2 if reg == 7 and size == 1 else size
            state.regs[8 + reg] = _add(address, step)
            return _Operand("mem", address), pc
        if mode == 4:
            step = 2 if reg == 7 and size == 1 else size
            address = _add(state.regs[8 + reg], (-step) & FULL)
            state.regs[8 + reg] = address
            return _Operand("mem", address), pc
        if mode == 5:
            return _Operand("mem", _add(state.regs[8 + reg], _signed(self.word(pc), 2) & FULL)), pc + 2
        if mode == 6:
            return _Operand("mem", self.indexed(state, state.regs[8 + reg], self.word(pc))), pc + 2
        if reg == 0:
            return _Operand("mem", _signed(self.word(pc), 2) & 0xFFFFFF), pc + 2
        if reg == 1:
            return _Operand("mem", ((self.word(pc) << 16) | self.word(pc + 2)) & 0xFFFFFF), pc + 4
        if reg == 2:
            return _Operand("mem", (pc + _signed(self.word(pc), 2)) & 0xFFFFFF), pc + 2
        if reg == 3:
            return _Operand("mem", self.indexed(state, pc, self.word(pc))), pc + 2
        if reg == 4:
            if size == 4:
                return _Operand("imm", (self.word(pc) << 16) | self.word(pc + 2)), pc + 4
            return _Operand("imm", self.word(pc) & _MASK[size]), pc + 2
        raise Unsupported("invalid effective address")

    def indexed(self, state, base, extension):
        index = state.regs[(extension >> 12) & 0xF]
        if extension & 0x0800:
            index = _full(index)
        else:
            low = _low(index, 2)
            index = None if low is None else _signed(low, 2) & FULL
        return _add(_add(base, index), _signed(extension, 1) & FULL)

    def get(self, state, operand, size):
        """Operand value: int, Sym (long only), Part (registers) or None."""
        if operand.kind in ("d", "a"):
            value = state.regs[operand.value + (8 if operand.kind == "a" else 0)]
            if size == 4:
                return value
            if isinstance(value, Sym):
                return None
            bits, mask = _bits(value)
            return _make(bits & _MASK[size], mask & _MASK[size])
        if operand.kind == "imm":
            return operand.value
        return self.read(state, operand.value, size)

    def put(self, state, operand, size, value):
        if operand.kind == "d":
            self.set_dreg(state, operand.value, size, value)
        elif operand.kind == "a":
            self.set_areg(state, operand.value, size, value)
        elif operand.kind == "mem":
            self.write(state, operand.value, size, value)
        else:
            raise Unsupported("write to immediate")

    # -- flags ------------------------------------------------------------
    @staticmethod
    def logic_flags(state, value, size):
        """N/Z from known bits; V and C clear."""
        if isinstance(value, Sym):
            value = None
        bits, mask = _bits(value)
        bits, mask = bits & _MASK[size], mask & _MASK[size]
        negative = int(bool(bits & _SIGN[size])) if mask & _SIGN[size] else None
        if bits & mask:
            zero = 0
        elif mask == _MASK[size]:
            zero = 1
        else:
            zero = None
        state.flags.update(N=negative, Z=zero, V=0, C=0)

    @staticmethod
    def arith(state, left, right, size, subtract, *, extend=True, compare=False):
        """Return left +/- right and update flags."""
        lv, rv = _low(left, size), _low(right, size)
        if lv is None or rv is None or (size == 4 and (isinstance(left, Sym) or isinstance(right, Sym))):
            state.flags.update(N=None, Z=None, V=None, C=None)
            if extend and not compare:
                state.flags["X"] = None
            if size == 4:
                return _sub(left, right) if subtract else _add(left, right)
            return None
        mask, sign = _MASK[size], _SIGN[size]
        result = ((lv - rv) if subtract else (lv + rv)) & mask
        if subtract:
            carry = int(rv > lv)
            overflow = int(bool((lv ^ rv) & (lv ^ result) & sign))
        else:
            carry = int(lv + rv > mask)
            overflow = int(bool(~(lv ^ rv) & (lv ^ result) & sign))
        state.flags.update(N=int(bool(result & sign)), Z=int(result == 0), V=overflow, C=carry)
        if extend and not compare:
            state.flags["X"] = carry
        return result

    @staticmethod
    def condition(state, code):
        f = state.flags
        n, z, v, c = f.get("N"), f.get("Z"), f.get("V"), f.get("C")

        def known(*values):
            return all(value is not None for value in values)
        if code == 0:
            return True
        if code == 1:
            return False
        if code in (2, 3):
            if c == 1 or z == 1:
                higher = False
            elif known(c, z):
                higher = True
            else:
                return None
            return higher if code == 2 else not higher
        if code in (4, 5):
            return None if c is None else (c == 0) == (code == 4)
        if code in (6, 7):
            return None if z is None else (z == 0) == (code == 6)
        if code in (8, 9):
            return None if v is None else (v == 0) == (code == 8)
        if code in (10, 11):
            return None if n is None else (n == 0) == (code == 10)
        if code in (12, 13):
            return None if not known(n, v) else (n == v) == (code == 12)
        if z == 1:
            greater = False
        elif known(n, v, z):
            greater = n == v
        else:
            return None
        return greater if code == 14 else not greater

    # -- execution --------------------------------------------------------
    def step(self, state, pc):
        """Execute one instruction; returns successor (pc, state) pairs.

        A return to the original caller is reported as ``("return", target)``.
        """
        opcode = self.word(pc)
        ext = pc + 2
        group = opcode >> 12
        mode, reg = (opcode >> 3) & 7, opcode & 7
        size = (1, 2, 4, None)[(opcode >> 6) & 3]

        if group in (1, 2, 3):
            move_size = {1: 1, 3: 2, 2: 4}[group]
            source, ext = self.ea(state, ext, mode, reg, move_size)
            value = self.get(state, source, move_size)
            destination_mode, destination_reg = (opcode >> 6) & 7, (opcode >> 9) & 7
            if destination_mode == 1:
                if move_size == 1:
                    raise Unsupported("byte MOVEA")
                self.set_areg(state, destination_reg, move_size, value)
                return [(ext, state)]
            destination, ext = self.ea(state, ext, destination_mode, destination_reg, move_size)
            self.put(state, destination, move_size, value)
            self.logic_flags(state, value, move_size)
            return [(ext, state)]

        if group == 7:
            if opcode & 0x100:
                raise Unsupported("invalid MOVEQ")
            value = _signed(opcode & 0xFF, 1) & FULL
            state.regs[(opcode >> 9) & 7] = value
            self.logic_flags(state, value, 4)
            return [(ext, state)]

        if group == 6:
            condition = (opcode >> 8) & 0xF
            displacement = _signed(opcode & 0xFF, 1)
            if displacement == 0:
                displacement = _signed(self.word(ext), 2)
                following = pc + 4
            else:
                following = pc + 2
            target = (pc + 2 + displacement) & 0xFFFFFF
            if condition == 1:
                return self.call(state, target, following)
            taken = self.condition(state, condition)
            if taken is None:
                return [(target, state), (following, state.copy())]
            return [(target if taken else following, state)]

        if group == 5:
            if size is None:
                return self.condition_codes(state, pc, opcode, ext, mode, reg)
            quick = ((opcode >> 9) & 7) or 8
            operand, ext = self.ea(state, ext, mode, reg, size)
            subtract = bool(opcode & 0x100)
            if operand.kind == "a":
                value = state.regs[8 + reg]
                state.regs[8 + reg] = _sub(value, quick) if subtract else _add(value, quick)
                return [(ext, state)]
            value = self.get(state, operand, size)
            self.put(state, operand, size, self.arith(state, value, quick, size, subtract))
            return [(ext, state)]

        if group == 4:
            return self.misc(state, opcode, ext, mode, reg, size)
        if group == 0:
            return self.immediate(state, opcode, ext, mode, reg, size)
        if group == 0xE:
            return self.shift(state, opcode, ext, mode, reg, size)
        if group in (8, 9, 0xB, 0xC, 0xD):
            return self.alu(state, opcode, ext, group, mode, reg)
        raise Unsupported(f"opcode {opcode:04X}")

    def condition_codes(self, state, pc, opcode, ext, mode, reg):
        """DBcc and Scc."""
        condition = (opcode >> 8) & 0xF
        result = self.condition(state, condition)
        if mode != 1:
            operand, ext = self.ea(state, ext, mode, reg, 1)
            self.put(state, operand, 1, None if result is None else (0xFF if result else 0))
            return [(ext, state)]
        target = (ext + _signed(self.word(ext), 2)) & 0xFFFFFF
        following = pc + 4
        if result is True:
            return [(following, state)]
        successors = [(following, state.copy())] if result is None else []
        counter = _low(state.regs[reg], 2)
        if counter is None:
            exhausted = state.copy()
            self.set_dreg(state, reg, 2, None)
            self.set_dreg(exhausted, reg, 2, 0xFFFF)
            return successors + [(target, state), (following, exhausted)]
        counter = (counter - 1) & 0xFFFF
        self.set_dreg(state, reg, 2, counter)
        return successors + [(following if counter == 0xFFFF else target, state)]

    def call(self, state, target, following):
        if len(state.chain) >= MAX_CALL_DEPTH:
            raise Unsupported("call depth")
        self.push(state, following)
        state.chain = state.chain + (following,)
        return [(target, state)]

    def misc(self, state, opcode, ext, mode, reg, size):
        if opcode == 0x4E75:
            target = self.pop(state)
            if not isinstance(target, int):
                raise Unsupported("unknown return target")
            target &= 0xFFFFFF
            if not state.chain:
                return [("return", target)]
            if target != state.chain[-1]:
                raise Unsupported("manipulated internal return")
            state.chain = state.chain[:-1]
            return [(target, state)]
        if opcode == 0x4E71:
            return [(ext, state)]
        if opcode & 0xFFF8 == 0x4E50:
            displacement = _signed(self.word(ext), 2)
            self.push(state, state.regs[8 + reg])
            state.regs[8 + reg] = state.regs[SP]
            state.regs[SP] = _add(state.regs[SP], displacement & FULL)
            return [(ext + 2, state)]
        if opcode & 0xFFF8 == 0x4E58:
            state.regs[SP] = state.regs[8 + reg]
            state.regs[8 + reg] = self.pop(state)
            return [(ext, state)]
        if opcode & 0xFF80 == 0x4E80:
            operand, ext = self.ea(state, ext, mode, reg, 4)
            if operand.kind != "mem" or mode in (3, 4):
                raise Unsupported("invalid JSR/JMP")
            target = operand.value
            if not isinstance(target, int):
                raise Unsupported("unknown control target")
            target &= 0xFFFFFF
            if not opcode & 0x40:
                return self.call(state, target, ext)
            if mode == 2:
                # JMP (An) is also how a popped return PC is resumed.
                if state.chain and target == state.chain[-1]:
                    state.chain = state.chain[:-1]
                elif not state.chain:
                    stack = state.regs[SP]
                    if not isinstance(stack, Sym):
                        raise Unsupported("stack pointer lost")
                    if stack.offset > 0:
                        return [("return", target)]
            return [(target, state)]
        if opcode & 0xF1C0 == 0x41C0:
            operand, ext = self.ea(state, ext, mode, reg, 4)
            if operand.kind != "mem":
                raise Unsupported("invalid LEA")
            state.regs[8 + ((opcode >> 9) & 7)] = operand.value
            return [(ext, state)]
        if opcode & 0xFFF8 == 0x4840:
            value = state.regs[reg]
            bits, mask = _bits(None if isinstance(value, Sym) else value)
            state.regs[reg] = _make(((bits << 16) | (bits >> 16)) & FULL,
                                    ((mask << 16) | (mask >> 16)) & FULL)
            self.logic_flags(state, state.regs[reg], 4)
            return [(ext, state)]
        if opcode & 0xFFC0 == 0x4840:
            operand, ext = self.ea(state, ext, mode, reg, 4)
            if operand.kind != "mem":
                raise Unsupported("invalid PEA")
            self.push(state, operand.value)
            return [(ext, state)]
        if opcode & 0xFFB8 == 0x4880:
            source_size, size = (1, 2) if opcode & 0x40 == 0 else (2, 4)
            value = state.regs[reg]
            bits, mask = _bits(None if isinstance(value, Sym) else value)
            sign = _SIGN[source_size]
            extension = _MASK[size] & ~_MASK[source_size]
            if mask & sign:
                bits = bits | extension if bits & sign else bits & ~extension
                mask |= extension
            else:
                mask &= ~extension
            result = _make(bits & _MASK[size], mask & _MASK[size])
            self.set_dreg(state, reg, size, result)
            self.logic_flags(state, result, size)
            return [(ext, state)]
        if opcode & 0xFB80 == 0x4880:
            return self.movem(state, opcode, ext, mode, reg)
        if opcode & 0xF900 == 0x4000 and size is not None:
            operand, ext = self.ea(state, ext, mode, reg, size)
            kind = opcode & 0xFF00
            if kind == 0x4200:
                value = 0
                self.logic_flags(state, value, size)
            elif kind == 0x4400:
                value = self.arith(state, 0, self.get(state, operand, size), size, True)
            elif kind == 0x4600:
                value = _logic("eor", self.get(state, operand, size), _MASK[size], size)
                self.logic_flags(state, value, size)
            else:
                value = None
                state.flags.update(X=None, N=None, Z=None, V=None, C=None)
            self.put(state, operand, size, value)
            return [(ext, state)]
        if opcode & 0xFF00 == 0x4A00 and size is not None:
            operand, ext = self.ea(state, ext, mode, reg, size)
            self.logic_flags(state, self.get(state, operand, size), size)
            return [(ext, state)]
        if opcode & 0xFDC0 == 0x44C0:
            operand, ext = self.ea(state, ext, mode, reg, 2)
            value = _low(self.get(state, operand, 2), 2)
            for bit, name in enumerate("CVZNX"):
                state.flags[name] = None if value is None else (value >> bit) & 1
            return [(ext, state)]
        if opcode & 0xFFC0 == 0x40C0:
            operand, ext = self.ea(state, ext, mode, reg, 2)
            self.put(state, operand, 2, None)
            return [(ext, state)]
        raise Unsupported(f"opcode {opcode:04X}")

    def movem(self, state, opcode, ext, mode, reg):
        size = 4 if opcode & 0x40 else 2
        mask = self.word(ext)
        ext += 2
        to_registers = bool(opcode & 0x400)
        if mode == 4 and not to_registers:
            address = state.regs[8 + reg]
            for index in range(16):
                if mask & (1 << index):
                    address = _add(address, (-size) & FULL)
                    self.write(state, address, size, state.regs[15 - index])
            state.regs[8 + reg] = address
            return [(ext, state)]
        if mode in (0, 1, 4) or (to_registers and mode == 7 and reg == 4) or (
                not to_registers and mode == 3):
            raise Unsupported("invalid MOVEM")
        if mode == 3:
            address = state.regs[8 + reg]
        else:
            operand, ext = self.ea(state, ext, mode, reg, size)
            address = operand.value
        for index in range(16):
            if mask & (1 << index):
                if to_registers:
                    value = self.read(state, address, size)
                    if size == 2:
                        value = None if not isinstance(value, int) else _signed(value, 2) & FULL
                    state.regs[index] = value
                else:
                    self.write(state, address, size, state.regs[index])
                address = _add(address, size)
        if mode == 3:
            state.regs[8 + reg] = address
        return [(ext, state)]

    def immediate(self, state, opcode, ext, mode, reg, size):
        if opcode & 0x100 or opcode & 0xF00 == 0x800:
            if opcode & 0x100:
                if mode == 1:
                    raise Unsupported("MOVEP")
                bit = _low(state.regs[(opcode >> 9) & 7], 1)
            else:
                bit = self.word(ext) & 0xFF
                ext += 2
            operation = (opcode >> 6) & 3
            width = 4 if mode == 0 else 1
            operand, ext = self.ea(state, ext, mode, reg, width)
            value = self.get(state, operand, width)
            if bit is None:
                state.flags["Z"] = None
                if operation:
                    self.put(state, operand, width, None)
                return [(ext, state)]
            selected = 1 << (bit % (8 * width))
            bits, known = _bits(None if isinstance(value, Sym) else value)
            state.flags["Z"] = int(not bits & selected) if known & selected else None
            if operation == 1:
                self.put(state, operand, width, _logic("eor", value, selected, width))
            elif operation == 2:
                self.put(state, operand, width, _logic("and", value, ~selected & FULL, width))
            elif operation == 3:
                self.put(state, operand, width, _logic("or", value, selected, width))
            return [(ext, state)]
        kind = (opcode >> 9) & 7
        if size is None or kind in (4, 7):
            raise Unsupported(f"opcode {opcode:04X}")
        immediate, ext = self.ea(state, ext, 7, 4, size)
        source = immediate.value
        if mode == 7 and reg == 4:
            if kind not in (0, 1, 5) or size == 4:
                raise Unsupported("immediate to status register")
            for bit, name in enumerate("CVZNX"):
                flag = (source >> bit) & 1
                current = state.flags.get(name)
                if kind == 0:
                    state.flags[name] = 1 if flag else current
                elif kind == 1:
                    state.flags[name] = current if flag else 0
                else:
                    state.flags[name] = None if current is None else current ^ flag
            return [(ext, state)]
        operand, ext = self.ea(state, ext, mode, reg, size)
        value = self.get(state, operand, size)
        if kind in (2, 3):
            self.put(state, operand, size, self.arith(state, value, source, size, kind == 2))
        elif kind == 6:
            self.arith(state, value, source, size, True, compare=True)
        else:
            result = _logic({0: "or", 1: "and", 5: "eor"}[kind], value, source, size)
            self.put(state, operand, size, result)
            self.logic_flags(state, result, size)
        return [(ext, state)]

    def shift(self, state, opcode, ext, mode, reg, size):
        if size is None:
            operand, ext = self.ea(state, ext, mode, reg, 2)
            self.put(state, operand, 2, None)
            state.flags.update(X=None, N=None, Z=None, V=None, C=None)
            return [(ext, state)]
        count_field = (opcode >> 9) & 7
        if opcode & 0x20:
            count = _low(state.regs[count_field], 1)
            count = None if count is None else count % 64
        else:
            count = count_field or 8
        kind = (opcode >> 3) & 3
        left = bool(opcode & 0x100)
        current = state.regs[reg]
        if count is None or kind == 2 or isinstance(current, Sym):
            self.set_dreg(state, reg, size, None)
            state.flags.update(X=None, N=None, Z=None, V=None, C=None)
            return [(ext, state)]
        if count == 0:
            self.logic_flags(state, self.get(state, _Operand("d", reg), size), size)
            return [(ext, state)]
        mask, bits = _MASK[size], 8 * size
        value, known = _bits(current)
        value, known = value & mask, known & mask
        if kind == 3:
            rotate = count % bits

            def turn(word):
                if left:
                    return ((word << rotate) | (word >> (bits - rotate))) & mask
                return ((word >> rotate) | (word << (bits - rotate))) & mask
            result, result_known = turn(value), turn(known)
        elif left:
            result = (value << count) & mask if count < bits else 0
            result_known = ((known << count) | ((1 << count) - 1)) & mask if count < bits else mask
        else:
            vacated = mask & ~(mask >> count) if count < bits else mask
            if kind == 0 and known & _SIGN[size]:
                fill = vacated if value & _SIGN[size] else 0
                result = ((value >> count) | fill) & mask if count < bits else fill
                result_known = ((known >> count) | vacated) & mask
            elif kind == 0:
                result = (value >> count) & mask if count < bits else 0
                result_known = (known >> count) & mask if count < bits else 0
            else:
                result = (value >> count) if count < bits else 0
                result_known = ((known >> count) | vacated) & mask
        product = _make(result, result_known)
        self.set_dreg(state, reg, size, product)
        if known == mask:
            # Exact flags only from a completely known operand.
            if kind == 3:
                carry = (result & 1) if left else int(bool(result & _SIGN[size]))
            elif left:
                carry = (value >> (bits - count)) & 1 if count <= bits else 0
            elif kind == 0:
                carry = (_signed(value, size) >> min(count - 1, bits)) & 1
            else:
                carry = (value >> (count - 1)) & 1 if count <= bits else 0
            overflow = 0
            if kind == 0 and left:
                signs = {bool(((value << i) & mask) & _SIGN[size]) for i in range(min(count, bits) + 1)}
                overflow = int(len(signs) > 1)
            state.flags.update(N=int(bool(result & _SIGN[size])), Z=int(result == 0),
                               V=overflow, C=carry)
            if kind != 3:
                state.flags["X"] = carry
        else:
            self.logic_flags(state, product, size)
            state.flags.update(V=None, C=None)
            if kind != 3:
                state.flags["X"] = None
        return [(ext, state)]

    def alu(self, state, opcode, ext, group, mode, reg):
        register = (opcode >> 9) & 7
        opmode = (opcode >> 6) & 7
        if opmode in (3, 7):
            size = 2 if opmode == 3 else 4
            operand, ext = self.ea(state, ext, mode, reg, size)
            value = self.get(state, operand, size)
            if group in (9, 0xD, 0xB):
                if size == 2:
                    low = _low(value, 2)
                    value = None if low is None else _signed(low, 2) & FULL
                current = state.regs[8 + register]
                if group == 0xB:
                    self.arith(state, current, value, 4, True, compare=True)
                else:
                    state.regs[8 + register] = (_add if group == 0xD else _sub)(current, value)
                return [(ext, state)]
            factor, multiplier = _low(value, 2), _low(state.regs[register], 2)
            result = None
            if group == 0xC and opmode == 3 and factor is not None and multiplier is not None:
                result = factor * multiplier
            self.set_dreg(state, register, 4, result)
            self.logic_flags(state, result, 4)
            return [(ext, state)]
        size = (1, 2, 4)[opmode & 3]
        if opmode >= 4 and mode in (0, 1) and group != 0xB:
            if group == 0xC and opmode in (5, 6):
                if opmode == 5 and mode == 0:
                    first, second = register, reg
                elif opmode == 5:
                    first, second = 8 + register, 8 + reg
                elif mode == 1:
                    first, second = register, 8 + reg
                else:
                    raise Unsupported("invalid EXG")
                state.regs[first], state.regs[second] = state.regs[second], state.regs[first]
                for index in (first, second):
                    if index >= 8:
                        state.regs[index] = _full(state.regs[index])
                return [(ext, state)]
            # ABCD/SBCD/ADDX/SUBX: unmodelled multi-precision results.
            if mode == 0:
                self.set_dreg(state, register, size, None)
            else:
                step = 2 if size == 1 and 7 in (reg, register) else size
                state.regs[8 + reg] = _sub(state.regs[8 + reg], step)
                state.regs[8 + register] = _sub(state.regs[8 + register], step)
                self.write(state, state.regs[8 + register], size, None)
            state.flags.update(X=None, N=None, Z=None, V=None, C=None)
            return [(ext, state)]
        if group == 0xB and opmode >= 4 and mode == 1:
            raise Unsupported("CMPM")
        operand, ext = self.ea(state, ext, mode, reg, size)
        destination = _Operand("d", register)
        if group == 0xB and opmode < 4:
            self.arith(state, self.get(state, destination, size),
                       self.get(state, operand, size), size, True, compare=True)
            return [(ext, state)]
        if opmode >= 4:
            source, target = destination, operand
        else:
            source, target = operand, destination
        left, right = self.get(state, target, size), self.get(state, source, size)
        if group in (9, 0xD):
            result = self.arith(state, left, right, size, group == 9)
        else:
            result = _logic({8: "or", 0xC: "and", 0xB: "eor"}[group], left, right, size)
            self.logic_flags(state, result, size)
        self.put(state, target, size, result)
        return [(ext, state)]


def _initial_state(return_value):
    regs = [None] * 16
    regs[SP] = Sym("S", 0)
    state = State(regs, {name: None for name in "XNZVC"}, {}, ())
    _store(state.stack, 0, 4, return_value)
    return state


def _explore(emulator, handler, return_value, limit):
    """Return the set of caller return targets, or None when unproven."""
    pending = deque([(handler, _initial_state(return_value))])
    seen: dict[tuple[int, tuple[int, ...]], State] = {}
    targets = set()
    steps = 0
    while pending:
        pc, state = pending.popleft()
        context = (pc, state.chain)
        previous = seen.get(context)
        if previous is not None:
            joined = previous.join(state)
            if joined.key() == previous.key():
                continue
            state = joined
        seen[context] = state
        steps += 1
        if steps > limit:
            return None
        for successor, following in emulator.step(state.copy(), pc):
            if successor == "return":
                targets.add(following)
            else:
                pending.append((successor, following))
    return targets


def _reads_return_stream(image, handler):
    emulator = _Emulator(image)
    try:
        _explore(emulator, handler, Sym("R", 0), MAX_PROBE_STEPS)
    except Unsupported:
        pass
    return emulator.reads_return_stream


def inline_operand_length(image: MegaDriveImage, handler: int, return_address: int) -> int | None:
    """Bytes consumed after ``return_address`` by ``handler``, if proven."""
    try:
        targets = _explore(_Emulator(image), handler, return_address, MAX_SITE_STEPS)
    except Unsupported:
        return None
    if not targets or len(targets) != 1:
        return None
    size = next(iter(targets)) - return_address
    if size <= 0 or size > MAX_INLINE_BYTES or size & 1:
        return None
    return size


def _call_target(emulator, pc):
    """Direct BSR/JSR target and return address, or None."""
    opcode = emulator.word(pc)
    if opcode & 0xFF00 == 0x6100:
        displacement = _signed(opcode & 0xFF, 1)
        if displacement:
            return (pc + 2 + displacement) & 0xFFFFFF, pc + 2
        return (pc + 2 + _signed(emulator.word(pc + 2), 2)) & 0xFFFFFF, pc + 4
    if opcode & 0xFFC0 == 0x4E80 and (opcode >> 3) & 7 in (5, 7):
        mode, reg = (opcode >> 3) & 7, opcode & 7
        if mode == 5 or reg == 3:
            return None
        operand, following = emulator.ea(_initial_state(None), pc + 2, mode, reg, 4)
        return operand.value & 0xFFFFFF, following
    return None


class InlineOperandProver:
    """Cache ROM-only proofs for one immutable image across decoder passes.

    Both successful lengths and rejected sites depend only on the image,
    handler address and return address. Facts and continuation-walk boundaries
    are deliberately not cached: those change when a decoder pass finds code.
    """

    def __init__(self, image):
        self.image = image
        self.handlers: dict[int, bool] = {}
        self.lengths: dict[tuple[int, int], int | None] = {}

    def consumes(self, handler):
        if handler not in self.handlers:
            self.handlers[handler] = _reads_return_stream(self.image, handler)
        return self.handlers[handler]

    def length(self, handler, following):
        key = handler, following
        if key not in self.lengths:
            self.lengths[key] = (inline_operand_length(self.image, handler, following)
                                 if self.consumes(handler) else None)
        return self.lengths[key]


def _walk_continuation(image, start, known_starts, prover, budget):
    """Follow direct flow from a proven continuation to later call sites.

    The decoder would reach the same instructions from the continuation seed;
    walking them now lets a chain of inline-operand calls resolve in one pass
    instead of one decoder pass per call.
    """
    emulator = _Emulator(image)
    pending, seen, found = [start], set(), []
    while pending and budget[0] > 0:
        pc = pending.pop()
        if pc in seen or pc in known_starts:
            continue
        seen.add(pc)
        budget[0] -= 1
        try:
            call = _call_target(emulator, pc)
            if call is not None:
                handler, following = call
                size = prover.length(handler, following)
                if size is not None:
                    found.append(InlineTrapCall(pc, following, following + size, None, handler, size))
                    pending.append(following + size)
                elif not prover.consumes(handler):
                    pending.append(following)
                # An unproven site of an operand consumer ends this path.
                continue
            successors = emulator.step(_initial_state(None), pc)
        except Unsupported:
            continue
        pending.extend(address for address, _ in successors if address != "return")
    return found


def discover_inline_operand_calls(
    image: MegaDriveImage, facts: dict[int, InstructionFact], *,
    prover: InlineOperandProver | None = None,
) -> tuple[InlineTrapCall, ...]:
    """Calls whose handler provably skips variable-length inline operands."""
    if prover is None:
        prover = InlineOperandProver(image)
    elif prover.image is not image:
        raise ValueError("inline operand prover belongs to a different image")
    calls = []
    for fact in sorted(facts.values(), key=lambda item: item.cpu_address):
        opcode = int.from_bytes(fact.raw[:2], "big")
        if not (opcode & 0xFFC0 == 0x4E80 or opcode & 0xFF00 == 0x6100) or len(fact.flows) != 1:
            continue
        handler, following = fact.flows[0] & 0xFFFFFF, fact.cpu_address + fact.length
        size = prover.length(handler, following)
        if size is not None:
            calls.append(InlineTrapCall(fact.cpu_address, following, following + size, None, handler, size))
    known_starts = {fact.cpu_address for fact in facts.values()}
    budget = [MAX_WALK_INSTRUCTIONS]
    for call in tuple(calls):
        calls.extend(_walk_continuation(image, call.continuation, known_starts, prover, budget))
    calls = list({call.call_address: call for call in calls}.values())
    # A backend fall-through decode can place a false call inside another
    # site's operands; only calls outside every proven operand range remain.
    covered = {address for call in calls for address in range(call.data_address, call.continuation)}
    return tuple(sorted((call for call in calls if call.call_address not in covered),
                        key=lambda call: call.call_address))
