# Changelog

## Unreleased

- Validate JDK availability before downloads; run Ghidra without interactive
  stdin and report actionable installation errors.
- Ship verified MIT processor-language source bundles without upstream ROMs,
  loaders or build wrappers. Bound downloads by their pinned sizes.
- Find Core in renamed source archives, explain missing dependencies, and pin
  Core's Git source. Clarify installation, verification and Docker requirements.
- Include fixture-maintenance regressions in normal CI. Keep launcher cleanup
  and Python tests portable across Windows and Linux.
- Improve abstract arithmetic soundness, 68000 range alignment, Z80 output and
  conservative SNES control-flow handling; guard generated output directories.

## 0.5.0

Tagged baseline:
[v0.5.0](https://github.com/Retrolarium/retrolarium-disassembler/tree/v0.5.0).
