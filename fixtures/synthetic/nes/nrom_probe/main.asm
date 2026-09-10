.setcpu "6502"

.segment "CODE"

.proc Reset
    sei
    cld
    ldx #$FF
    txs
    jsr NmiHandler
    lda ProbePointers
    bne Loop
Loop:
    jmp Loop
.endproc

ProbePointers:
    .addr Reset, Reset::Loop, NmiHandler, IrqHandler
    .word $0000

; These mapped-looking words are intentionally decreasing and unreferenced.
RejectedLookalike:
    .addr IrqHandler, NmiHandler, Reset::Loop, Reset

ProbeData:
    .byte $4E, $52, $4F, $4D

.proc NmiHandler
    jmp Reset
.endproc

.proc IrqHandler
    rti
.endproc

.segment "VECTORS"
    .addr NmiHandler, Reset, IrqHandler
