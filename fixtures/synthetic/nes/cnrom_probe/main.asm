.setcpu "6502"

.segment "CODE"

.proc Reset
    sei
    cld
    ldx #$FF
    txs
    lda #$03
    sta $8000
    lda #$00
    sta $8000
Loop:
    jmp Loop
.endproc

ProbePointers:
    .addr Reset, Reset::Loop, NmiHandler, IrqHandler

ProbeData:
    .byte $43, $4E, $52, $4F, $4D

.proc NmiHandler
    rti
.endproc

.proc IrqHandler
    rti
.endproc

.segment "VECTORS"
    .addr NmiHandler, Reset, IrqHandler
