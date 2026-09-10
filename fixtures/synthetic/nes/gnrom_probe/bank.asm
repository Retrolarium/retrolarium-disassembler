.setcpu "6502"

.ifndef BANK_ID
    .error "BANK_ID must be defined"
.endif

.segment "CODE"

.proc BankEntry
    sei
    cld
    lda #BANK_ID
    sta $00
    lda #((BANK_ID << 4) | BANK_ID)
    sta $8000
Loop:
    jmp Loop
.endproc

BankPointers:
    .addr BankEntry, BankEntry::Loop, NmiHandler, IrqHandler

BankMarker:
    .byte $47, $4E, $52, $4F, $4D, BANK_ID

.proc NmiHandler
    rti
.endproc

.proc IrqHandler
    rti
.endproc

.segment "VECTORS"
    .addr NmiHandler, BankEntry, IrqHandler
