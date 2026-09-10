; Retrolarium project-owned W65C816 mapping and state-analysis probe.

.setcpu "65816"

.export Reset, NativeNmi, NativeIrq, NearSub, FarSub, LocalTarget
.export Pointer16, Pointer24, PointerSplit, RelativePointers

.segment "CODE"

.a8
.i8
Reset:
    sei
    clc
    xce
    rep     #$30
.a16
.i16
    lda     #$1234
    ldx     #$5678
    sep     #$20
.a8
    lda     #$12
    jsr     NearSub
    jsl     FarSub
    bra     LocalTarget

NearSub:
    rep     #$20
.a16
    lda     #$9ABC
    sep     #$20
.a8
    rts

FarSub:
    rtl

LocalTarget:
    wai
    bra     LocalTarget

NativeNmi:
    rti

NativeIrq:
    rti

; Known current-bank, far, split and signed table material.
Pointer16:
    .word   Reset, NearSub, LocalTarget, NativeNmi

Pointer24:
    .faraddr Reset, FarSub, NativeNmi

PointerSplit:
    .lobytes Reset, NearSub, LocalTarget, NativeNmi
    .hibytes Reset, NearSub, LocalTarget, NativeNmi
    .bankbytes Reset, NearSub, LocalTarget, NativeNmi

RelativePointers:
    .word   (Reset-RelativePointers) & $FFFF
    .word   (NearSub-RelativePointers) & $FFFF
    .word   (LocalTarget-RelativePointers) & $FFFF
    .word   (NativeNmi-RelativePointers) & $FFFF
