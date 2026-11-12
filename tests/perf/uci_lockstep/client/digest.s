; digest.s -- 1-byte digest of the game state (lockstep desync check).
;
; The digest covers exactly the live state: CORE_ZP .. CORE_ZP + CORE_ZP_USED - 1, then
; CORE_RAM .. CORE_RAM + CORE_RAM_USED - 1 (core_zp.inc). Bytes beyond the *_USED marks are
; never read.
;
; Function: CRC-8, polynomial $07, init $00, no reflection, no final XOR (CRC-8/SMBUS; check
; value of "123456789" is $F4), byte-wise table. Every single-bit and every burst error up to 8
; bits changes it; anything else is missed with probability 1/256 per check.
; When it is taken and how it travels: digest.inc.
;
; Calling convention:
;   - JSR from any context, including an NMI/IRQ handler: it writes no memory, so it can
;     interrupt anything (it reads state the main thread may be changing, so take the snapshot
;     only between ticks, as digest.inc says)
;   - out: A = digest; X, Y, N/Z/C clobbered; D must be clear (it is never used)
;   - cost: 17 cycles per byte (+1 per byte if crc8_tab straddles a page) + ~20
;
; Test hooks: DIGEST_ZP_LEN / DIGEST_RAM_LEN override the lengths.

.include "platform.inc"
.include "core_zp.inc"

.export digest_state, crc8_tab

.ifndef DIGEST_ZP_LEN
DIGEST_ZP_LEN  = CORE_ZP_USED
.endif
.ifndef DIGEST_RAM_LEN
DIGEST_RAM_LEN = CORE_RAM_USED
.endif

.if DIGEST_ZP_LEN > CORE_ZP_SIZE || DIGEST_RAM_LEN > CORE_RAM_SIZE
        .error "digest covers more than the state owns"
.endif

DIGEST_POLY = $07
DIGEST_INIT = $00

.segment "CODE"

.proc digest_state
        lda #DIGEST_INIT
.if ::DIGEST_ZP_LEN > 0
        ldx #0
@zp:    eor CORE_ZP,x           ; zero page,X
        tay
        lda crc8_tab,y
        inx
  .if ::DIGEST_ZP_LEN < 256
        cpx #DIGEST_ZP_LEN
  .endif
        bne @zp
.endif
.if ::DIGEST_RAM_LEN > 0
  .repeat (::DIGEST_RAM_LEN + 255) / 256, P
        ldx #0
:       eor CORE_RAM + P * 256,x
        tay
        lda crc8_tab,y
        inx
    .if ::DIGEST_RAM_LEN - P * 256 < 256
        cpx #<(DIGEST_RAM_LEN - P * 256)
    .endif
        bne :-
  .endrepeat
.endif
        rts
.endproc

.segment "RODATA"

; crc8_tab[i] = CRC-8 of the single byte i (MSB first, poly $07), built at assembly time.
crc8_tab:
.repeat 256, I
  crc8v .set I
  .repeat 8
    .if crc8v & $80
      crc8v .set ((crc8v << 1) ^ DIGEST_POLY) & $FF
    .else
      crc8v .set (crc8v << 1) & $FF
    .endif
  .endrepeat
        .byte crc8v
.endrepeat
