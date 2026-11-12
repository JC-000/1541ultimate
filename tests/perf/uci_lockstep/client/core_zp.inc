; core_zp.inc -- zero-page layout of the stand-in game state.
;
; Every state variable is an offset from CORE_ZP (zero page) or CORE_RAM
; (absolute RAM), both supplied by platform.inc.

.ifndef CORE_ZP
        .error "platform.inc must define CORE_ZP"
.endif
.ifndef CORE_RAM
        .error "platform.inc must define CORE_RAM"
.endif

; --- zero page (CORE_ZP .. CORE_ZP+CORE_ZP_SIZE-1) ---
rng_lo          = CORE_ZP + $00     ; PRNG state, low byte
rng_hi          = CORE_ZP + $01     ; PRNG state, high byte
CORE_ZP_USED    = $02               ; bump as variables are added

.if CORE_ZP_USED > CORE_ZP_SIZE
        .error "core zero page overflows CORE_ZP_SIZE"
.endif
.if CORE_ZP + CORE_ZP_SIZE > $100
        .error "CORE_ZP region runs past $FF"
.endif

; --- RAM (CORE_RAM .. CORE_RAM+CORE_RAM_SIZE-1) ---
CORE_RAM_USED   = $00               ; nothing yet
