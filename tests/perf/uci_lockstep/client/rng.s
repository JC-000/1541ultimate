; rng.s -- deterministic PRNG (16-bit xorshift, shifts 7/9/8), the stand-in game state.
;
; Determinism rules:
;   - no hardware reads, no SED/BCD, no dependence on the D flag
;   - state starts from the constant RNG_SEED, never from power-on RAM
;   - the full state is two zero-page bytes; nothing else is read
;
; Generator: x ^= x << 7; x ^= x >> 9; x ^= x << 8   (16-bit, mod 2^16)
; Period 65535 over all non-zero states; state 0 is a fixed point and is
; never entered (rng_seed sets a non-zero state, rng_mix repairs a zero).
;
; Calling convention (all three routines):
;   - JSR from any context; not re-entrant (don't call from NMI/IRQ while
;     the main thread may be inside one of them)
;   - X and Y are preserved; A and N/Z/C/V are clobbered
;   - D is neither read nor written; I is untouched
;   - stack use: the 2-byte return address only
;
; Zero page: rng_lo, rng_hi (see core_zp.inc). RAM: none.

.include "platform.inc"
.include "core_zp.inc"

.exportzp rng_lo, rng_hi
.export rng_seed, rng_next, rng_mix
.export RNG_SEED

RNG_SEED = $6502        ; fixed initial state, identical on every machine

.segment "CODE"

; rng_seed -- set the state to RNG_SEED.
;   in: -   out: A = <RNG_SEED
.proc rng_seed
        lda #>RNG_SEED
        sta rng_hi
        lda #<RNG_SEED
        sta rng_lo
        rts
.endproc

; rng_next -- advance the state one step.
;   in: -   out: A = new rng_hi (the byte callers should consume);
;   the full new state is rng_hi:rng_lo.  30 cycles body, 42 incl. JSR/RTS.
.proc rng_next
        ; x ^= x << 7 (high byte): hi ^= (hi << 7) | (lo >> 1)
        lda rng_hi
        lsr a                   ; C = hi bit 0
        lda rng_lo
        ror a                   ; A = (hi0 << 7) | (lo >> 1), C = lo bit 0
        eor rng_hi
        sta rng_hi              ; hi' = hi after step 1
        ; low byte, steps 1 and 2 together:
        ;   lo' = lo ^ (lo0 << 7) ^ (hi' >> 1) = lo ^ ror(hi', C=lo0)
        ror a
        eor rng_lo
        sta rng_lo
        ; x ^= x << 8: hi ^= lo
        eor rng_hi
        sta rng_hi
        rts
.endproc

; rng_mix -- fold one input byte into the state (lo ^= A).
;   in: A = byte to mix (e.g. a player's input byte for this tick)
;   out: A clobbered.  If the result would be the all-zero state (a fixed
;   point of the generator) rng_hi is set to >RNG_SEED instead.
.proc rng_mix
        eor rng_lo
        sta rng_lo
        ora rng_hi
        bne done
        lda #>RNG_SEED
        sta rng_hi
done:
        rts
.endproc
