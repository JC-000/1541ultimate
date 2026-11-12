; tick.s -- the per-tick game step (a stand-in: it only mixes the inputs into the PRNG).
;
; Both machines call it once per lockstep tick with the same two input bytes, in the same order,
; so the state stays bit-identical:
;   1. P1's input byte is XORed into the PRNG's low byte, P2's into its high byte (an all-zero
;      result is repaired like rng_mix does: high byte := >RNG_SEED)
;   2. the PRNG advances exactly once (rng_next)
; The two players land in different state bytes on purpose: with both mixed into the same byte
; the XOR is commutative, so a P1/P2 swap between the machines would leave state and digest
; unchanged and go unnoticed. Now any swap with P1 != P2 changes the state.
;
; PRE-TICK POLICY: a session starts from rng_seed and then runs EXACTLY FIVE lead-in ticks,
; -5..-1, each a full core_tick with P1 = P2 = 0, before tick 0, whatever the input delay.
; session.s delivers them for any delay 1..24. Digest-tick buttons (the tick runs with the
; previous tick's buttons) are digest.inc's.
;
; P1/P2 are player numbers, not "my"/"other": the session layer hands out my/other bytes plus
; the local player number (1 or 2), and the caller maps them before calling.
;
; Calling convention: in A = P1 byte, X = P2 byte. Out: A clobbered, X and Y preserved.
; Same rules as rng.s (not re-entrant; never call from NMI/IRQ while the main thread may be
; inside it).

.include "platform.inc"
.include "core_zp.inc"

.import rng_next, RNG_SEED
.export core_tick

.segment "CODE"

.proc core_tick
        eor rng_lo              ; P1 -> low byte
        sta rng_lo
        txa
        eor rng_hi              ; P2 -> high byte
        sta rng_hi
        ora rng_lo
        bne :+
        lda #>RNG_SEED          ; never enter the all-zero fixed point
        sta rng_hi
:       jmp rng_next
.endproc
