; digest.inc -- the lockstep state-digest convention.
;
; Every 256th stream tick carries a 1-byte state digest instead of a button byte; the session
; layer (session.s) compares the two digests at that game tick and end the
; session on a mismatch (the tick then runs with the previous tick's buttons).
;
;   stream tick t with (t & $FF) = DIGEST_TICK      carries the digest, not buttons
;   the digest is digest_state (digest.s) of the state at the START of the game
;   tick whose low byte is DIGEST_SNAP_TICK in the same 256-tick block, i.e. after tick
;   DIGEST_SNAP_TICK - 1 ran and before tick DIGEST_SNAP_TICK runs.
;
; The game does it, identically on both machines, when its session layer hands it a tick:
;       lda <tick low byte>
;       cmp #DIGEST_SNAP_TICK
;       bne :+
;       jsr digest_state
;       sta c64n_digest
;   :   ...run the tick (core_tick)
;
; Lead-in ticks -5..-1 (tick.s pre-tick policy) are never digest ticks or snapshots:
; tick -1 has low byte $FF but carries no stream byte, and the session layers skip it.
;
; A session layer reads (stores) my stream tick $FF at game tick $FF - delay, so the snapshot
; must already exist then: delay <= DIGEST_TICK - DIGEST_SNAP_TICK - 1 = DIGEST_MAX_DELAY.
; The relay's delay is capped by session.s.

.ifndef DIGEST_INC
DIGEST_INC = 1

DIGEST_TICK      = $FF
DIGEST_SNAP_TICK = $DF
DIGEST_MAX_DELAY = DIGEST_TICK - DIGEST_SNAP_TICK - 1     ; 31

.endif
