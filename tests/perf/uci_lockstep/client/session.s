; session.s -- C64 lockstep session layer over the relay (wire protocol: ../README.md).
;
; Interface and usage: session.inc. Per tick: lead-in ticks -5..-1, input delay, stalls, digest
; ticks, the 240-frame stall limit; the transport is batched, acknowledged TICKS datagrams.
;
; Per frame (c64n_frame), then c64n_poll from the game after its frame work:
;   1. net_poll A: the READ pushed by last frame's c64n_poll completes: handle the reply
;   2. session: LAG / hangup / store this frame's input for every stream tick up to tick+delay
;   3. queue one datagram if one is due (TICKS every frame; LOBBY; BYE after an end)
;   4. net_poll B: push the WRITE
;   5. session: tick or stall
;   6. (c64n_poll) net_poll C: the WRITE is done; push the READ for its reply
; Every datagram has a SEQ the reply echoes: replies owed = last SEQ sent - newest SEQ seen.
;
; All stream counters are 16-bit and wrap; only differences are compared.

C64N_IMPL = 1
.include "session.inc"
.include "net.inc"

.export c64n_init, c64n_frame, c64n_host, c64n_join, c64n_leave, c64n_hangup
.export c64n_mode, c64n_flags, c64n_order, c64n_arg, c64n_event, c64n_status
.export c64n_code, c64n_end_reason, c64n_peer_reason, c64n_player, c64n_sid
.export c64n_tick, c64n_tick_hi, c64n_my, c64n_oth, c64n_digest, c64n_delay
.export c64n_nonce, c64n_fctr, c64n_rtt
; internals, for tests
.export cs_tick, cs_read, cs_acked, cs_have, cs_neg, cs_silent, my_ring, oth_ring
.export tx_seq, rx_seq, bye_left, lobby_seq, noreply, rx_lag
.export c64n_poll, c64n_late_replies, c64n_lost_replies, c64n_late_writes, c64n_skips

RING_MASK       = C64N_RING - 1
WINDOW          = 6             ; most stream bytes in one TICKS (bounds the frame's UCI cost)
LOBBY_FAST      = 15            ; frames between LOBBY datagrams with an order / in a room
LOBBY_SLOW      = 60            ; ... otherwise
MAX_RX_LAG      = 6             ; frames of round trip the read schedule follows (~100 ms)
BYE_COUNT       = 3
BYE_PERIOD      = 3             ; frames between BYEs

T_LOBBY         = $01
T_TICKS         = $10
T_BYE           = $1F
T_STATE         = $81
T_START         = $82
T_RTICKS        = $90
T_RBYE          = $9F

.segment "BSS"
c64n_mode:      .res 1
c64n_flags:     .res 1
c64n_order:     .res 1
c64n_arg:       .res 4
c64n_event:     .res 1
c64n_status:    .res 1
c64n_code:      .res 4
c64n_end_reason: .res 1
c64n_peer_reason: .res 1
c64n_player:    .res 1
c64n_sid:       .res 1
c64n_tick:      .res 1          ; tick of the last C64N_EV_TICK (low byte; -5 = $FB)
c64n_tick_hi:   .res 1
c64n_my:        .res 1
c64n_oth:       .res 1
c64n_digest:    .res 1          ; game: digest to send for stream tick $FF (digest.inc)
c64n_delay:     .res 1
c64n_nonce:     .res 2
my_ring:        .res C64N_RING
oth_ring:       .res C64N_RING
cs_tick:         .res 2          ; next game tick to run (starts at -5)
cs_read:         .res 2          ; next stream tick of mine to store
cs_acked:        .res 2          ; first of my stream ticks the relay has not confirmed
cs_have:         .res 2          ; first of the other's stream ticks I do not hold
cs_neg:          .res 1          ; 1 while cs_tick is negative
cs_silent:       .res 1          ; consecutive stalled frames
cs_prev_my:      .res 1
cs_prev_oth:     .res 1
in_byte:        .res 1
lag:            .res 1
hangup_req:     .res 1
tx_seq:         .res 1          ; sequence number of the last datagram built
rx_seq:         .res 1          ; newest sequence number a reply has echoed
empty_wait:     .res 1          ; 1: a READ came back empty, waiting to see why
empty_seq:      .res 1          ; ... for the reply with this sequence number
c64n_late_replies: .res 1       ; replies that came after their READ had given up (wraps)
c64n_lost_replies: .res 1       ; replies that never came (wraps)
c64n_late_writes: .res 2        ; frames whose datagram only left in a later frame
c64n_skips:     .res 2          ; frames that sent nothing to drain a reply backlog
skipped:        .res 1          ; the last session frame sent nothing (drain)
end_polls:      .res 1          ; 1 once the game calls c64n_poll
first_poll:     .res 1          ; 1 during the frame's first poll
spin:           .res 1          ; poll_mid's budget
spin_empty:     .res 1          ; ... and the empty-READ count it started with
spin_line:      .res 1          ; ... and the raster line (low byte) it started on
start_rd:       .res 1          ; 1: the frame's first poll asked for a READ (no-wait firmware)
empty_sent:     .res 1          ; sent seq when the empty READ was seen
noreply:        .res 1          ; frames since the last datagram from the relay (capped)
sctr:           .res 1          ; frames since the last session/BYE datagram
lctr:           .res 1          ; frames since the last LOBBY datagram
lobby_seq:      .res 1
order_seq:      .res 1
sent_order:     .res 1
bye_left:       .res 1
bye_reason:     .res 1
last_sid:       .res 1
c64n_fctr:      .res 1          ; frames (c64n_frame calls), wraps
c64n_rtt:       .res 1          ; last LOBBY round trip in frames, 0 = unknown
lobby_at:       .res 1          ; c64n_fctr when the last LOBBY went out
rx_lag:         .res 1          ; replies left in flight before reading (c64n_rtt - 1)
seen_empty:     .res 1          ; net_stats EMPTY (low byte) last looked at
tmp:            .res 2

.segment "CODE"

; ---------------------------------------------------------------------------------------------
; c64n_init -- caller has set net_peer_ip / net_peer_port. Out: C=1 if there is no device.
.proc c64n_init
        ldx #0
        txa
:       sta c64n_mode,x         ; clear every BSS variable above (they are contiguous)
        inx
        cpx #(tmp + 2 - c64n_mode)
        bne :-
        lda #C64N_ST_UNKNOWN
        sta c64n_status
        lda $D012               ; nonce: anything that differs between program runs
        eor $DC04
        sta c64n_nonce
        lda $DC05
        eor $DC06
        sta c64n_nonce+1
        lda #LOBBY_SLOW         ; first LOBBY POLL goes out on the first frame
        sta lctr
        jsr net_init
        bcc :+
        lda #C64N_F_NO_NET
        sta c64n_flags
        sec
        rts
:       jsr net_open
        lda #C64N_MODE_LOBBY
        sta c64n_mode
        clc
        rts
.endproc

.proc c64n_host
        lda #C64N_ORD_HOST
        sta c64n_order
        rts
.endproc
.proc c64n_join                 ; room code in c64n_arg[0..3]
        lda #C64N_ORD_JOIN
        sta c64n_order
        rts
.endproc
.proc c64n_leave
        lda #C64N_ORD_LEAVE
        sta c64n_order
        rts
.endproc
; In a session: end it (BYE to the relay). Otherwise: leave the room.
.proc c64n_hangup
        lda c64n_mode
        cmp #C64N_MODE_SESSION
        bne c64n_leave
        lda #1
        sta hangup_req
        rts
.endproc

; ---------------------------------------------------------------------------------------------
; c64n_frame -- A = this frame's input byte, C = 1 if the game is lagging. Out: A = event.
.proc c64n_frame
        sta in_byte
        lda #0
        rol a
        sta lag
        lda #C64N_EV_NONE
        sta c64n_event
        lda c64n_mode
        bne :+
        rts                     ; A = 0 = C64N_EV_NONE
:       inc c64n_fctr
        lda net_tx_len          ; last frame's datagram never left in its own frame
        beq :+
        INC16 c64n_late_writes
:       lda end_polls           ; 1. the READ pushed at the end of last frame: the reply.
        sta first_poll          ;    (With the game calling c64n_poll, no READ is pushed
        jsr poll                ;    here: it would hold the interface when the WRITE is due.)
        lda #0
        sta first_poll
        jsr take_rx             ;    (a reply finished here: may start or end the session)
        jsr in_session          ; 2. this frame's input
        bne :+
        jsr sess_pre
:       jsr send_due            ; 3. this frame's datagram
        jsr poll_mid            ; 4. push this frame's WRITE (the game then calls c64n_poll
                                ;    once its frame work is done: WRITE done -> READ pushed)
        jsr take_rx
        jsr in_session          ; 5. tick or stall
        bne :+
        jsr sess_decide
:       lda noreply
        cmp #$FF
        beq :+
        inc noreply
        bne :++
:       lda c64n_flags
        ora #C64N_F_NO_RELAY
        sta c64n_flags
:       lda c64n_event
        rts
.endproc

; Z=1 if in a session and nothing (START/END/LAG) happened yet this frame.
.proc in_session
        lda c64n_mode
        cmp #C64N_MODE_SESSION
        bne :+
        lda c64n_event
:       rts
.endproc

; c64n_poll -- extra network step for the end of the game's frame work (optional, but it is
; what gives a UCI READ the rest of the frame to be staged): finishes this frame's WRITE and
; pushes the READ for its reply. Handles no datagram (that happens in c64n_frame). A, X, Y
; clobbered.
.proc c64n_poll
        lda #1
        sta end_polls
        jmp poll
.endproc

; net_poll, telling the backend whether to read: only when a reply is due. Every datagram
; carries a sequence number and every reply echoes it, so the replies owed are exactly
;   sent - rx_seq    (sent = the last seq handed to the device; rx_seq = the newest reply seen)
; and the replies to the last rx_lag datagrams are still in flight (rx_lag = LOBBY round trip
; in frames - 1: 0 on a LAN). So a READ is issued only while owed > rx_lag: it finds its datagram
; queued and does not hold the interface. A reply that is merely late (after its READ came
; back empty) is read later like any other; one that is lost is skipped as soon as a newer
; reply arrives. Both are counted (c64n_late_replies / c64n_lost_replies).
.proc poll
        lda net_stats + NET_STAT_EMPTY  ; an empty READ: remember which reply it waited for
        cmp seen_empty
        beq :+
        sta seen_empty
        lda empty_wait
        bne :+
        lda rx_seq
        clc
        adc #1
        sta empty_seq
        inc empty_wait
        jsr sent
        sta empty_sent
:       ldx #0
        lda first_poll          ; frame start, and the game calls c64n_poll: no READ now, as
        beq :+                  ; it would hold the interface when the WRITE is due -- unless
        lda net_status          ; READs cost nothing (no-wait firmware): then the next poll
        and #NET_ST_FREE_READ   ; finishes it and pushes the WRITE, and a reply that came in
        beq @want               ; after last frame's READ is taken this frame, not the next
:                               ; (start_rd tells send_due a READ is on its way)
        lda empty_wait          ; after an empty READ, read again only once a newer datagram
        beq :+                  ; has gone out (the awaited reply may be lost: another READ
        lda net_status          ; for it alone would just stall again) -- unless empty reads
        and #NET_ST_FREE_READ   ; cost nothing (no-wait firmware): then a reply that is only
        bne :+                  ; late, e.g. a LOBBY answer, is read as soon as it is there.
        lda c64n_mode           ; Only in a session: in the lobby the next datagram is up to
        cmp #C64N_MODE_SESSION  ; LOBBY_FAST frames away, and the late reply would then be read
        bne :+                  ; after a newer LOBBY, losing the RTT measurement (rx_lag 0)
        jsr sent
        cmp empty_sent
        beq @want
:       ldy c64n_mode           ; rx_lag paces the session's one-datagram-a-frame stream. In
        cpy #C64N_MODE_SESSION  ; the lobby (one LOBBY per LOBBY_FAST frames) a reply is read
        bne @any                ; as soon as one is owed, so each LOBBY's round trip is timed
        jsr owed                ; (not just the first one, which may include ARP)
        cmp rx_lag
        beq :+
        bcc :+
@yes:   inx
:
@want:  stx net_rx_want
        jsr net_poll
        php                     ; (C = error, for the caller)
        lda first_poll
        beq @r
        lda #0                  ; start_rd = a READ was wanted and the buffer was free for it
        ldx net_rx_want
        beq :+
        ldx net_rx_len
        bne :+
        lda #1
:       sta start_rd
@r:     plp
        rts
@any:   jsr owed
        bne @yes
        beq @want
.endproc

; The frame's WRITE poll. On firmware whose empty READ is free, in a session, with a reply
; overdue (owed > rx_lag) and nothing received yet: also READ now, waiting a little for each
; free READ, so a reply that landed since the frame-start READ is taken this frame -- as a
; waiting READ would have taken it -- instead of at the end-of-frame READ, a frame later.
; The WRITE still goes first after an empty READ (net_poll). One more empty READ ends it (so
; at most one extra READ a frame, ~1 500 cycles with the WRITE ahead of it); so do MID_LINES
; raster lines (~65 cycles each) and MID_SPINS net_polls, whichever comes first. The line
; budget is what bounds it on hardware: there a look costs ~400 cycles and the interface can
; stay busy for all twelve (pair runs 2026-11-11: up to ~8 000 cycles a frame without it).
; (Low raster byte: across lines 255 -> 256 and 262 -> 0 the difference can only read high,
; which ends the loop early, never late.)
MID_SPINS = 12
MID_LINES = 40
.proc poll_mid
        jsr poll
        lda net_status
        and #NET_ST_FREE_READ
        beq @x
        lda c64n_mode
        cmp #C64N_MODE_SESSION
        bne @x
        lda #MID_SPINS
        sta spin
        lda net_stats + NET_STAT_EMPTY
        sta spin_empty
        lda $D012
        sta spin_line
@l:     lda net_rx_len
        bne @x                  ; the reply is in
        lda $D012
        sec
        sbc spin_line
        cmp #MID_LINES
        bcs @x                  ; out of time: the end-of-frame poll finishes what is in flight
        lda net_stats + NET_STAT_EMPTY
        cmp spin_empty
        bne @x                  ; it is not there yet
        jsr owed
        cmp rx_lag
        beq @wr
        bcc @wr
        lda #1
        bne @p
@wr:    lda net_tx_len          ; nothing overdue: just see the WRITE out
        beq @x
        lda #0
@p:     sta net_rx_want
        jsr net_poll
        ldx #24                 ; ~120 cycles between looks (a free READ: ~870 in all)
:       dex
        bne :-
        dec spin
        bne @l
@x:     rts
.endproc

; A = sequence number of the last datagram handed to the device.
.proc sent
        lda tx_seq
        ldy net_tx_len          ; (the one still in the send buffer has not left yet)
        beq :+
        sec
        sbc #1
:       rts
.endproc

; A = replies owed for datagrams already handed to the device.
.proc owed
        jsr sent
        sec
        sbc rx_seq
        bpl :+
        lda #0                  ; (never negative; treat as none)
:       rts
.endproc

; A = the sequence number a reply echoes.
.proc note_seq
        sta tmp+1
        ldx empty_wait          ; a READ came back empty: late or lost?
        beq @new
        cmp empty_seq
        bne :+
        inc c64n_late_replies   ; the very reply it waited for: it was late
        jmp @clr
:       sec
        sbc empty_seq
        bmi @new                ; older than that: keep waiting
        inc c64n_lost_replies   ; newer: the awaited one never came
@clr:   lda #0
        sta empty_wait
@new:   lda tmp+1
        sec
        sbc rx_seq
        beq @x
        bmi @x                  ; not newer than what we have
        lda tmp+1
        sta rx_seq
@x:     rts
.endproc

; ---------------------------------------------------------------------------------------------
; Session, before the network: LAG, hangup, input.
.proc sess_pre
        lda lag
        beq :+
        lda #C64N_EV_LAG        ; no input, no tick; the network still runs
        sta c64n_event
        rts
:       lda hangup_req
        beq @fill
        lda #C64N_END_USER
        jmp end_session
@fill:  ; while cs_read <= cs_tick + delay and cs_read - cs_acked < RING - 2: store input
        lda cs_tick              ; (stream tick tick+delay is read at game tick tick)
        sec                     ; tmp = cs_tick + delay + 1
        adc c64n_delay
        sta tmp
        lda cs_tick+1
        adc #0
        sta tmp+1
        lda tmp
        sec
        sbc cs_read
        tax
        lda tmp+1
        sbc cs_read+1
        bmi @done               ; target - read < 0
        bne :+                  ; > 255 ahead: impossible, but store
        txa
        beq @done               ; == 0: nothing to read
:       lda cs_read
        sec
        sbc cs_acked
        cmp #C64N_RING - 2      ; (never more than 255 apart)
        bcs @done               ; ring full: wait for the relay's ACK
        jsr store_my
        jmp @fill
@done:  rts
.endproc

; Store in_byte (or the digest, on stream tick $xxFF) as my byte for cs_read; cs_read++.
.proc store_my
        lda in_byte
        ldx cs_read
        cpx #$FF
        bne :+
        lda c64n_digest
:       pha
        txa
        and #RING_MASK
        tax
        pla
        sta my_ring,x
        inc cs_read
        bne :+
        inc cs_read+1
:       rts
.endproc

; Session, after the network: tick or stall.
.proc sess_decide
        ; my byte for this tick read with the full delay?  stall if cs_read - cs_tick <= delay
        lda cs_read
        sec
        sbc cs_tick
        cmp c64n_delay          ; (cs_read - cs_tick is 0..delay+1, always < 256)
        beq @stall
        bcc @stall
        lda cs_have              ; the other's byte for cs_tick here?
        cmp cs_tick
        bne @tick
        lda cs_have+1
        cmp cs_tick+1
        bne @tick
@stall: inc cs_silent
        lda cs_silent
        cmp #C64N_STALL_LIMIT
        bcc :+
        lda #C64N_END_TIMEOUT
        jmp end_session
:       lda #C64N_EV_STALL
        sta c64n_event
        rts

@tick:  lda cs_tick
        sta c64n_tick
        lda cs_tick+1
        sta c64n_tick_hi
        lda cs_neg
        beq @real
        lda #0                  ; ticks -5..-1 carry no buttons
        sta c64n_my
        sta c64n_oth
        beq @deliver
@real:  lda cs_tick
        and #RING_MASK
        tax
        lda my_ring,x
        sta c64n_my
        lda oth_ring,x
        sta c64n_oth
        lda cs_tick
        cmp #$FF
        bne @deliver
        lda c64n_my             ; digest tick: compare, then run with the previous buttons
        cmp c64n_oth
        beq :+
        lda #C64N_END_DESYNC
        jmp end_session
:       lda cs_prev_my
        sta c64n_my
        lda cs_prev_oth
        sta c64n_oth
@deliver:
        lda c64n_my
        sta cs_prev_my
        lda c64n_oth
        sta cs_prev_oth
        inc cs_tick
        bne :+
        inc cs_tick+1
        bne :+
        lda #0                  ; -1 -> 0: real ticks from now on
        sta cs_neg
:       lda #0
        sta cs_silent
        lda #C64N_EV_TICK
        sta c64n_event
        rts
.endproc

; A = player, X = sid, Y = delay (from START).
.proc start_session
        sta c64n_player
        stx c64n_sid
        tya
        beq @one
        cmp #C64N_MAX_DELAY + 1
        bcc :+
        lda #C64N_MAX_DELAY
        bne :+
@one:   lda #1
:       sta c64n_delay
        lda #<-5                ; ticks count from -5
        sta cs_tick
        lda #>-5
        sta cs_tick+1
        lda #0
        sta cs_read
        sta cs_read+1
        sta cs_acked
        sta cs_acked+1
        sta cs_have
        sta cs_have+1
        sta cs_silent
        sta cs_prev_my
        sta cs_prev_oth
        sta hangup_req
        sta c64n_end_reason
        sta c64n_peer_reason
        sta bye_left
        sta c64n_order
        sta sent_order
        ldx #C64N_RING - 1
:       sta my_ring,x
        sta oth_ring,x
        dex
        bpl :-
        lda #1
        sta cs_neg
        lda #C64N_SEND_PERIOD   ; first TICKS on the next frame
        sta sctr
        lda c64n_flags
        and #<~C64N_F_IN_ROOM
        sta c64n_flags
        lda #C64N_MODE_SESSION
        sta c64n_mode
        lda #C64N_EV_START
        sta c64n_event
        rts
.endproc

; A = C64N_END_*. Back to the lobby; a local end sends BYE (3 times).
.proc end_session
        sta c64n_end_reason
        ldx #0                  ; END_LOST: the relay told us, no BYE owed
        cmp #C64N_END_LOST
        beq :+
        ldx #BYE_COUNT
:       stx bye_left
        tax                     ; END_* -> BYE reason (same numbers except LOST)
        stx bye_reason
        lda c64n_sid
        sta last_sid
        lda #C64N_MODE_LOBBY
        sta c64n_mode
        lda #C64N_ST_UNKNOWN
        sta c64n_status
        lda #0
        sta hangup_req
        sta c64n_order
        sta sent_order
        sta sctr
        lda #LOBBY_SLOW - LOBBY_FAST   ; a LOBBY POLL soon after the BYEs
        sta lctr
        lda c64n_flags
        and #<~C64N_F_IN_ROOM
        sta c64n_flags
        lda #C64N_EV_END
        sta c64n_event
        rts
.endproc

; ---------------------------------------------------------------------------------------------
; Queue the datagram that is due, if the backend's send slot is free.
.proc send_due
        inc sctr
        bne :+
        dec sctr                ; saturate at 255
:       lda c64n_mode
        cmp #C64N_MODE_SESSION
        beq @sess
        lda bye_left
        beq lobby_send
        lda sctr
        cmp #BYE_PERIOD
        bcc @no
        lda net_tx_len
        bne @no
        lda #T_BYE
        sta net_tx_buf
        lda last_sid
        sta net_tx_buf+1
        lda bye_reason
        sta net_tx_buf+2
        jsr next_seq
        sta net_tx_buf+3
        dec bye_left
        lda #4
        jmp queue
@sess:  lda sctr
        cmp #C64N_SEND_PERIOD
        bcc @no
        lda net_tx_len
        bne @no
        lda start_rd            ; a READ pushed at frame start is fetching the queued reply
        bne @send               ; now: nothing to drain.
        lda skipped             ; More replies owed than are in flight means one is queued
        bne @send               ; unread (left behind a late reply): send nothing this frame,
        lda empty_wait          ; so the one READ a frame catches up instead of every later
        bne @send               ; reply being read a frame late. Never two frames running
        jsr owed                ; (a reply that is lost, not queued, must not stop the sends
        cmp rx_lag              ; that bring newer replies), and not while a READ has just
        beq @send               ; come back empty. The next TICKS repeats this frame's input
        bcc @send               ; (redundancy window).
        INC16 c64n_skips
        lda #1
        sta skipped
        rts
@send:  lda #0
        sta skipped
        jmp send_ticks
@no:    rts
.endproc

.proc lobby_send
        inc lctr
        bne :+
        dec lctr
:       lda c64n_order
        beq @per
        cmp sent_order
        bne @now                ; a new order: send at once
@per:   ldx #LOBBY_SLOW
        lda c64n_order
        bne @fast
        lda c64n_flags
        and #C64N_F_IN_ROOM
        beq :+
@fast:  ldx #LOBBY_FAST
:       cpx lctr
        beq @now
        bcs @no                 ; lctr < period
@now:   lda net_tx_len
        bne @no
        lda #T_LOBBY
        sta net_tx_buf
        lda #C64N_PROTO
        sta net_tx_buf+1
        ldx #3
:       lda app_id,x
        sta net_tx_buf+2,x
        dex
        bpl :-
        lda #C64N_APP_VERSION
        sta net_tx_buf+6
        lda c64n_nonce
        sta net_tx_buf+7
        lda c64n_nonce+1
        sta net_tx_buf+8
        jsr next_seq
        sta lobby_seq
        sta net_tx_buf+9
        lda c64n_order
        sta net_tx_buf+10
        sta sent_order
        beq :+
        lda lobby_seq
        sta order_seq
:       ldx #3
:       lda #0
        ldy c64n_order
        cpy #C64N_ORD_JOIN
        bne :+
        lda c64n_arg,x
:       sta net_tx_buf+11,x
        dex
        bpl :--
        lda c64n_rtt
        sta net_tx_buf+15
        lda c64n_fctr
        sta lobby_at
        lda #0
        sta lctr
        lda #16
        jmp queue
@no:    rts
.endproc

; A STATE/START answers the last LOBBY sent: its round trip in frames -> c64n_rtt (the relay
; sizes the session's input delay from it).
.proc measure_rtt
        lda net_rx_buf+1
        cmp lobby_seq
        bne @x
        lda c64n_fctr
        sec
        sbc lobby_at
        bne :+
        lda #1
:       sta c64n_rtt
        sec
        sbc #1
        cmp #MAX_RX_LAG + 1
        bcc :+
        lda #MAX_RX_LAG
:       sta rx_lag
@x:     rts
.endproc

.segment "RODATA"
app_id: .byte C64N_APP
.assert * - app_id = 4, error, "APP must be 4 characters"

.segment "CODE"

; TICKS: $10 SID SEQ ACK FIRST N BYTES. ACK = low byte of cs_have, FIRST = low byte of
; cs_acked (the relay unwraps both against the 16-bit counts it keeps), BYTES = my stream from
; cs_acked, at most WINDOW.
.proc send_ticks
        lda #T_TICKS
        sta net_tx_buf
        lda c64n_sid
        sta net_tx_buf+1
        jsr next_seq
        sta net_tx_buf+2
        lda cs_have
        sta net_tx_buf+3
        lda cs_acked
        sta net_tx_buf+4
        sta tmp
        lda cs_read
        sec
        sbc cs_acked            ; unconfirmed bytes (< RING)
        cmp #WINDOW + 1
        bcc :+
        lda #WINDOW
:       sta net_tx_buf+5
        sta tmp+1
        ldy #0
@c:     cpy tmp+1
        beq @d
        lda tmp
        and #RING_MASK
        tax
        lda my_ring,x
        sta net_tx_buf+6,y
        inc tmp
        iny
        bne @c
@d:     tya
        clc
        adc #6
        ; fall through
.endproc
; A = datagram length: hand it to the backend.
.proc queue
        sta net_tx_len
        lda #0
        sta sctr
        rts
.endproc

; A = tx_seq + 1, the sequence number of the datagram being built (every datagram has one).
.proc next_seq
        inc tx_seq
        lda tx_seq
        rts
.endproc

; ---------------------------------------------------------------------------------------------
; Handle the received datagram, if any.
.proc take_rx
        lda net_rx_len
        bne :+
        rts
:       ldx #1                  ; where the echoed SEQ is: STATE/START +1, TICKS +2, BYE +3
        lda net_rx_buf
        cmp #T_RTICKS
        bne :+
        inx
:       cmp #T_RBYE
        bne :+
        ldx #3
:       cpx net_rx_len
        bcs :+
        lda net_rx_buf,x
        jsr note_seq
:       lda #0
        sta noreply
        lda c64n_flags
        and #<~C64N_F_NO_RELAY
        sta c64n_flags
        lda net_rx_buf
        ldx c64n_mode
        cpx #C64N_MODE_SESSION
        beq @sess
        cmp #T_STATE
        bne :+
        jsr rx_state
        jmp @done
:       cmp #T_START
        bne :+
        jsr rx_start
        jmp @done
:       cmp #T_RBYE
        bne @done
        lda #0                  ; the relay has our BYE
        sta bye_left
        beq @done
@sess:  cmp #T_RTICKS
        bne :+
        jsr rx_ticks
        jmp @done
:       cmp #T_RBYE
        bne @done
        jsr rx_bye
@done:  lda #0
        sta net_rx_len
        rts
.endproc

; $81 SEQ STATUS CODE[4]
.proc rx_state
        lda net_rx_len
        cmp #7
        bcs :+
        rts
:        lda net_rx_buf+2
        sta c64n_status
        ldx #3
:       lda net_rx_buf+3,x
        sta c64n_code,x
        dex
        bpl :-
        lda c64n_flags
        and #<~C64N_F_IN_ROOM
        ldx c64n_status
        cpx #C64N_ST_WAITING
        bne :+
        ora #C64N_F_IN_ROOM
:       sta c64n_flags
        jsr measure_rtt
        ; fall through
.endproc
; The reply to the LOBBY that carried the current order answers it (unless main replaced it).
.proc order_answered
        lda net_rx_buf+1
        cmp order_seq
        bne @x
        lda sent_order
        beq @x
        cmp c64n_order
        bne @x
        lda #C64N_ORD_NONE
        sta c64n_order
        sta sent_order
@x:     rts
.endproc

; $82 SEQ SID PLAYER DELAY START_TICK(2)
.proc rx_start
        lda net_rx_len
        cmp #7
        bcc @x
        lda net_rx_buf+5        ; START_TICK must be 0 in v1
        ora net_rx_buf+6
        bne @x
        ldx net_rx_buf+2
        beq @x                  ; SID 0 is not a session
        cpx last_sid
        beq @x                  ; the session we just ended: a stale START
        lda net_rx_buf+3
        cmp #1
        beq :+
        cmp #2
        bne @x
:       jsr measure_rtt
        jsr order_answered
        ldx net_rx_buf+2
        ldy net_rx_buf+4
        lda net_rx_buf+3
        jmp start_session
@x:     rts
.endproc

; $9F SID REASON
.proc rx_bye
        lda net_rx_len
        cmp #3
        bcc @x
        lda net_rx_buf+1
        cmp c64n_sid
        bne @x
        lda net_rx_buf+2
        sta tmp
        ldx #C64N_END_LOST
        cmp #C64N_BYE_DESYNC
        bne :+
        ldx #C64N_END_DESYNC
:       txa
        jsr end_session
        lda #0                  ; the relay closed it: no BYE owed (also not for DESYNC)
        sta bye_left
        lda tmp
        sta c64n_peer_reason
@x:     rts
.endproc

; $90 SID SEQ ACK FIRST N BYTES[N] (ACK, FIRST: low bytes; the windows are < 128 apart)
.proc rx_ticks
        lda net_rx_len
        cmp #6
        bcc @x
        lda net_rx_buf+1
        cmp c64n_sid
        bne @x
        lda net_rx_buf+5        ; N, and the datagram must hold all N bytes
        cmp #WINDOW + 1
        bcs @x
        adc #6
        cmp net_rx_len
        beq :+
        bcs @x
:       ; ACK: d = ACK - cs_acked (8 bits); adopt if 0 < d <= cs_read - cs_acked
        lda cs_read
        sec
        sbc cs_acked
        sta tmp                 ; unconfirmed (< RING)
        lda net_rx_buf+3
        sec
        sbc cs_acked
        beq @bytes              ; nothing new
        cmp tmp
        beq :+
        bcs @bytes              ; behind (stale) or beyond what I sent
:       clc
        adc cs_acked
        sta cs_acked
        bcc @bytes
        inc cs_acked+1
@bytes: ; k = cs_have - FIRST (8 bits) must be 0..N-1: the first byte I do not have
        lda cs_have
        sec
        sbc net_rx_buf+4
        tay
@k:     cpy net_rx_buf+5
        bcs @x                  ; nothing new (or a gap: k "negative")
        lda cs_have             ; ring room: cs_have - cs_tick < RING - 1
        sec
        sbc cs_tick
        cmp #C64N_RING - 1
        bcs @x
        lda cs_have
        and #RING_MASK
        tax
        lda net_rx_buf+6,y
        sta oth_ring,x
        inc cs_have
        bne :+
        inc cs_have+1
:       iny
        bne @k
@x:     rts
.endproc
