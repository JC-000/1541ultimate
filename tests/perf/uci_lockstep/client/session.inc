; session.inc -- public interface of the C64 lockstep session layer (session.s).
;
; One per-frame call, events, tick numbering, lead-in ticks and a digest-tick rule. Underneath it
; speaks the relay's wire protocol (../README.md) over the net ABI (net.inc: the UCI on Ultimate
; hardware).
;
; ---------------------------------------------------------------------------
; How a program uses it
; ---------------------------------------------------------------------------
;   init:   store the relay's IPv4 in net_peer_ip[0..3] and its UDP port (6520) in
;           net_peer_port (little-endian), then  jsr c64n_init
;           (C=1 / C64N_F_NO_NET: no network device; every later c64n_frame returns NONE)
;   frame:  once per video frame, from the main loop (never from an interrupt):
;              lda <this frame's input byte>     ; joystick
;              clc   (sec if the game is still busy with the previous tick: LAG)
;              jsr c64n_frame                    ; -> A = event (C64N_EV_*), also in c64n_event
;           on C64N_EV_START  reset the game state (rng_seed, ...); c64n_player = 1 or 2
;           on C64N_EV_TICK   run one game tick with c64n_my / c64n_oth (tick c64n_tick):
;                             first, if c64n_tick = DIGEST_SNAP_TICK: jsr digest_state /
;                             sta c64n_digest (digest.inc); then the step (core_tick)
;           on C64N_EV_END    the session is over (c64n_end_reason); back in the lobby
;           then, once the frame's game work is done:  jsr c64n_poll
;           (finishes this frame's datagram and starts reading its reply, so the UCI READ has
;           the rest of the frame to be staged; without it c64n_frame still works, one READ
;           later)
;   orders: any time from the main loop:
;             jsr c64n_host                     ; open a room; the code appears in c64n_code
;             fill c64n_arg[0..3] (room code, 4 ASCII letters), jsr c64n_join
;             jsr c64n_leave / c64n_hangup
;
; Ticks: c64n_tick (+ c64n_tick_hi) counts from -5: ticks -5..-1 carry zero buttons and need no
; network; tick t >= 0 carries both players' stream byte t. The input passed at frame f is the
; local player's byte for tick (current tick + c64n_delay). Stream ticks t with
; (t & $FF) = $FF carry c64n_digest instead; at that game tick the two digests are compared
; (mismatch: END DESYNC) and the tick runs with the previous tick's buttons.

.ifndef C64N_INC
C64N_INC = 1

C64N_PORT           = 6520      ; relay UDP port for C64s
C64N_PROTO          = 3
.define C64N_APP "LS64"
C64N_APP_VERSION    = 1

; --- modes (c64n_mode)
C64N_MODE_OFF       = 0         ; no network device
C64N_MODE_LOBBY     = 1
C64N_MODE_SESSION   = 2

; --- c64n_flags
C64N_F_NO_NET       = $01       ; net_init failed (no UCI)
C64N_F_NO_RELAY     = $02       ; no datagram from the relay for 255 frames
C64N_F_IN_ROOM      = $04       ; relay says WAITING: in a room, waiting for the other player

; --- orders (c64n_order); values are the LOBBY OP codes
C64N_ORD_NONE       = 0
C64N_ORD_HOST       = 1
C64N_ORD_JOIN       = 2
C64N_ORD_LEAVE      = 3

; --- lobby STATUS from the relay (c64n_status); $FF = none yet
C64N_ST_IDLE        = 0
C64N_ST_WAITING     = 1
C64N_ST_NOROOM      = 2
C64N_ST_FULL        = 3
C64N_ST_MISMATCH    = 4
C64N_ST_BUSY        = 5
C64N_ST_UNKNOWN     = $FF

; --- events
C64N_EV_NONE        = 0
C64N_EV_TICK        = 1
C64N_EV_STALL       = 2
C64N_EV_START       = 3
C64N_EV_END         = 4
C64N_EV_LAG         = 5

; --- c64n_end_reason
C64N_END_LOST       = 1         ; the relay says the other player is gone
C64N_END_TIMEOUT    = 2         ; 240 consecutive stalled frames
C64N_END_DESYNC     = 3         ; digest mismatch (here, or reported by the other side)
C64N_END_USER       = 4         ; c64n_hangup

; --- BYE reasons on the wire
C64N_BYE_LOST       = 1
C64N_BYE_TIMEOUT    = 2
C64N_BYE_DESYNC     = 3
C64N_BYE_USER       = 4
C64N_BYE_RELAY      = 5

C64N_RING           = 32        ; button rings (power of two)
C64N_MAX_DELAY      = 24
C64N_STALL_LIMIT    = 240
C64N_SEND_PERIOD    = 1         ; frames between session datagrams (60/s)

.ifndef C64N_IMPL
        .import c64n_init, c64n_frame, c64n_host, c64n_join, c64n_leave, c64n_hangup
        .import c64n_mode, c64n_flags, c64n_order, c64n_arg, c64n_event, c64n_status
        .import c64n_code, c64n_end_reason, c64n_peer_reason, c64n_player, c64n_sid
        .import c64n_tick, c64n_tick_hi, c64n_my, c64n_oth, c64n_digest, c64n_delay
        .import c64n_nonce, c64n_fctr, c64n_rtt, c64n_poll
        .import c64n_late_replies, c64n_lost_replies, c64n_late_writes, c64n_skips
.endif

.endif
