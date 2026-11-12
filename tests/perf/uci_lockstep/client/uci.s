; uci.s -- UCI (Ultimate Command Interface) backend of the C64 net ABI (net.inc).
;
; One connected UDP socket over the Ultimate's network target ($DF1B-$DF1F): Ultimate 64 (Elite),
; C64 Ultimate, 1541 Ultimate. Without the interface net_init reports NODEV.
;
; Derived from c64-wireguard src/net/uci/ (net.s, uci_cmd.s, uci_regs.inc; MIT License,
; Copyright (c) 2026 JC-000), which is hardware-proven on the U64E: the register map, the command
; layouts ($08 UDP_CONNECT with the host as an ASCII dotted quad + NUL, $11 SOCKET_WRITE,
; $10 SOCKET_READ with a 2-byte length header, $09 SOCKET_CLOSE), the $C9 probe, the $FFFF
; "no data" read header, the phantom-socket guard (no id / id 0 = failed open), the "00,..."
; status-line check on an open, settled (two agreeing) STATUS reads, and the fence after every
; register access. What is new here is the shape: the WireGuard driver waits (TOD-bounded) for
; every command, which would freeze a 60 Hz game for the ~40 ms an empty READ holds the
; interface. This one never waits: net_poll pushes a command and returns, and later calls
; complete it once STATE leaves Busy (bounded in frames, i.e. wall clock at any CPU speed).
; Datagrams here are <= 64 bytes, far below one 893-byte reply block, so the multi-block
; (Data More) machinery is not needed; a reply that claims more than 255 bytes is dropped.
;
; Fence: UCI_FENCE_ITERS sizes it for a 1 MHz C64 (the game runs at stock speed): 76 cycles,
; so consecutive register accesses land >= 83 cycles (~81 us) apart,
; 29 % over the 62.9 us floor c64-wireguard bracketed on a C64 Ultimate (its 85 us choice is
; ~5 450 cycles of 48/64 MHz CPU). Running this build at turbo speed needs a longer fence.
; UNMEASURED on hardware at 1 MHz with this spacing.
;
; Per call (measured in a 6502 simulator): a status check ~200 cycles; pushing a WRITE or
; reading a reply ~95 cycles per byte; never a wait. Per session frame (three calls, c64n_frame +
; c64n_poll) median ~5 200, max ~5 500 simulated; 5 400-6 100 max measured on an Ultimate 64
; Elite and a C64 Ultimate (CIA) with a READ that waits.

NET_IMPL = 1
.include "net.inc"

.export net_init, net_open, net_poll, net_close
.export net_tx_buf, net_tx_len, net_rx_buf, net_rx_len, net_rx_want
.export net_peer_ip, net_peer_port, net_status, net_err
.export uci_state, uci_sock, net_stats, uci_hist_lo, uci_hist_hi
; primitives, for the timing probe (c64/uciprobe/main.s)
.export uci_fence, uci_put := put, uci_ctrl := ctrl, uci_read_status := read_status
.export uci_get_byte := get_byte, uci_finish := finish
.export uci_stat_code := stat_code, uci_fence_iters := UCI_FENCE_ITERS
.if .defined(UCI_TRACE)
.export uci_trace_i, uci_trace_on, uci_trace_ev, uci_trace_fr, uci_trace_lo, uci_trace_hi
.importzp frame                 ; the program's raster-IRQ frame counter (netdemo: line 251)
.endif

; --- registers (c64-wireguard uci_regs.inc) --------------------------------------------------
UCI_STATUS        = $DF1C       ; r: status
UCI_CONTROL       = $DF1C       ; w: control
UCI_CMD_DATA      = $DF1D       ; w: command FIFO
UCI_ID            = $DF1D       ; r: $C9 when present ($49 while the UCI IRQ is active)
UCI_RESP_DATA     = $DF1E       ; r: response FIFO (each read pops)
UCI_STATUS_DATA   = $DF1F       ; r: status-text FIFO (each read pops)

UCI_STAT_DATA_AV  = $80
UCI_STAT_STAT_AV  = $40
UCI_STAT_STATE    = $30         ; 00 idle, 10 busy, 20 data last, 30 data more
UCI_STAT_ERROR    = $08
UCI_STAT_CMD_BUSY = $01
UCI_STATE_BUSY    = $10

UCI_CTRL_PUSH_CMD = $01
UCI_CTRL_NEXT_DATA= $02         ; accept the reply (data last -> idle)
UCI_CTRL_ABORT    = $04
UCI_CTRL_CLR_ERR  = $08

UCI_TARGET_NETWORK  = $03
UCI_CMD_UDP_CONNECT = $08
UCI_CMD_SOCKET_CLOSE= $09
UCI_CMD_SOCKET_READ = $10
UCI_CMD_SOCKET_WRITE= $11

UCI_READ_MAX      = 255         ; fw 3.14d returns nothing above this

; -D UCI_READ_NOWAIT=1: every SOCKET_READ carries a 6th byte $00, "do not wait" (the opt-in form
; proposed in #962). Only for firmware that has it: on others the
; 6-byte READ is refused (status 81) and every READ is a net error.
UCI_HIST_N        = 16          ; READ-hold histogram buckets (busy polls, last one = 15+)

; -D UCI_TRACE=1 (measurement builds only): a 256-entry ring of interface events, each with the
; program's IRQ frame counter and the raster line, so a host tool can time every command on
; hardware to one raster line (63.6 us NTSC). Event byte: low nibble TR_*, high nibble the polls
; the command was busy (waitc, 15 = 15+). Logging stops while uci_trace_on is 0.
TR_PUSH_WRITE     = 1
TR_PUSH_READ      = 2
TR_READ_DATA      = 3
TR_READ_EMPTY     = 4
TR_WRITE_DONE     = 5

UCI_FENCE_ITERS   = 8           ; 20 + 7 * 8 = 76 cycles per fence (JSR/RTS included); with the
                                ; access itself and loop code, accesses land >= 85 cycles apart

; --- driver states (uci_state) ---------------------------------------------------------------
UST_OFF     = 0                 ; no interface
UST_CLOSED  = 1                 ; interface present, no socket
UST_IDLE    = 2                 ; socket open, nothing in flight
UST_CONNECT = 3                 ; commands in flight from here on
UST_WRITE   = 4
UST_READ    = 5
UST_CLOSE   = 6

WAIT_LIMIT  = 240               ; polls (2 per frame) a command or a busy interface may take: 2 s
RETRY_WAIT  = 180               ; polls (3 per frame with c64n_poll) between refused opens: 1 s

.segment "BSS"
net_tx_buf:     .res NET_TX_MAX
net_tx_len:     .res 1
net_rx_buf:     .res NET_RX_MAX
net_rx_len:     .res 1
net_rx_want:    .res 1
net_peer_ip:    .res 4
net_peer_port:  .res 2          ; little-endian
net_status:     .res 1
net_err:        .res 1
net_stats:      .res NET_STATS_SIZE
; How long each READ held the interface, counted in net_poll calls that found it still busy
; (the session calls net_poll 3 times a frame: two at the frame start, one after the frame's
; work). Buckets 0..15 (15 = 15 or more): data READs at uci_hist_*+0, empty READs at +16.
; 16-bit counts, split into low and high bytes. Diagnostics, read by ../run_pair.py.
uci_hist_lo:    .res 2 * UCI_HIST_N
uci_hist_hi:    .res 2 * UCI_HIST_N
.if .defined(UCI_TRACE)
.segment "DATA"
uci_trace_on:   .byte 1
.segment "BSS"
uci_trace_i:    .res 1          ; next entry
uci_trace_ev:   .res 256
uci_trace_fr:   .res 256
uci_trace_lo:   .res 256        ; $D012
uci_trace_hi:   .res 256        ; $D011 (bit 7 = raster bit 8)
.endif
uci_state:      .res 1
uci_sock:       .res 1
last_empty:     .res 1          ; the last READ came back empty
idle_known:     .res 1          ; a reply was just accepted: the interface is idle
open_req:       .res 1
waitc:          .res 1
retry:          .res 1
cmd_err:        .res 1
prev:           .res 1
stat_code:      .res 2          ; first two characters of the status line
stat_n:         .res 1
rlen:           .res 1
rcnt:           .res 1
dtmp:           .res 1
ddiv:           .res 1
dlead:          .res 1

.segment "CODE"

; 76-cycle delay after every UCI register access. Preserves A, X, Y; clobbers N/Z/C.
.proc uci_fence
        pha
        lda #UCI_FENCE_ITERS
:       sec
        sbc #1
        bne :-
        pla
        rts
.endproc

; A -> command FIFO. Preserves A, X, Y.
.proc put
        sta UCI_CMD_DATA
        jmp uci_fence
.endproc

; Settled STATUS: read until two consecutive fenced reads agree (the register is unlatched
; and tears on state edges). Out: A = status. Clobbers X.
.proc read_status
        ldx #8
        lda UCI_STATUS
        jsr uci_fence
@l:     sta prev
        lda UCI_STATUS
        jsr uci_fence
        cmp prev
        beq @d
        dex
        bne @l
@d:     rts
.endproc

.proc ctrl                      ; A -> control register
        sta UCI_CONTROL
        jmp uci_fence
.endproc

; One response byte if DATA_AV. Out: C=0, A = byte; C=1 none. Preserves X, Y.
.proc get_byte
        lda UCI_STATUS
        jsr uci_fence
        and #UCI_STAT_DATA_AV
        beq @none
        lda UCI_RESP_DATA
        jsr uci_fence
        clc
        rts
@none:  sec
        rts
.endproc

; Drain the response FIFO, then the status line (first two characters into stat_code), then
; accept the reply. Bounded: 255 bytes each.
.proc finish
        ldy #0
@r:     jsr get_byte
        bcs @s0
        dey
        bne @r
@s0:    ldy #0
        sty stat_n
@s:     lda UCI_STATUS
        jsr uci_fence
        and #UCI_STAT_STAT_AV
        beq @ack
        lda UCI_STATUS_DATA
        jsr uci_fence
        ldx stat_n
        cpx #2
        bcs :+
        sta stat_code,x
        inc stat_n
:       dey
        bne @s
@ack:   lda #UCI_CTRL_NEXT_DATA
        jmp ctrl
.endproc

; Accept a WRITE/READ reply. Default: accept at once; the accept (NEXT_DATA = DATA_ACC on a
; "data last" block) returns the interface to idle and discards what is left of the reply
; (command_protocol.vhd as read by c64-uci-p2p's model) -- here the WRITE's 2-byte count and
; the "00,OK" status line, which we do not need. That saves ~25 register accesses (~2 700
; cycles) per frame. -D UCI_DRAIN=1 builds the c64-wireguard behaviour
; (drain response and status, then accept).
.proc done_reply
.if .defined(UCI_DRAIN)
        jmp finish
.else
        lda #UCI_CTRL_NEXT_DATA
        jsr ctrl
        lda #1
        sta idle_known
        rts
.endif
.endproc

; An empty READ that took under 3 polls means the firmware does not wait: NET_ST_FREE_READ.
; One that took 5+ (W firmware: ~37 ms, >= 6 polls) means it does. 3-4: keep (session.s
; poll_mid looks every ~300 cycles while a free READ is staged). Clobbers A, X.
.proc free_read
        lda net_status
        ldx waitc
        cpx #3
        bcs :+
        ora #NET_ST_FREE_READ
        bne @x
:       cpx #5
        bcc @x
        and #<~NET_ST_FREE_READ
@x:     sta net_status
        rts
.endproc

; Count one finished READ in the hold histogram. X = 0 (data) or UCI_HIST_N (empty).
; waitc = the polls that found it busy. Clobbers A, X.
.proc hist                      ; X = 0: a READ with data, UCI_HIST_N: an empty READ
.if .defined(UCI_TRACE)
        lda #TR_READ_DATA
        cpx #0
        beq :+
        lda #TR_READ_EMPTY
:       jsr trace
.endif
        lda waitc
        cmp #UCI_HIST_N - 1
        bcc :+
        lda #UCI_HIST_N - 1
:       stx dtmp
        clc
        adc dtmp
        tax
        inc uci_hist_lo,x
        bne :+
        inc uci_hist_hi,x
:       rts
.endproc

.proc set_err                   ; A = NET_ERR_*
        sta net_err
        INC16 net_stats + NET_STAT_ERRORS
        lda net_status
        ora #NET_ST_ERROR
        sta net_status
        rts
.endproc

.proc abort
        lda #0
        sta idle_known
        lda #UCI_CTRL_ABORT
        jsr ctrl
        lda #0
        sta waitc
        lda #NET_ERR_WEDGE
        jmp set_err
.endproc

; ---------------------------------------------------------------------------------------------
.if .defined(UCI_TRACE)
; A = TR_* event. Keeps X and Y.
.proc trace
        pha
        lda uci_trace_on
        bne :+
        pla
        rts
:       txa
        pha
        ldx uci_trace_i
        php
        sei                     ; frame and raster from the same moment
        lda VIC_RASTER_LO
        sta uci_trace_lo,x
        lda VIC_RASTER_HI
        sta uci_trace_hi,x
        lda VIC_RASTER_LO
        cmp uci_trace_lo,x
        bcs :+
        sta uci_trace_lo,x      ; line 255 -> 256 between the reads: take the new pair
        lda VIC_RASTER_HI
        sta uci_trace_hi,x
:       lda frame
        sta uci_trace_fr,x
        plp
        lda waitc
        cmp #15
        bcc :+
        lda #15
:       asl a
        asl a
        asl a
        asl a
        sta dtmp
        pla                     ; X
        tay
        pla                     ; the event
        pha
        ora dtmp
        sta uci_trace_ev,x
        inc uci_trace_i
        tya
        tax
        pla
        rts
.endproc
VIC_RASTER_LO = $D012
VIC_RASTER_HI = $D011

.macro TRACE ev
        lda #ev
        jsr trace
.endmacro
.else
.macro TRACE ev
.endmacro
.endif

.proc net_init
        lda #0
        sta net_status
        sta net_err
        sta uci_state
        sta uci_sock
        sta open_req
        sta waitc
        sta retry
        sta last_empty
        sta idle_known
        sta net_tx_len
        sta net_rx_len
        sta net_rx_want
        ldx #NET_STATS_SIZE - 1
:       sta net_stats,x
        dex
        bpl :-
        ldx #2 * UCI_HIST_N - 1
:       sta uci_hist_lo,x
        sta uci_hist_hi,x
        dex
        bpl :-
        ldx #16                 ; open bus can read $C9 once by chance: demand it 16 times
@p:     lda UCI_ID
        jsr uci_fence
        and #$7F
        cmp #$49
        bne @none
        dex
        bne @p
        lda #UCI_CTRL_ABORT     ; whatever an earlier program left in flight
        jsr ctrl
        lda #NET_ST_PRESENT
        sta net_status
        lda #UST_CLOSED
        sta uci_state
        clc
        rts
@none:  lda #NET_ERR_NODEV
        sta net_err
        sec
        rts
.endproc

.proc net_open
        lda #1
        sta open_req
        lda #0
        sta retry
        rts
.endproc

.proc net_close
        lda #0
        sta open_req
        lda net_status
        and #<~NET_ST_OPEN
        sta net_status
        rts                     ; net_poll sends the CLOSE once the interface is free
.endproc

; ---------------------------------------------------------------------------------------------
; net_poll -- at most ONE completion and ONE push per call; nothing is ever waited for.
; If a command is in flight and its reply is not staged yet, the call returns at once (the
; session layer calls net_poll twice a frame, so a command gets until the next call). Order of
; pushes: a READ first when a reply is owed and the receive buffer is free, else the WRITE.
; In a session that gives, per frame (session.s):
;   call 1: complete last frame's WRITE  -> push the READ for its reply (already queued)
;   call 2: complete that READ (reply)   -> push this frame's WRITE
; Worst case per call: settled status (2 reads) + one reply of <= 39 bytes + one WRITE of
; <= 39 bytes, each register access ~100 cycles.
.proc net_poll
        lda net_status
        and #<~NET_ST_ERROR
        sta net_status
        lda uci_state
        bne :+
        jmp @out                ; no interface
:       cmp #UST_CONNECT
        bcc @start              ; nothing in flight
        jsr poll_done
        bcc @start              ; completed: the interface is free for one push
        inc waitc               ; still busy: come back next call
        lda waitc
        cmp #WAIT_LIMIT
        bcc @out
        jsr abort               ; the command is lost; a READ/WRITE keeps the socket
        lda uci_state
        ldx #UST_IDLE
        cmp #UST_READ+1
        bcc :+
        ldx #UST_CLOSED         ; an aborted CLOSE: forget the socket
:       cmp #UST_CONNECT
        bne :+
        ldx #UST_CLOSED
:       stx uci_state
        jmp @out

@start: jsr ready
        bcs @out
        lda uci_state
        cmp #UST_IDLE
        beq @idle
        lda open_req            ; UST_CLOSED
        beq @out
        lda retry
        beq :+
        dec retry
        jmp @out
:       jsr push_connect
        jmp @out
@idle:  lda open_req
        bne :+
        jsr push_close
        jmp @out
:       lda last_empty          ; after an empty READ the WRITE goes first (a lost reply
        beq @rd                 ; must not keep the interface busy with READs)
        lda #0
        sta last_empty
        lda net_tx_len
        bne @wr
@rd:    lda net_rx_want         ; a reply owed and somewhere to put it: READ first
        beq :+
        lda net_rx_len
        bne :+
        jsr push_read
        jmp @out
:       lda net_tx_len
        beq @out
@wr:    jsr push_write
@out:   lda net_tx_len          ; a datagram still waiting for the interface
        beq :+
        INC16 net_stats + NET_STAT_DEFERRED
:       lda net_status          ; C = NET_ST_ERROR
        asl a
        rts
.endproc

; Is the command in flight finished? C=1 still busy; C=0 done (reply handled by complete).
.proc poll_done
        jsr read_status
        tax
        and #UCI_STAT_CMD_BUSY
        bne @busy
        txa
        and #UCI_STAT_STATE
        cmp #UCI_STATE_BUSY
        beq @busy
        txa
        jsr complete
        clc
        rts
@busy:  sec
        rts
.endproc

; Is the interface idle (STATE 00, CMD_BUSY 0)? C=0 yes. A latched ERROR is cleared; an orphaned
; reply (not ours) is drained and accepted; a busy interface is waited for, then aborted.
.proc ready
        lda idle_known          ; we just accepted a reply: the interface is idle (the probe
        beq :+                  ; reads STATUS 0 right after the accept on both devices,
        lda #0                  ; firmware 3.15a): skip the register read
        sta waitc
        clc
        rts
:       lda UCI_STATUS          ; one read: a torn value can only make us wait a poll
        jsr uci_fence
        tax
        and #UCI_STAT_ERROR
        beq :+
        lda #UCI_CTRL_CLR_ERR
        jsr ctrl
:       txa
        and #(UCI_STAT_STATE | UCI_STAT_CMD_BUSY)
        bne :+
        sta waitc               ; A = 0
        clc
        rts
:       txa
        and #$20                ; data last / data more: a stale reply
        beq @wait
        jsr finish
        sec
        rts
@wait:  inc waitc
        lda waitc
        cmp #WAIT_LIMIT
        bcc :+
        jsr abort
:       sec
        rts
.endproc

; Commit the pushed bytes as a command. A = the new state.
.proc push
        sta uci_state
        lda #0
        sta idle_known
        lda #UCI_CTRL_PUSH_CMD
        jsr ctrl
        lda #0
        sta waitc
        rts
.endproc

.proc begin                     ; A = command
        pha
        lda #UCI_TARGET_NETWORK
        jsr put
        pla
        jmp put
.endproc

.proc push_connect
        lda #UCI_CMD_UDP_CONNECT
        jsr begin
        lda net_peer_port       ; port, little-endian
        jsr put
        lda net_peer_port+1
        jsr put
        ldx #0                  ; host as ASCII dotted quad + NUL (UCI quirk: not 4 raw bytes)
@ip:    lda net_peer_ip,x
        jsr put_dec
        cpx #3
        beq :+
        lda #'.'
        jsr put
        inx
        bne @ip
:       lda #0
        jsr put
        lda #UST_CONNECT
        jmp push
.endproc

; A (0..255) as decimal ASCII without leading zeros. Preserves X.
.proc put_dec
        sta dtmp
        lda #0
        sta dlead
        lda #100
        jsr digit
        lda #10
        jsr digit
        lda dtmp
        ora #'0'
        jmp put
digit:  sta ddiv
        ldy #'0'
        lda dtmp
@l:     cmp ddiv
        bcc @d
        sbc ddiv
        iny
        bne @l
@d:     sta dtmp
        cpy #'0'
        bne @emit
        lda dlead
        beq @skip
@emit:  tya
        jsr put
        lda #1
        sta dlead
@skip:  rts
.endproc

.proc push_write
        lda #UCI_CMD_SOCKET_WRITE
        jsr begin
        lda uci_sock
        jsr put
        ldx #0
@l:     lda net_tx_buf,x
        sta UCI_CMD_DATA
        jsr uci_fence
        inx
        cpx net_tx_len
        bcc @l
        lda #0
        sta net_tx_len          ; copied into the FIFO: the buffer is free again
        INC16 net_stats + NET_STAT_WRITES
        lda #UST_WRITE
        jsr push
        TRACE TR_PUSH_WRITE
        rts
.endproc

.proc push_read
        lda #UCI_CMD_SOCKET_READ
        jsr begin
        lda uci_sock
        jsr put
        lda #<UCI_READ_MAX
        jsr put
        lda #>UCI_READ_MAX
        jsr put
.if .defined(UCI_READ_NOWAIT)
        lda #0                  ; opt-in: this READ does not wait for a datagram
        jsr put
.endif
        INC16 net_stats + NET_STAT_READS
        lda #UST_READ
        jsr push
        TRACE TR_PUSH_READ
        rts
.endproc

.proc push_close
        lda uci_sock
        bne :+
        lda #UST_CLOSED         ; never opened
        sta uci_state
        rts
:       lda #UCI_CMD_SOCKET_CLOSE
        jsr begin
        lda uci_sock
        jsr put
        lda #UST_CLOSE
        jmp push
.endproc

; ---------------------------------------------------------------------------------------------
; A reply is staged (STATE left Busy). A = settled status.
.proc complete
        ldx #0
        and #UCI_STAT_ERROR
        beq :+
        inx
        lda #UCI_CTRL_CLR_ERR
        jsr ctrl
:       stx cmd_err
        lda uci_state
        cmp #UST_READ
        beq c_read
        cmp #UST_WRITE
        beq c_write
        cmp #UST_CONNECT
        beq c_connect
        ; UST_CLOSE
        jsr finish
        lda #0
        sta uci_sock
        lda #UST_CLOSED
        sta uci_state
        rts

c_write:
        TRACE TR_WRITE_DONE
        jsr done_reply
        lda #UST_IDLE
        sta uci_state
        lda cmd_err
        beq :+
        lda #NET_ERR_SEND
        jmp set_err
:       rts

c_connect:
        lda #0
        sta uci_sock
        jsr get_byte            ; 1-byte socket id
        bcs :+
        sta uci_sock
:       jsr finish
        lda cmd_err
        bne @fail
        lda uci_sock
        beq @fail               ; phantom socket: no id / id 0
        lda stat_n
        cmp #2
        bcc @ok                 ; no status line: accept the id
        lda stat_code           ; "00,OK"; anything else (e.g. "85,ERROR OPENING SOCKET")
        cmp #'0'                ; is a refusal
        bne @fail
        lda stat_code+1
        cmp #'0'
        bne @fail
@ok:    lda #UST_IDLE
        sta uci_state
        lda net_status
        ora #NET_ST_OPEN
        sta net_status
        rts
@fail:  lda #0
        sta uci_sock
        lda #UST_CLOSED
        sta uci_state
        lda #RETRY_WAIT
        sta retry
        lda #NET_ERR_OPEN
        jmp set_err

c_read:
        lda #UST_IDLE
        sta uci_state
        lda cmd_err
        bne @bad
        jsr get_byte            ; length, little-endian (DATA_AV checked once: the rest of
        bcs @bad                ; the reply is one staged block). None at all: not a READ
                                ; answer (e.g. "81" for a 6-byte READ on firmware without it)
        sta rlen
        lda UCI_RESP_DATA
        jsr uci_fence
        tax
        and rlen
        cmp #$FF
        beq @empty              ; $FFFF: nothing queued (not an error)
        txa
        bne @bad                ; > 255: never asked for; framing not what we think
        lda rlen
        beq @empty
        ldy #0
        lda UCI_RESP_DATA       ; payload: the length header vouches for it (one reply
        jsr uci_fence           ; block holds 893 bytes, we asked for <= 255)
@b:     cpy #NET_RX_MAX
        bcs :+
        sta net_rx_buf,y
:       iny
        cpy rlen
        beq @got
        lda UCI_RESP_DATA
        jsr uci_fence
        jmp @b
@got:   ldx #0
        jsr hist
        jsr done_reply
        lda rlen
        cmp #NET_RX_MAX+1
        bcs @long
        sta net_rx_len          ; last: the datagram is now the caller's
        INC16 net_stats + NET_STAT_RX
        rts
@empty: INC16 net_stats + NET_STAT_EMPTY
        jsr free_read
        ldx #UCI_HIST_N
        jsr hist
        lda #1
        sta last_empty
        jmp done_reply
@bad:   jsr finish
@long:  lda #NET_ERR_RECV
        jmp set_err
.endproc
