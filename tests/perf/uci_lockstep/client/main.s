; main.s -- the lockstep test client (NTSC): lockstep.prg, over the Ultimate Command Interface.
;
; Connects to the relay (CONFIG block, port 6520), shows the lobby, and in a session runs a
; stand-in game step (core_tick: both players' bytes into a PRNG) on every tick, with the digest
; of that state handed to the session layer as digest.inc says. Two C64s in one session end
; every tick with the same PRNG state; the relay compares their digests every 256 ticks.
;
;   F1      HOST: open a room (the relay's room code appears after ROOM)
;   A-Z 0-9 type a room code (last 4 characters; DEL clears)
;   F3      JOIN the typed code
;   F5      LEAVE; in a session: hang up
;   joystick port 2 = the input byte sent each tick (bit 0 up .. bit 4 fire)
;
; Runs with BASIC and KERNAL banked out ($01 = $35) and a raster IRQ frame counter. The main
; loop (not the IRQ) calls c64n_frame once per frame.
;
; For ../run_pair.py: a CONFIG block at $0810 (relay address, port, auto HOST/JOIN; the PRG
; carries defaults, run_pair.py patches them before it starts the program) and a STATUS block at
; $0830 rewritten every frame (lobby state, ticks, stalls, digest, rng, UCI counters, CIA-timed
; cycle costs of c64n_frame and of the whole frame).

.include "platform.inc"
.include "session.inc"
.include "net.inc"
.include "digest.inc"

.import rng_seed, core_tick, digest_state
.importzp rng_lo, rng_hi

.ifndef RELAY_IP0
RELAY_IP0 = 0                   ; run_pair.py writes the relay's address into the CONFIG block
RELAY_IP1 = 0
RELAY_IP2 = 0
RELAY_IP3 = 0
.endif
.define NET_NAME "UCI"

CPU_PORT    = $01
SCREEN      = $0400
COLRAM      = $D800
VIC_CTRL1   = $D011
VIC_RASTER  = $D012
VIC_IRQFLAG = $D019
VIC_IRQMASK = $D01A
VIC_BORDER  = $D020
VIC_BG      = $D021
CIA1_PRA    = $DC00
CIA1_PRB    = $DC01
CIA1_DDRA   = $DC02
CIA1_DDRB   = $DC03
CIA1_ICR    = $DC0D
CIA1_TAL    = $DC04
CIA1_TAH    = $DC05
CIA1_CRA    = $DC0E
CIA2_ICR    = $DD0D
RASTER_LINE = 251

K_F1 = 1
K_F3 = 3
K_F5 = 5
K_DEL = 8

; ---------------------------------------------------------------------------
.segment "LOADADDR"
        .addr $0801

.segment "EXEHDR"
        .addr stub_end
        .word 10
        .byte $9E, "2061", 0
stub_end:
        .addr 0

.segment "STARTUP"              ; $080D: SYS 2061
start:  jmp init

; --- CONFIG block, $0810, 32 bytes (written by ../run_pair.py) -------------------------------
.segment "NETCFG"
netcfg:
cfg_magic:      .byte "NCFG"            ; +0
cfg_version:    .byte 1                 ; +4
cfg_relay:      .byte RELAY_IP0, RELAY_IP1, RELAY_IP2, RELAY_IP3    ; +5 relay IPv4
cfg_port:       .word C64N_PORT         ; +9 relay UDP port, little-endian
cfg_flags:      .byte 0                 ; +11 bit 0: HOST at boot; bit 1: JOIN cfg_code at boot
cfg_code:       .byte 0, 0, 0, 0        ; +12 room code for bit 1
cfg_ip:         .byte 0, 0, 0, 0        ; +16 reserved (unused over the UCI)
cfg_gw:         .byte 0, 0, 0, 0        ; +20 reserved (unused over the UCI)
cfg_cmd:        .byte 0                 ; +24 host command: 'Q' = hang up, close the
                                        ;     socket, stop (STATUS mode $FF when done)
                .res 7                  ; +25 reserved
.assert * - netcfg = 32, error, "CONFIG block must be 32 bytes"

; --- STATUS block, $0830, 64 bytes, rewritten every frame ------------------------------------
.segment "NETSTAT"
netstat:        .res 64
ST_MAGIC  = 0   ; "NSTA"
ST_VER    = 4   ; 1
ST_ALIVE  = 5   ; +1 every frame
ST_MODE   = 6   ; c64n_mode
ST_FLAGS  = 7   ; c64n_flags
ST_LOBBY  = 8   ; c64n_status
ST_PLAYER = 9
ST_DELAY  = 10
ST_END    = 11  ; c64n_end_reason
ST_PEER   = 12  ; c64n_peer_reason
ST_EVENT  = 13  ; last event
ST_TICKS  = 14  ; 16-bit ticks run this session (incl. the 5 lead-in ticks)
ST_STALLS = 16  ; 16-bit stall frames this session
ST_DIGEST = 18  ; last digest snapshot
ST_RNG    = 19  ; rng_lo, rng_hi
ST_RTT    = 21  ; c64n_rtt (LOBBY round trip, frames)
ST_NETST  = 22  ; net_status
ST_NETERR = 23  ; net_err
ST_STATS  = 24  ; net_stats (12 bytes: writes, reads, empty, errors, deferred, rx)
ST_CODE   = 36  ; room code (4)
ST_FRAMES = 40  ; 16-bit frames since boot
ST_NETCYC = 42  ; 16-bit CIA cycles in c64n_frame, this frame
ST_NETMAX = 44  ; 16-bit max of the above this session
ST_WORK   = 46  ; 16-bit CIA cycles of the whole main-loop pass, this frame
ST_WORKMAX = 48 ; 16-bit max of the above this session
ST_RELAY  = 50  ; relay IPv4 in use (4) + port (2)
ST_SID    = 56  ; c64n_sid
ST_LATER  = 57  ; replies that came after their READ had given up (wraps)
ST_LOSTR  = 58  ; replies that never came (wraps)
ST_LATEW  = 60  ; 16-bit frames whose datagram only left in a later frame
ST_SKIPS  = 62  ; 16-bit frames that sent nothing to drain a reply backlog

.segment "ZEROPAGE"
frame:          .res 1
sptr:           .res 2

.segment "BSS"
joy2:           .res 1
key:            .res 1          ; key down this frame (0 = none)
key_prev:       .res 1
typed:          .res 4
last_event:     .res 1
disp_tick:      .res 2
disp_p1:        .res 1
disp_p2:        .res 1
last_digest:    .res 1
stalls:         .res 2
t_work:         .res 2              ; CIA1 timer A at the start of the main-loop pass
t_net:          .res 2              ; ... just before c64n_frame
drow:           .res 1
quit:           .res 1              ; 0 running; 1.. frames since 'Q'
col:            .res 1
save_x:         .res 1
t_tmp:          .res 2
t_tmp2:         .res 2

.export start, frame, wait_frame, wait_done, after_net, after_poll, joy2, key, typed, last_event
.export netcfg, netstat
.export disp_tick, disp_p1, disp_p2, last_digest

; ---------------------------------------------------------------------------
.segment "RODATA"
hex_digits:     .byte "0123456789ABCDEF"
relay_ip:       .byte RELAY_IP0, RELAY_IP1, RELAY_IP2, RELAY_IP3
st_magic:       .byte "NSTA"
st_cfgmagic:    .byte "NCFG"

; keyboard matrix (column 0..7 x row 0..7) -> ASCII / K_* (0 = ignored)
keymap:
        .byte K_DEL, 0, 0, 0, K_F1, K_F3, K_F5, 0
        .byte "3WA4ZSE", 0
        .byte "5RD6CFTX"
        .byte "7YG8BHUV"
        .byte "9IJ0MKON"
        .byte 0, "PL", 0, 0, 0, 0, 0
        .byte 0, 0, 0, 0, 0, 0, 0, 0
        .byte "1", 0, 0, "2", 0, 0, "Q", 0

str_title:  .byte "C64 LOCKSTEP  APP LS64 V1", 0
str_net:    .byte "NET   ", NET_NAME, 0
str_ok:     .byte " OK", 0
str_none:   .byte " NONE", 0
str_relay:  .byte "RELAY ", 0
str_port:   .byte ":6520", 0
str_noreply: .byte " NO REPLY", 0
str_lobby:  .byte "LOBBY ", 0
str_room:   .byte " ROOM ", 0
str_typed:  .byte "TYPED ", 0
str_tick:   .byte "TICK ", 0
str_p1:     .byte " P1 ", 0
str_p2:     .byte " P2 ", 0
str_you:    .byte " YOU P", 0
str_dly:    .byte " DLY ", 0
str_rng:    .byte "RNG ", 0
str_dig:    .byte " DIGEST ", 0
str_end:    .byte "LAST END ", 0
str_peer:   .byte " PEER ", 0
str_help1:  .byte "F1 HOST  F3 JOIN TYPED  F5 LEAVE", 0
str_help2:  .byte "TYPE A-Z 0-9 FOR A CODE, DEL CLEARS", 0
status_names:   ; 8 characters each, index = c64n_status (6 = unknown / in session)
        .byte "IDLE    ", "WAITING ", "NO ROOM ", "FULL    "
        .byte "MISMATCH", "BUSY    ", "--------", "SESSION "

; ---------------------------------------------------------------------------
.segment "CODE"

.assert start = $080D, lderror, "BASIC stub SYS address mismatch"
.assert netcfg = $0810, lderror, "CONFIG block must be at $0810"
.assert netstat = $0830, lderror, "STATUS block must be at $0830"

.proc init
        sei
        cld
        ldx #$FF
        txs
        lda #$7F
        sta CIA1_ICR
        sta CIA2_ICR
        lda CIA1_ICR
        lda CIA2_ICR
        lda #$35
        sta CPU_PORT
        lda #<irq
        sta $FFFE
        lda #>irq
        sta $FFFF
        lda #<nmi
        sta $FFFA
        lda #>nmi
        sta $FFFB
        lda #0
        ldx #CORE_ZP            ; core zero page starts clear (core state is seeded anyway)
:       sta $00,x
        inx
        cpx #CORE_ZP + CORE_ZP_SIZE
        bne :-
        sta frame
        sta key_prev
        sta last_event
        sta disp_tick
        sta disp_tick+1
        sta disp_p1
        sta disp_p2
        sta last_digest
        sta quit
        ldx #63
:       sta netstat,x
        dex
        bpl :-
        ldx #3
:       lda st_magic,x
        sta netstat,x
        dex
        bpl :-
        lda #1
        sta netstat+ST_VER
        lda #$FF                ; CIA1 timer A free-running from $FFFF: cycle costs (no IRQ)
        sta CIA1_TAL
        sta CIA1_TAH
        lda #$11
        sta CIA1_CRA
        lda #$FF                ; the first frame draws row 0
        sta drow
        lda #' '
        ldx #3
:       sta typed,x
        dex
        bpl :-
        lda #11
        sta VIC_BORDER
        lda #6
        sta VIC_BG
        jsr clear_screen
        jsr draw_static
        jsr rng_seed

        jsr apply_config
        jsr c64n_init
        lda cfg_flags           ; auto HOST / JOIN from the CONFIG block
        lsr a
        bcc :+
        jsr c64n_host
:       lda cfg_flags
        and #2
        beq :++
        ldx #3
:       lda cfg_code,x
        sta c64n_arg,x
        dex
        bpl :-
        jsr c64n_join
:

        lda #$1B
        sta VIC_CTRL1
        lda #RASTER_LINE
        sta VIC_RASTER
        lda #$01
        sta VIC_IRQMASK
        sta VIC_IRQFLAG
        cli
.endproc

main_loop:
        lda frame
wait_frame:   cmp frame               ; wait for the raster IRQ
        beq wait_frame
wait_done:
        lda quit                ; stopping: wait for the socket to close
        beq :+
        jmp quitting
:       lda cfg_cmd
        cmp #'Q'
        bne :+
        jsr c64n_hangup         ; (in a session: BYE; otherwise leave the room)
        lda #1
        sta quit
:       jsr timer_read
        sta t_work
        stx t_work+1
        jsr read_keys
        jsr read_joy2
        jsr handle_key
        jsr timer_read
        sta t_net
        stx t_net+1
        lda joy2
        clc                     ; this demo's tick work always fits in a frame
        jsr c64n_frame
after_net:
        sta last_event
        ldy #ST_NETCYC
        lda t_net
        ldx t_net+1
        jsr cost
        lda last_event
        cmp #C64N_EV_START
        bne @nostart
        jsr rng_seed            ; a session starts from the constant state
        lda #0
        sta disp_tick
        sta disp_tick+1
        sta disp_p1
        sta disp_p2
        sta stalls
        sta stalls+1
        sta netstat+ST_NETMAX   ; session maxima restart
        sta netstat+ST_NETMAX+1
        sta netstat+ST_WORKMAX
        sta netstat+ST_WORKMAX+1
        beq @draw
@nostart:
        cmp #C64N_EV_STALL
        bne @nostall
        inc stalls
        bne @draw
        inc stalls+1
        bne @draw
@nostall:
        cmp #C64N_EV_TICK
        bne @draw
        jsr game_tick
@draw:  jsr draw
        jsr timer_read          ; the frame's work is done: let the network finish this
        sta t_net               ; frame's datagram and start reading its reply, which then
        stx t_net+1             ; has the rest of the frame to arrive and be staged
        jsr c64n_poll
after_poll:
        ldy #ST_NETCYC
        lda t_net
        ldx t_net+1
        jsr add_cost
        ldy #ST_WORK
        lda t_work
        ldx t_work+1
        jsr cost
        jsr update_status
        jmp main_loop

; 'Q' from run_pair.py: a few more frames of the session layer (the BYE goes out), then close
; the socket -- an Ultimate socket left open across the next reset leaks a firmware UDP PCB
; (8 in all) and can poison the device's lease path -- and stop: STATUS mode $FF.
QUIT_BYE_FRAMES   = 12
QUIT_CLOSE_FRAMES = 30
.proc quitting
        inc quit
        lda quit
        cmp #QUIT_BYE_FRAMES
        bcs :+
        lda #0
        clc
        jsr c64n_frame          ; still running: the BYE / LOBBY LEAVE leave
        jsr c64n_poll
        jmp @st
:       bne :+
        jsr net_close           ; once, at QUIT_BYE_FRAMES
:       jsr net_poll            ; the CLOSE goes out and completes
        lda quit
        cmp #QUIT_CLOSE_FRAMES
        bcc @st
        lda #QUIT_CLOSE_FRAMES  ; (stay here)
        sta quit
        jsr update_status
        lda #$FF
        sta netstat+ST_MODE
        jmp main_loop
@st:    jsr update_status
        jmp main_loop
.endproc

; CIA1 timer A now (counts down): A = low, X = high.
.proc timer_read
:       ldx CIA1_TAH
        lda CIA1_TAL
        cpx CIA1_TAH
        bne :-
        rts
.endproc

; A/X = timer value at the start of something; Y = ST_NETCYC or ST_WORK. Stores the elapsed
; cycles at netstat+Y (cost) or adds them to it (add_cost), and raises the session maximum at
; netstat+Y+2.
.proc elapsed16                 ; A/X = start -> t_tmp = cycles since. Preserves Y.
        sta t_tmp
        stx t_tmp+1
        jsr timer_read
        sta t_tmp2
        stx t_tmp2+1
        lda t_tmp
        sec
        sbc t_tmp2
        sta t_tmp
        lda t_tmp+1
        sbc t_tmp2+1
        sta t_tmp+1
        rts
.endproc

.proc add_cost
        jsr elapsed16
        lda netstat,y
        clc
        adc t_tmp
        sta netstat,y
        lda netstat+1,y
        adc t_tmp+1
        sta netstat+1,y
        jmp upd_max
.endproc

.proc cost
        jsr elapsed16
        lda t_tmp
        sta netstat,y
        lda t_tmp+1
        sta netstat+1,y
        ; fall through
.endproc
.proc upd_max
        lda netstat+2,y         ; new maximum? (max - now borrows)
        cmp netstat,y
        lda netstat+3,y
        sbc netstat+1,y
        bcs @x
        lda netstat,y
        sta netstat+2,y
        lda netstat+1,y
        sta netstat+3,y
@x:     rts
.endproc

; Relay address and port from the CONFIG block (compile-time values if it is not valid).
.proc apply_config
        ldx #3
:       lda cfg_magic,x
        cmp st_cfgmagic,x
        bne @dflt
        dex
        bpl :-
        lda cfg_version
        cmp #1
        bne @dflt
        ldx #3
:       lda cfg_relay,x
        sta net_peer_ip,x
        dex
        bpl :-
        lda cfg_port
        sta net_peer_port
        lda cfg_port+1
        sta net_peer_port+1
        rts
@dflt:  lda #0
        sta cfg_flags
        ldx #3
:       lda relay_ip,x
        sta net_peer_ip,x
        dex
        bpl :-
        lda #<C64N_PORT
        sta net_peer_port
        lda #>C64N_PORT
        sta net_peer_port+1
        rts
.endproc

; The STATUS block for run_pair.py (~400 cycles).
.proc update_status
        inc netstat+ST_ALIVE
        lda c64n_mode
        sta netstat+ST_MODE
        lda c64n_flags
        sta netstat+ST_FLAGS
        lda c64n_status
        sta netstat+ST_LOBBY
        lda c64n_player
        sta netstat+ST_PLAYER
        lda c64n_delay
        sta netstat+ST_DELAY
        lda c64n_end_reason
        sta netstat+ST_END
        lda c64n_peer_reason
        sta netstat+ST_PEER
        lda last_event
        sta netstat+ST_EVENT
        lda disp_tick
        sta netstat+ST_TICKS
        lda disp_tick+1
        sta netstat+ST_TICKS+1
        lda stalls
        sta netstat+ST_STALLS
        lda stalls+1
        sta netstat+ST_STALLS+1
        lda last_digest
        sta netstat+ST_DIGEST
        lda rng_lo
        sta netstat+ST_RNG
        lda rng_hi
        sta netstat+ST_RNG+1
        lda c64n_rtt
        sta netstat+ST_RTT
        lda net_status
        sta netstat+ST_NETST
        lda net_err
        sta netstat+ST_NETERR
        lda c64n_sid
        sta netstat+ST_SID
        lda c64n_late_replies
        sta netstat+ST_LATER
        lda c64n_lost_replies
        sta netstat+ST_LOSTR
        lda c64n_late_writes
        sta netstat+ST_LATEW
        lda c64n_late_writes+1
        sta netstat+ST_LATEW+1
        lda c64n_skips
        sta netstat+ST_SKIPS
        lda c64n_skips+1
        sta netstat+ST_SKIPS+1
        ldx #NET_STATS_SIZE - 1
:       lda net_stats,x
        sta netstat+ST_STATS,x
        dex
        bpl :-
        ldx #3
:       lda c64n_code,x
        sta netstat+ST_CODE,x
        lda net_peer_ip,x
        sta netstat+ST_RELAY,x
        dex
        bpl :-
        lda net_peer_port
        sta netstat+ST_RELAY+4
        lda net_peer_port+1
        sta netstat+ST_RELAY+5
        inc netstat+ST_FRAMES
        bne :+
        inc netstat+ST_FRAMES+1
:       rts
.endproc

; One lockstep tick: digest snapshot (digest.inc), then the game step.
.proc game_tick
        lda c64n_tick
        cmp #DIGEST_SNAP_TICK
        bne :+
        lda c64n_tick_hi        ; (never during the lead-in ticks -5..-1)
        bmi :+
        jsr digest_state
        sta c64n_digest
        sta last_digest
:       lda c64n_my             ; my/other -> P1/P2 by player number
        ldx c64n_oth
        ldy c64n_player
        cpy #1
        beq :+
        lda c64n_oth
        ldx c64n_my
:       sta disp_p1
        stx disp_p2
        jsr core_tick
        inc disp_tick
        bne :+
        inc disp_tick+1
:       rts
.endproc

.proc handle_key
        lda key
        beq @x
        cmp key_prev
        beq @x                  ; held
        cmp #K_F1
        bne :+
        jmp c64n_host
:       cmp #K_F3
        bne :+
        ldx #3
@cp:    lda typed,x
        sta c64n_arg,x
        dex
        bpl @cp
        jmp c64n_join
:       cmp #K_F5
        bne :+
        jmp c64n_hangup
:       cmp #K_DEL
        bne :+
        lda #' '
        sta typed
        sta typed+1
        sta typed+2
        sta typed+3
        rts
:       ldx typed+1             ; shift the code left, append
        stx typed
        ldx typed+2
        stx typed+1
        ldx typed+3
        stx typed+2
        sta typed+3
@x:     rts
.endproc

; Keyboard matrix scan: key = first mapped key down (keymap value), else 0.
.proc read_keys
        lda key
        sta key_prev
        lda #0
        sta key
        lda #$FF
        sta CIA1_DDRA           ; port A drives the columns
        lda #0
        sta CIA1_DDRB
        ldx #0                  ; X = column * 8
        lda #$FE
        sta col
@col:   lda col
        sta CIA1_PRA
        lda CIA1_PRB
        eor #$FF
        beq @next
        stx save_x
        ldy #8
@row:   lsr a
        bcc @nk
        pha
        lda keymap,x
        beq :+
        sta key
        pla
        jmp @done
:       pla
@nk:    inx
        dey
        bne @row
        ldx save_x
@next:  txa
        clc
        adc #8
        tax
        sec
        rol col                 ; next column; C = 0 after the eighth
        bcs @col
@done:  lda #$FF
        sta CIA1_PRA
        lda #0
        sta CIA1_DDRA           ; back to inputs for the joystick read
        rts
.endproc

.proc read_joy2
        lda CIA1_PRA
        eor #$FF
        and #$1F
        sta joy2
        rts
.endproc

; ---------------------------------------------------------------------------
; Screen. Strings are upper-case ASCII; & $3F is the screen code.

.proc clear_screen
        ldx #0
@l:     lda #$20
        sta SCREEN,x
        sta SCREEN + $100,x
        sta SCREEN + $200,x
        sta SCREEN + $2E8,x
        lda #1
        sta COLRAM,x
        sta COLRAM + $100,x
        sta COLRAM + $200,x
        sta COLRAM + $2E8,x
        inx
        bne @l
        rts
.endproc

.macro AT r
        lda #<(SCREEN + (r) * 40 + 1)
        ldx #>(SCREEN + (r) * 40 + 1)
        jsr at_row
.endmacro
.macro PUTS s
        lda #<s
        ldx #>s
        jsr put_str
.endmacro

; Start a row: clear 38 columns, write position Y = 0.
.proc at_row
        sta sptr
        stx sptr+1
        ldy #37
        lda #$20
:       sta (sptr),y
        dey
        bpl :-
        iny
        rts
.endproc

.proc put_str                   ; A/X = string; Y = column (advanced)
        sta @l+1                ; self-modified source address (the PRG runs from RAM)
        stx @l+2
        ldx #0
@l:     lda $FFFF,x
        beq @d
        and #$3F
        sta (sptr),y
        iny
        inx
        bne @l
@d:     rts
.endproc

.proc put_char                  ; ASCII
        and #$3F
        sta (sptr),y
        iny
        rts
.endproc

.proc put_hex
        pha
        lsr a
        lsr a
        lsr a
        lsr a
        tax
        lda hex_digits,x
        jsr put_char
        pla
        and #$0F
        tax
        lda hex_digits,x
        jmp put_char
.endproc

.proc put_dec                   ; A = 0..255, no leading zeros
        ldx #0
        stx save_x
@h:     cmp #100
        bcc @t0
        sbc #100
        inx
        bne @h
@t0:    pha
        txa
        beq :+
        ora #'0'
        jsr put_char
        inc save_x
:       pla
        ldx #0
@t:     cmp #10
        bcc @o
        sbc #10
        inx
        bne @t
@o:     pha
        txa
        bne :+
        lda save_x
        beq :++
        txa
:       ora #'0'
        jsr put_char
:       pla
        ora #'0'
        jmp put_char
.endproc

; Static rows, once at boot.
.proc draw_static
        AT 1
        PUTS str_title
        AT 13
        PUTS str_help1
        AT 14
        PUTS str_help2
        rts
.endproc

; One status row per frame, round robin (all of them cost ~11 000 cycles: too much for one
; frame next to the network and the game).
.proc draw
        ldx drow
        inx
        cpx #7
        bcc :+
        ldx #0
:       stx drow
        lda row_hi,x
        pha
        lda row_lo,x
        pha
        rts                     ; to row_*: RTS pops the address and adds 1
row_lo: .lobytes row_net-1, row_relay-1, row_lobby-1, row_typed-1, row_tick-1, row_rng-1, row_end-1
row_hi: .hibytes row_net-1, row_relay-1, row_lobby-1, row_typed-1, row_tick-1, row_rng-1, row_end-1
.endproc

.proc row_net
        AT 3
        PUTS str_net
        lda c64n_flags
        and #C64N_F_NO_NET
        beq :+
        PUTS str_none
        rts
:       PUTS str_ok
        rts
.endproc

.proc row_relay
        AT 4
        PUTS str_relay
        ldx #0
:       stx col
        lda relay_ip,x
        jsr put_dec
        ldx col
        cpx #3
        beq :+
        lda #'.'
        jsr put_char
        ldx col
        inx
        bne :-
:       PUTS str_port
        lda c64n_flags
        and #C64N_F_NO_RELAY
        beq :+
        PUTS str_noreply
:       rts
.endproc

.proc row_lobby
        AT 5
        PUTS str_lobby
        lda c64n_mode
        ldx #7
        cmp #C64N_MODE_SESSION
        beq @nm
        ldx c64n_status
        cpx #6
        bcc @nm
        ldx #6
@nm:    txa
        asl a
        asl a
        asl a
        tax
        lda #8
        sta col
:       lda status_names,x
        jsr put_char
        inx
        dec col
        bne :-
        PUTS str_room
        ldx #0
:       lda c64n_code,x
        beq :+
        stx col
        jsr put_char
        ldx col
:       inx
        cpx #4
        bne :--
        rts
.endproc

.proc row_typed
        AT 6
        PUTS str_typed
        ldx #0
:       lda typed,x
        stx col
        jsr put_char
        ldx col
        inx
        cpx #4
        bne :-
        rts
.endproc

.proc row_tick
        AT 8
        PUTS str_tick
        lda disp_tick+1
        jsr put_hex
        lda disp_tick
        jsr put_hex
        PUTS str_p1
        lda disp_p1
        jsr put_hex
        PUTS str_p2
        lda disp_p2
        jsr put_hex
        PUTS str_you
        lda c64n_player
        ora #'0'
        jsr put_char
        PUTS str_dly
        lda c64n_delay
        jmp put_dec
.endproc

.proc row_rng
        AT 9
        PUTS str_rng
        lda rng_hi
        jsr put_hex
        lda rng_lo
        jsr put_hex
        PUTS str_dig
        lda last_digest
        jmp put_hex
.endproc

.proc row_end
        AT 10
        PUTS str_end
        lda c64n_end_reason
        ora #'0'
        jsr put_char
        PUTS str_peer
        lda c64n_peer_reason
        ora #'0'
        jmp put_char
.endproc

; ---------------------------------------------------------------------------
.proc irq
        pha
        lda #$01
        sta VIC_IRQFLAG
        inc frame
        pla
        rti
.endproc

.proc nmi
        rti
.endproc
