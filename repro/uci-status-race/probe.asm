; probe.asm - 6510 probe for the UCI $DF1C status race.
; Opens a plain TCP connection through the Command Interface, sends one byte ('B'), then READs 1472 bytes at a time
; (two blocks: 893+2 and 579 bytes) until TARGET payload bytes have arrived, closes, and repeats NCONN times. Every
; block's first "reply ready" sample of $DF1C is kept; after the block is drained, a block shorter than 895 bytes
; must be the last one of its reply (a "more" block is always full). If that block's sample said Data More (11),
; that is a misread: $DF1C is re-read three times, the event is counted and logged.
;
;   ACT = 1 (probe-recheck.prg): if the first re-read says Data Last (10) the block is treated as last and
;           the run continues.
;   ACT = 0 (probe-hang.prg): the event is counted, then the misread is believed like an ordinary client would:
;           DATA_ACC, then wait for another block, which never comes. The wait times out (ERR = 11, DONE = $EE).
;
; Build: 64tass -a -D ACT=1 probe.asm -o probe-recheck.prg ; 64tass -a -D ACT=0 probe.asm -o probe-hang.prg
; Configure with host/mkcfg.py (it patches the config block at $0810 inside the PRG file).
; UCI rules followed: the status queue ($DF1F) is read only while STAT_AV is set, each byte consumed once.

; ACT comes from the command line (-D ACT=1 or -D ACT=0).

; ---- config block, inside the PRG image (patched by host/mkcfg.py) -----------------------------
NCONN   = $0810         ; 16 bit connections to make, 0 = until stopped
TARGET  = $0812         ; 24 bit payload bytes per connection
TMO     = $0815         ; wait budget per reply, units of 65536 polls of $DF1C
OPENLEN = $0816         ; length of the OPEN_TCP command at OPENCMD
OPENCMD = $0820         ; OPEN_TCP command: 03 07 port.lo port.hi host-ascii 00 (up to 64 bytes)

; ---- results, in RAM ($C000..): read from the screen at the end, or dump 192 bytes with host/decode.py ----
DONE    = $C002         ; $00 running, $5A finished OK, $EE stopped on an error
ERR     = $C003         ; error code, 0 none
CONNS   = $C010         ; 16 bit connections completed
READS   = $C012         ; 24 bit READ commands issued
LASTBLK = $C015         ; 24 bit blocks that were the last of their reply (shorter than 895 bytes)
EVENTS  = $C018         ; 16 bit last blocks whose first sample said 11 (the race)
ACTED   = $C01A         ; ... of which the first re-read said 10
STILL   = $C01C         ; ... of which the first re-read still said 11
DIS     = $C01E         ; 16 bit blocks whose first sample differs from a read after the drain (any state)
MISM    = $C020         ; 16 bit payload bytes that did not equal their stream offset & $FF
SIG     = $C022         ; $E1 once initialised
LOGY    = $C023         ; byte offset of the next log entry
LOG     = $C040         ; 16 entries x 8: sample, re-read 1, 2, 3, block bytes lo, hi, READS lo, mid

E_OPEN  = 2
E_WRITE = 4
E_READ  = 5
E_CLOSE = 7
E_TMO   = 11
E_BUSY  = 13

CTRL    = $DF1C
CMDREG  = $DF1D
RESP    = $DF1E
STATR   = $DF1F
CHROUT  = $FFD2
CMDB    = $C0C0         ; WRITE / READ / CLOSE commands are built here

; ---- zero page ---------------------------------------------------------------------------------
cp      = $FB           ; command pointer (2)
cl      = $FD           ; command length (2)
rx0     = $20           ; payload bytes received, 24 bit (also the expected byte)
rx1     = $21
rx2     = $22
zstat   = $2C           ; first sample of $DF1C in the current reply block
rdflag  = $2D           ; 0 generic reply, 1 READ reply (2 byte header, then byte-checked payload)
hs      = $2E           ; header bytes still to skip
gotf    = $2F           ; first data byte of the reply seen
first   = $30           ; first data byte of the reply (the handle for OPEN_TCP)
bb0     = $31           ; data bytes drained from this block
bb1     = $32
c1      = $33           ; status code of the last block, 2 ASCII bytes
c2      = $34
sidx    = $35
post    = $36
r1      = $37
r2      = $38
r3      = $39
w0      = $3A
w1      = $3B
w2      = $3C
hh      = $3D           ; handle
py      = $3E

inc16   .macro
        inc \1
        bne +
        inc \1+1
+
        .endm

        * = $0801
        .word basic_end, 10
        .byte $9e
        .text "2061"
        .byte 0
basic_end
        .word 0
        jmp start       ; $080D

        * = $0860
start
        sei
        cld
        ldx #$FF
        txs
        lda #$00
        tax
clr
        sta $C000,x
        inx
        bne clr
        lda #$E1
        sta SIG
conn_loop
        lda NCONN
        ora NCONN+1
        beq do_conn
        lda CONNS
        cmp NCONN
        bne do_conn
        lda CONNS+1
        cmp NCONN+1
        beq finished
do_conn
        jsr one_conn
        bcs failed
        #inc16 CONNS
        jmp conn_loop
finished
        lda #$5A
        sta DONE
        jmp report
failed
        lda #$EE
        sta DONE
report
        jsr print_report
park
        jmp park

; ------------------------------------------------------------------------------------ one_conn
; OPEN_TCP, WRITE 'B', READ 1472 until TARGET payload bytes arrived, CLOSE. C set on error (ERR set).
one_conn
        lda #<OPENCMD
        sta cp
        lda #>OPENCMD
        sta cp+1
        lda OPENLEN
        sta cl
        lda #$00
        sta cl+1
        sta rdflag
        jsr uci_xact
        bcs oc_ret1
        jsr is_ok
        beq oc_open
        lda #E_OPEN
        jmp oc_err
oc_ret1
        rts
oc_open
        lda first
        sta hh
        lda #$03                ; WRITE handle, 'B'
        sta CMDB
        lda #$11
        sta CMDB+1
        lda hh
        sta CMDB+2
        lda #$42
        sta CMDB+3
        lda #$04
        jsr run_cmd
        bcs oc_ret2
        jsr is_ok
        beq oc_wrote
        lda #E_WRITE
        jmp oc_err
oc_ret2
        rts
oc_wrote
        lda #$00
        sta rx0
        sta rx1
        sta rx2
xf_loop
        lda #$03                ; READ handle, 1472
        sta CMDB
        lda #$10
        sta CMDB+1
        lda hh
        sta CMDB+2
        lda #$C0
        sta CMDB+3
        lda #$05
        sta CMDB+4
        #inc16 READS
        bne xf_c
        inc READS+2
xf_c
        lda #$05
        ldx #$01
        stx rdflag
        jsr run_cmd_rd
        bcs oc_ret
        lda c1
        cmp #$30
        bne xf_bad
        lda c2
        cmp #$32                ; "02" NO DATA: ask again
        beq xf_loop
        cmp #$30
        bne xf_bad
        lda rx0                 ; payload received >= TARGET ?
        cmp TARGET
        lda rx1
        sbc TARGET+1
        lda rx2
        sbc TARGET+2
        bcc xf_loop
        lda #$03                ; CLOSE handle
        sta CMDB
        lda #$09
        sta CMDB+1
        lda hh
        sta CMDB+2
        lda #$03
        jsr run_cmd
        bcs oc_ret
        clc
        rts
xf_bad
        lda #E_READ
oc_err
        sta ERR
        sec
oc_ret
        rts

; run_cmd: command in CMDB, length in A, generic reply. run_cmd_rd: same, rdflag already set.
run_cmd
        ldx #$00
        stx rdflag
run_cmd_rd
        sta cl
        lda #$00
        sta cl+1
        lda #<CMDB
        sta cp
        lda #>CMDB
        sta cp+1
        jmp uci_xact

; Z set when the last status code was "00".
is_ok
        lda c1
        cmp #$30
        bne iso_no
        lda c2
        cmp #$30
iso_no
        rts

; ---------------------------------------------------------------------------------- uci_xact
; Run one command (cp, cl) and read its whole reply. rdflag 1: skip the 2 byte header, count and check the payload.
; Status text of the last block -> c1/c2 (ASCII). C set: interface error (ERR set).
uci_xact
        jsr release
        bcc ux_push
        rts
ux_push
        lda cl
        ora cl+1
        beq ux_pushed
        ldy #$00
        lda (cp),y
        sta CMDREG
        inc cp
        bne ux_n1
        inc cp+1
ux_n1
        lda cl
        bne ux_n2
        dec cl+1
ux_n2
        dec cl
        jmp ux_push
ux_pushed
        lda rdflag
        asl
        sta hs
        lda #$00
        sta gotf
        sta first
        lda #$01                ; PUSH_CMD
        sta CTRL
        jsr wait_reply
        bcs ux_ret
ux_block
        lda #$00
        sta bb0
        sta bb1
        jsr drain_data
        jsr drain_status
        lda CTRL                ; the state after the drain
        and #$30
        sta post
        lda zstat
        and #$30
        cmp post
        beq ux_same
        #inc16 DIS
ux_same
        lda bb1                 ; a block of 895 bytes or more can be a "more" block, a shorter one is the last
        cmp #$03
        bcc ux_short
        bne ux_decide
        lda bb0
        cmp #$7F
        bcs ux_decide
ux_short
        inc LASTBLK
        bne ux_lb
        inc LASTBLK+1
        bne ux_lb
        inc LASTBLK+2
ux_lb
        lda zstat
        and #$30
        cmp #$30
        bne ux_decide
        jsr race_event
        bcs ux_last
ux_decide
        lda zstat
        and #$30
        cmp #$30                ; Data More
        bne ux_last
        lda #$02                ; DATA_ACC, then wait for the next block
        sta CTRL
        jsr wait_reply
        bcs ux_ret2
        jmp ux_block
ux_ret2
        rts
ux_last
        lda #$02
        sta CTRL
        clc
ux_ret
        rts

; A last block whose first sample said 11. Re-read, count, log. C set when the run should go on as "last".
race_event
        lda CTRL
        sta r1
        lda CTRL
        sta r2
        lda CTRL
        sta r3
        #inc16 EVENTS
        ldy LOGY
        cpy #128
        bcs re_nolog
        lda zstat
        sta LOG,y
        iny
        lda r1
        sta LOG,y
        iny
        lda r2
        sta LOG,y
        iny
        lda r3
        sta LOG,y
        iny
        lda bb0
        sta LOG,y
        iny
        lda bb1
        sta LOG,y
        iny
        lda READS
        sta LOG,y
        iny
        lda READS+1
        sta LOG,y
        iny
        sty LOGY
re_nolog
        lda r1
        and #$30
        cmp #$20
        beq re_last
        #inc16 STILL
        clc
        rts
re_last
        #inc16 ACTED
        .if ACT
        sec
        .else
        clc
        .endif
        rts

; release: hand back anything pending and clear a stale error until the interface is Idle
release
        ldx #$20
rel_loop
        lda #$02
        sta CTRL
        lda #$08
        sta CTRL
        lda CTRL
        and #$30
        beq rel_ok
        dex
        bne rel_loop
        lda #E_BUSY
        sta ERR
        sec
        rts
rel_ok
        clc
        rts

; wait_reply: until state is Data Last / Data More; the first such sample stays in zstat
wait_reply
        lda #$00
        sta w0
        sta w1
        lda TMO
        sta w2
wr_loop
        lda CTRL
        sta zstat
        and #$30
        cmp #$20
        beq wr_ok
        cmp #$30
        beq wr_ok
        dec w0
        bne wr_loop
        dec w1
        bne wr_loop
        dec w2
        bne wr_loop
        lda #E_TMO
        sta ERR
        sec
        rts
wr_ok
        clc
        rts

; data of one block: polls DATA_AV for every byte
drain_data
dd_loop
        lda CTRL
        bpl dd_done
        lda RESP
        ldy gotf
        bne dd_have
        sta first
        inc gotf
dd_have
        inc bb0
        bne dd_cnt
        inc bb1
dd_cnt
        ldy rdflag
        beq dd_loop
        ldy hs
        beq dd_chk
        dec hs
        jmp dd_loop
dd_chk
        cmp rx0
        beq dd_ok
        #inc16 MISM
dd_ok
        inc rx0
        bne dd_loop
        inc rx1
        bne dd_loop
        inc rx2
        jmp dd_loop
dd_done
        rts

drain_status
        lda #$3F                ; '?' '?' if the block carries no status
        sta c1
        sta c2
        lda #$00
        sta sidx
ds_loop
        lda CTRL
        and #$40
        beq ds_done
        lda STATR
        ldx sidx
        cpx #$02
        bcs ds_loop             ; consumed, not stored
        sta c1,x
        inc sidx
        jmp ds_loop
ds_done
        rts

; ----------------------------------------------------------------------------- screen report
print_report
        lda #$93
        jsr CHROUT
        #pv s_done, DONE, 1
        #pv s_err, ERR, 1
        lda #$0D
        jsr CHROUT
        #pv s_conns, CONNS, 2
        lda #$0D
        jsr CHROUT
        #pv s_reads, READS, 3
        lda #$0D
        jsr CHROUT
        #pv s_last, LASTBLK, 3
        lda #$0D
        jsr CHROUT
        #pv s_events, EVENTS, 2
        lda #$0D
        jsr CHROUT
        #pv s_acted, ACTED, 2
        #pv s_still, STILL, 2
        lda #$0D
        jsr CHROUT
        #pv s_dis, DIS, 2
        #pv s_mism, MISM, 2
        lda #$0D
        jmp CHROUT

pv      .macro
        lda #<\1
        ldx #>\1
        jsr prstr
        lda #<\2
        sta cp
        lda #>\2
        sta cp+1
        ldy #\3-1
        jsr prval
        .endm

prstr
        sta cp
        stx cp+1
        ldy #$00
ps_loop
        lda (cp),y
        beq ps_done
        sty py
        jsr CHROUT
        ldy py
        iny
        bne ps_loop
ps_done
        rts

prval
pvl
        sty py
        lda (cp),y
        jsr prhex
        ldy py
        dey
        bpl pvl
        rts

prhex
        pha
        lsr
        lsr
        lsr
        lsr
        jsr nib
        pla
        and #$0F
nib
        cmp #$0A
        bcc nib_d
        adc #$06
nib_d
        adc #$30
        jmp CHROUT

s_done  .text "DONE=", 0
s_err   .text " ERR=", 0
s_conns .text "CONNS=", 0
s_reads .text "READS=", 0
s_last  .text "LAST BLOCKS=", 0
s_events .text "RACE EVENTS=", 0
s_acted .text "ACTED=", 0
s_still .text " STILL=", 0
s_dis   .text "DIS=", 0
s_mism  .text " MISM=", 0
