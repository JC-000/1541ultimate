; net.inc -- the C64 network driver ABI (one connected UDP socket to one peer).
;
; uci.s (Ultimate 64 / C64 Ultimate / 1541 Ultimate Command Interface) exports these symbols.
;
; The shape follows c64-wireguard's src/net_abi.inc (MIT, JC-000), cut down to what a
; lockstep game needs and made fully asynchronous: nothing here ever waits. net_poll does at
; most one unit of I/O per call and returns; the session layer calls it once per frame.
;
;   net_init    probe/initialise the device.            out: C=0 ok; C=1 no device (net_err)
;   net_open    connect to net_peer_ip / net_peer_port. Returns at once; the socket is usable
;               when net_status has NET_ST_OPEN (a backend retries a refused open itself).
;   net_poll    one step of I/O; once per frame.        out: C=1 on a backend error (net_err);
;               a datagram may have arrived either way (look at net_rx_len, never at C)
;   net_close   drop the socket (asynchronous on UCI; the open flag clears at once)
;
; Buffers (owned by the backend, filled/emptied by the caller):
;   net_tx_buf / net_tx_len   caller fills the buffer, then stores the length (1..NET_TX_MAX)
;                             LAST; the backend clears net_tx_len once the datagram is gone.
;                             Never touch the buffer while net_tx_len != 0.
;   net_rx_buf / net_rx_len   the backend stores one datagram and sets net_rx_len (1..NET_RX_MAX)
;                             LAST; the caller clears net_rx_len when done. Nothing more is
;                             received while net_rx_len != 0. Longer datagrams are dropped.
;   net_rx_want               caller: non-zero while a datagram is expected. The UCI backend
;                             issues a READ only then (an empty READ blocks the Command
;                             Interface ~40 ms on firmware whose READ waits).
;
; Rules: not re-entrant, never call from an interrupt; all calls clobber A, X, Y.
; Cost per call is bounded by the datagram size (no busy-waiting on the network).

.ifndef NET_INC
NET_INC = 1

NET_TX_MAX      = 64
NET_RX_MAX      = 64

; net_status bits
NET_ST_PRESENT  = $01           ; net_init found the device
NET_ST_OPEN     = $02           ; socket connected; sends/reads can run
NET_ST_FREE_READ= $04           ; a read that finds nothing does not hold the device (the UCI
                                ; backend sets it once an empty READ came back at once: no-wait
                                ; firmware, GideonZ/1541ultimate#962), so the session may read
                                ; whenever a reply is owed
NET_ST_ERROR    = $80           ; the last net_poll hit an error (net_err); cleared next poll

; net_err codes (backend-neutral)
NET_ERR_NONE    = $00
NET_ERR_NODEV   = $01           ; no device / interface disabled
NET_ERR_OPEN    = $02           ; open refused (retried)
NET_ERR_SEND    = $03           ; a datagram could not be sent (dropped)
NET_ERR_RECV    = $04           ; a malformed / short / over-long reply was dropped
NET_ERR_WEDGE   = $05           ; the device did not finish a command in time (aborted)

; net_stats: 16-bit little-endian counters since net_init (diagnostics; read by run_pair.py
; through the demo's status block). A backend that has no such event leaves it 0.
NET_STAT_WRITES   = 0           ; datagrams handed to the device
NET_STAT_READS    = 2           ; read commands issued (UCI)
NET_STAT_EMPTY    = 4           ; reads that found nothing (UCI's empty-read stall)
NET_STAT_ERRORS   = 6           ; net_err events
NET_STAT_DEFERRED = 8           ; net_poll calls that returned with a datagram still waiting
NET_STAT_RX       = 10          ; datagrams delivered to net_rx_buf
NET_STATS_SIZE    = 12

.macro INC16 addr          ; addr must be absolute (no labels: keeps @-local scopes intact)
        inc addr
        bne *+5
        inc addr + 1
.endmacro

.ifndef NET_IMPL
        .import net_stats
        .import net_init, net_open, net_poll, net_close
        .import net_tx_buf, net_tx_len, net_rx_buf, net_rx_len, net_rx_want
        .import net_peer_ip, net_peer_port, net_status, net_err
.endif

.endif
