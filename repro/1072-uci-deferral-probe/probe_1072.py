#!/usr/bin/env python3
"""probe_1072.py: hardware probe for the UCI deferral change (GideonZ/1541ultimate#1072).

A stub HTTP server on the PC stalls a UCI HTTP exchange (target 6, DO_EXCHANGE_RAW, handle from HEADER_CREATE). Then
either the C64 ABORTs it, or the PC resets the C64. A small 6502 routine measures with CIA2 timers (1 ms ticks at NTSC
PHI2) how long the interface takes to be idle again, and whether the next program's first UCI command (target 4
IDENTIFY, pushed with NO abort preamble, as a program that just started would) succeeds. See README.md.

    python3 probe_1072.py selftest                      offline: assembles the routines, exercises the stub server
    python3 probe_1072.py dump DIR                      write the three routines as .prg (load address $2000) + .hex
    python3 probe_1072.py run --host <ultimate-ip> [--legs abort,reset,late] [--out probe_1072.jsonl]
                              [--expect-git <hash>] [--no-config]

The device must already run the firmware under test (this script loads nothing and flashes nothing). --expect-git
refuses to run if the device's git_commit_hash (REST /v1/info) does not start with the given hash.

Legs:
  abort  push the exchange; after 2 s of stall the C64 writes ABORT and times ABORT -> state 00 (no abort bit).
         Then IDENTIFY on target 4.   RED (master, 30 s receive timeout): ~28000 ms (the rest of the receive
         timeout), then IDENTIFY OK.   GREEN: < 50 ms, IDENTIFY OK, the stub sees the device close the socket < 300 ms
         after the abort.
  reset  push the exchange and return to BASIC; after 2 s the PC resets the C64; at READY a probe routine reads the
         status byte and pushes IDENTIFY.   RED: initial status shows state 01 (BUSY), the push sets ERROR (busy), the
         probe waits ~25 s for idle and retries (tries=2).   GREEN: initial status idle, tries=1, reply < 50 ms.
  late   push the exchange; the stub answers 4 s after the request; the C64 aborts after 1 s; 2 s after the late
         answer a probe runs.   RED: abort ~3000 ms (it waits for the answer).   GREEN: abort < 50 ms. Both: the
         probe finds the interface idle (no unsolicited state 10 from the late result) and IDENTIFY succeeds.

Unless --no-config is given it sets, at runtime and not saved: CPU Speed 1, Turbo Control Off, System Mode NTSC,
Command Interface Enabled, reads each back, and records them. The C64 is reset at the end.

Needs the c64-test-harness (pip install, see README.md) for the REST client, memory access and key injection.
"""
import argparse, json, os, socket, sys, threading, time

HTTP, CONTROL = 6, 4
CMD_FREE_ALL, CMD_HDR_CREATE, CMD_EXCH_RAW = 0x10, 0x11, 0x32
VERB_GET = 1
CODE = 0x2000
# data area (the harness uci() helper uses $C200-$C3FF; these stay clear of what it reads back)
CMD_LEN, CMD_BYTES = 0xC0BF, 0xC0C0
PUSHED, GO = 0xC0E0, 0xC0E1
RES_LO, RES_HI, RES_STATUS, RES_TIMEOUT = 0xC0E2, 0xC0E3, 0xC0E4, 0xC0E5
P_INITIAL, P_AFTER, P_TRIES, P_RESP_LEN, P_RESP = 0xC0E6, 0xC0E7, 0xC0E8, 0xC0E9, 0xC100
SENTINEL, DONE = 0xC0FE, 0x42
SYS_KEYS = [ord(c) for c in 'SYS 8192'] + [0x0D]
CTRL, CMD, RESP_REG = 0xDF1C, 0xDF1D, 0xDF1E
TIMER_CAP_MS = 60000
NTSC_CYCLES_PER_MS = 1023                     # 1.0227 MHz


# ------------------------------------------------------------------ 6502 routines
def _asm():
    from c64_test_harness.bridge_ping import Asm
    return Asm(org=CODE)


def _sta(a, addr):
    a.emit(0x8D, addr & 0xFF, addr >> 8)


def _lda_abs(a, addr):
    a.emit(0xAD, addr & 0xFF, addr >> 8)


def _lda_imm(a, v):
    a.emit(0xA9, v & 0xFF)


def _timer_start(a):
    """CIA2 timer A: 1 ms underflows; timer B counts them down from 65535."""
    for reg, v in ((0xDD04, (NTSC_CYCLES_PER_MS - 1) & 0xFF), (0xDD05, (NTSC_CYCLES_PER_MS - 1) >> 8),
                   (0xDD06, 0xFF), (0xDD07, 0xFF), (0xDD0F, 0x51), (0xDD0E, 0x11)):
        _lda_imm(a, v)
        _sta(a, reg)


def _timer_check(a, timeout_label):
    """Falls through while under the cap; jumps to timeout_label when TIMER_CAP_MS has passed."""
    floor_hi = (0xFFFF - TIMER_CAP_MS) >> 8
    ok = 'under_cap_%d' % a.pos
    _lda_abs(a, 0xDD07)
    a.emit(0xC9, floor_hi)                    # CMP #floor
    a.branch(0xB0, ok)                        # BCS: still above the floor
    a.jmp(timeout_label)
    a.label(ok)


def _timer_stop_store(a):
    _lda_imm(a, 0)
    _sta(a, 0xDD0E)
    _sta(a, 0xDD0F)
    _lda_abs(a, 0xDD06)
    _sta(a, RES_LO)
    _lda_abs(a, 0xDD07)
    _sta(a, RES_HI)


def _push_command(a):
    """Writes CMD_LEN bytes from CMD_BYTES to the command register and pushes. No abort preamble."""
    a.emit(0xA2, 0x00)                        # LDX #0
    a.label('push')
    a.emit(0xBD, CMD_BYTES & 0xFF, CMD_BYTES >> 8)   # LDA CMD_BYTES,X
    _sta(a, CMD)
    a.emit(0xE8)                              # INX
    a.emit(0xEC, CMD_LEN & 0xFF, CMD_LEN >> 8)       # CPX CMD_LEN
    a.branch(0xD0, 'push')
    _lda_imm(a, 0x01)
    _sta(a, CTRL)


def _finish(a):
    _lda_imm(a, DONE)
    _sta(a, SENTINEL)
    a.emit(0x60)                              # RTS to BASIC


def build_push_only():
    """Push the exchange and return to BASIC with the interface BUSY."""
    a = _asm()
    _push_command(a)
    _lda_imm(a, 1)
    _sta(a, PUSHED)
    _finish(a)
    return a.build()


def build_push_then_abort():
    """Push; wait for the host's GO; write ABORT and time until (status & $34) == 0 (state 00, abort serviced)."""
    a = _asm()
    _push_command(a)
    _lda_imm(a, 1)
    _sta(a, PUSHED)
    a.label('wait_go')
    _lda_abs(a, GO)
    a.branch(0xF0, 'wait_go')                 # BEQ
    _timer_start(a)
    _lda_imm(a, 0x04)
    _sta(a, CTRL)                             # ABORT
    a.label('poll')
    _lda_abs(a, CTRL)
    a.emit(0x29, 0x34)                        # AND #$34
    a.branch(0xF0, 'idle')
    _timer_check(a, 'timeout')
    a.jmp('poll')
    a.label('timeout')
    _lda_imm(a, 1)
    _sta(a, RES_TIMEOUT)
    a.label('idle')
    _timer_stop_store(a)
    _lda_abs(a, CTRL)
    _sta(a, RES_STATUS)
    _finish(a)
    return a.build()


def build_settle():
    """Wait (up to TIMER_CAP_MS) until the interface is idle, without touching it; time it."""
    a = _asm()
    _timer_start(a)
    a.label('poll')
    _lda_abs(a, CTRL)
    a.emit(0x29, 0x30)
    a.branch(0xF0, 'idle')
    _timer_check(a, 'timeout')
    a.jmp('poll')
    a.label('timeout')
    _lda_imm(a, 1)
    _sta(a, RES_TIMEOUT)
    a.label('idle')
    _timer_stop_store(a)
    _finish(a)
    return a.build()


def settle(t):
    t.write_memory(RES_TIMEOUT, bytes([0]))
    run_routine(t, build_settle())
    return dict(ms=elapsed_ms(t), timed_out=bool(t.read_memory(RES_TIMEOUT, 1)[0]))


def build_probe():
    """A program's first UCI command: read the status, push target-4 IDENTIFY without an abort preamble. On ERROR
    (busy) clear it, wait for state 00 and push again. Times the whole thing; reads up to 32 reply bytes."""
    a = _asm()
    _lda_abs(a, CTRL)
    _sta(a, P_INITIAL)
    _timer_start(a)
    a.label('retry')
    _push_command(a)
    a.emit(0xEE, P_TRIES & 0xFF, P_TRIES >> 8)        # INC P_TRIES
    _lda_abs(a, CTRL)
    _sta(a, P_AFTER)
    a.emit(0x29, 0x08)                        # AND #$08 (ERROR)
    a.branch(0xF0, 'wait_reply')
    _lda_imm(a, 0x08)
    _sta(a, CTRL)                             # clear the error
    a.label('wait_idle')
    _timer_check(a, 'timeout')
    _lda_abs(a, CTRL)
    a.emit(0x29, 0x30)
    a.branch(0xD0, 'wait_idle')
    a.jmp('retry')
    a.label('wait_reply')
    _timer_check(a, 'timeout')
    _lda_abs(a, CTRL)
    a.emit(0x29, 0x20)                        # state 1x: a reply is there
    a.branch(0xF0, 'wait_reply')
    a.emit(0xA2, 0x00)                        # LDX #0
    a.label('read')
    _lda_abs(a, CTRL)
    a.branch(0x10, 'read_done')               # BPL: no DATA_AV
    _lda_abs(a, RESP_REG)
    a.emit(0x9D, P_RESP & 0xFF, P_RESP >> 8)  # STA P_RESP,X
    a.emit(0xE8)
    a.emit(0xE0, 32)                          # CPX #32
    a.branch(0xD0, 'read')
    a.label('read_done')
    a.emit(0x8E, P_RESP_LEN & 0xFF, P_RESP_LEN >> 8)  # STX P_RESP_LEN
    _lda_imm(a, 0x02)
    _sta(a, CTRL)                             # acknowledge
    a.jmp('stop')
    a.label('timeout')
    _lda_imm(a, 1)
    _sta(a, RES_TIMEOUT)
    a.label('stop')
    _timer_stop_store(a)
    _finish(a)
    return a.build()


# ------------------------------------------------------------------ stub server
LIVE_STUBS = []   # every stub this run started; run() closes them all, also after an error


class StubServer:
    """One connection. mode 'stall': read the request, never answer. mode 'late': answer `late_s` after the request.
    Records when the request was complete and when the device closed the socket (time.monotonic())."""

    def __init__(self, mode='stall', late_s=4.0):
        self.mode, self.late_s = mode, late_s
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(('0.0.0.0', 0))
        self.ls.listen(1)
        self.port = self.ls.getsockname()[1]
        self.t_request = self.t_answer = self.t_closed = None
        self.stop = False
        LIVE_STUBS.append(self)
        self.th = threading.Thread(target=self._serve, daemon=True)
        self.th.start()

    def _serve(self):
        self.ls.settimeout(120)
        try:
            c, _ = self.ls.accept()
        except OSError:
            return
        c.settimeout(0.05)
        buf, deadline = b'', time.monotonic() + 120
        while time.monotonic() < deadline and not self.stop:
            if self.t_request and self.mode == 'late' and not self.t_answer and \
                    time.monotonic() - self.t_request >= self.late_s:
                try:
                    c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlate')
                except OSError:
                    pass
                self.t_answer = time.monotonic()
            try:
                d = c.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                d = b''
            if not d:
                self.t_closed = time.monotonic()
                break
            buf += d
            if not self.t_request and b'\r\n\r\n' in buf:
                self.t_request = time.monotonic()
        c.close()

    def close(self):
        """End of the leg: the stub closes its side, so an image without a receive timeout ends the
        exchange (EOF) instead of holding the interface into the next leg."""
        self.stop = True
        self.th.join(1.0)
        try:
            self.ls.close()
        except OSError:
            pass

    def wait_request(self, timeout=30):
        end = time.monotonic() + timeout
        while not self.t_request and time.monotonic() < end:
            time.sleep(0.02)
        return self.t_request is not None

    def wait_closed(self, timeout):
        end = time.monotonic() + timeout
        while not self.t_closed and time.monotonic() < end:
            time.sleep(0.02)
        return self.t_closed


def my_ip_towards(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, 9))
    ip = s.getsockname()[0]
    s.close()
    return ip


# ------------------------------------------------------------------ device steps
def run_routine(t, code, keys=True, wait=True, timeout=75.0):
    t.write_memory(SENTINEL, bytes([0]))
    t.write_memory(CODE, code)
    if keys:
        t.inject_keys(SYS_KEYS)
    if not wait:
        return True
    end = time.time() + timeout
    while t.read_memory(SENTINEL, 1)[0] != DONE:
        if time.time() > end:
            return False
        time.sleep(0.05)
    return True


def set_command(t, cmd):
    t.write_memory(CMD_LEN, bytes([len(cmd)]))
    t.write_memory(CMD_BYTES, bytes(cmd))


def elapsed_ms(t):
    lo, hi = t.read_memory(RES_LO, 2)
    return 0xFFFF - (lo | (hi << 8))


def prepare_header(t, url):
    """FREE_ALL + HEADER_CREATE through the harness's own UCI routine; returns the header handle."""
    from c64_test_harness import build_uci_command
    def uci(cmd, params):
        r = build_uci_command(target=HTTP, cmd=cmd, params=bytes(params), resp_addr=0xC200, status_addr=0xC300,
                              resp_len_addr=0xC3F0, stat_len_addr=0xC3F2, error_addr=0xC3FF, sentinel_addr=0xC3FE,
                              code_addr=CODE, turbo_safe=False)
        t.write_memory(0xC3FE, bytes([0, 0]))
        t.write_memory(CODE, r)
        t.inject_keys(SYS_KEYS)
        end = time.time() + 20
        while t.read_memory(0xC3FE, 1)[0] != DONE:
            if time.time() > end:
                raise TimeoutError('UCI %02x did not finish' % cmd)
            time.sleep(0.05)
        n = int.from_bytes(t.read_memory(0xC3F0, 2), 'little')
        return t.read_memory(0xC200, n) if n else b''
    uci(CMD_FREE_ALL, [])
    rep = uci(CMD_HDR_CREATE, [VERB_GET] + list(url.encode()))
    if len(rep) != 1:
        raise RuntimeError('HEADER_CREATE returned %r' % rep)
    return rep[0]


def probe(t):
    for addr in (P_TRIES, RES_TIMEOUT, P_RESP_LEN):
        t.write_memory(addr, bytes([0]))
    set_command(t, [CONTROL, 0x01])
    finished = run_routine(t, build_probe())
    n = t.read_memory(P_RESP_LEN, 1)[0]
    initial, after, tries = t.read_memory(P_INITIAL, 3)
    return dict(finished=finished, ms=elapsed_ms(t), initial_status='%02x' % initial, after_push='%02x' % after,
                tries=tries, timed_out=bool(t.read_memory(RES_TIMEOUT, 1)[0]),
                reply=t.read_memory(P_RESP, n).decode('ascii', 'replace') if n else '')


def leg_abort(t, url_host, mode='stall', go_after=2.0):
    srv = StubServer(mode=mode)
    url = 'http://%s:%d/x25' % (url_host, srv.port)
    hdr = prepare_header(t, url)
    for addr in (PUSHED, GO, RES_TIMEOUT):
        t.write_memory(addr, bytes([0]))
    set_command(t, [HTTP, CMD_EXCH_RAW, hdr, 0xFF])
    run_routine(t, build_push_then_abort(), wait=False)
    got_request = srv.wait_request(30)
    time.sleep(go_after)
    t_go = time.monotonic()
    t.write_memory(GO, bytes([1]))
    end = time.time() + 75
    while t.read_memory(SENTINEL, 1)[0] != DONE and time.time() < end:
        time.sleep(0.05)
    rec = dict(server_got_request=got_request, abort_ms=elapsed_ms(t),
               abort_timed_out=bool(t.read_memory(RES_TIMEOUT, 1)[0]),
               status_after='%02x' % t.read_memory(RES_STATUS, 1)[0])
    if mode == 'late':
        srv.wait_closed(15)                   # base: after the late answer; X25: within a slice of the abort
        time.sleep(2.0)                       # a late result, if any were sent, would show by now
    closed = srv.wait_closed(3.0 if mode == 'stall' else 0.1)
    rec['device_closed_socket_ms_after_go'] = round((closed - t_go) * 1000) if closed else None
    rec['server_answered'] = srv.t_answer is not None
    rec['probe'] = probe(t)
    srv.close()
    return rec


def leg_reset(t, url_host, boot_s=3.0):
    srv = StubServer(mode='stall')
    url = 'http://%s:%d/x25' % (url_host, srv.port)
    hdr = prepare_header(t, url)
    t.write_memory(PUSHED, bytes([0]))
    set_command(t, [HTTP, CMD_EXCH_RAW, hdr, 0xFF])
    run_routine(t, build_push_only())
    got_request = srv.wait_request(30)
    time.sleep(2.0)
    t_reset = time.monotonic()
    t.reset(scope='cpu')
    time.sleep(boot_s)                        # BASIC READY
    p = probe(t)
    closed = srv.wait_closed(1.0)
    srv.close()
    return dict(server_got_request=got_request, boot_wait_s=boot_s, probe=p,
                ready_ms_after_reset=round((time.monotonic() - t_reset) * 1000),
                device_closed_socket_ms_after_reset=round((closed - t_reset) * 1000) if closed else None)


def verdict(leg, rec):
    p = rec['probe']
    probe_ok = p['finished'] and not p['timed_out'] and p['tries'] == 1 and p['reply'] != ''
    if leg == 'reset':
        return 'GREEN' if probe_ok and int(p['initial_status'], 16) & 0x30 == 0 and p['ms'] < 50 else 'RED'
    good = not rec['abort_timed_out'] and rec['abort_ms'] < 50 and probe_ok
    return 'GREEN' if good else 'RED'


WANT = [('U64 Specific Settings', 'CPU Speed', '1'), ('U64 Specific Settings', 'Turbo Control', 'Off'),
        ('U64 Specific Settings', 'System Mode', 'NTSC'), ('C64 and Cartridge Settings', 'Command Interface', 'Enabled')]


def cfg_apply(client):
    """Set each item at runtime (not saved), spelled as the device lists it, and read it back."""
    out, ok = {}, True
    for cat, item, want in WANT:
        values = client.get_config_item(cat, item).get('values') or []
        hit = [v for v in values if str(v).strip() == want]
        value = hit[0] if len(hit) == 1 else want
        client.set_config_item(cat, item, value)
        got = client.get_config_item(cat, item).get('current')
        good = str(got).strip() == want
        ok = ok and good
        out['%s / %s' % (cat, item)] = dict(want=want, set_as=value, read_back=got, ok=good)
    return dict(items=out, ok=ok)


def locked(host, fn):
    """Hold the harness's cross-process DeviceLock for the host while fn() runs (other harness users queue)."""
    from c64_test_harness.backends.device_lock import DeviceLock
    with DeviceLock(host, allow_nested=True):
        return fn()


def run(args):
    from c64_test_harness.backends.ultimate64 import Ultimate64Transport
    host = args.host

    def body():
        from c64_test_harness.backends.ultimate64_client import Ultimate64Client
        info = Ultimate64Client(host, warn_unlocked=False).get_info()
        git = info.get('git_commit_hash') or ''
        if args.expect_git and not git.startswith(args.expect_git[:7]):
            raise SystemExit('loaded image reports git %r, expected %r' % (git, args.expect_git))
        client = Ultimate64Client(host, warn_unlocked=False)
        cfg = dict(skipped=True)
        if not args.no_config:
            cfg = cfg_apply(client)
            if not cfg['ok']:
                raise SystemExit('config read-back differs: %r' % cfg)
        time.sleep(3.0)
        t = Ultimate64Transport(host=host)
        url_host = my_ip_towards(host)
        worst = 0
        try:
            for leg in args.legs.split(','):
                t.reset(scope='cpu')
                time.sleep(3.0)
                rec = dict(when=time.strftime('%Y-%m-%dT%H:%M:%S'), host=host, leg=leg,
                           device=dict(firmware=info.get('firmware_version'), core=info.get('core_version'), git=git),
                           config=cfg)
                # The previous leg's exchange must be over (its stub is closed); an image without a
                # receive timeout would otherwise still be BUSY here.
                rec['settle_before'] = settle(t)
                try:
                    if leg == 'abort':
                        rec.update(leg_abort(t, url_host))
                    elif leg == 'late':
                        rec.update(leg_abort(t, url_host, mode='late', go_after=1.0))
                    elif leg == 'reset':
                        rec.update(leg_reset(t, url_host))
                    else:
                        raise SystemExit('unknown leg %s' % leg)
                    rec['verdict'] = verdict(leg, rec)
                except Exception as e:     # an error row, not a lost one
                    rec['error'] = repr(e)
                    rec['verdict'] = 'ERROR'
                    t.reset(scope='cpu')
                    time.sleep(3.0)
                worst |= rec['verdict'] != 'GREEN'
                with open(args.out, 'a') as f:
                    f.write(json.dumps(rec) + '\n')
                print(json.dumps(rec, indent=1))
        finally:
            for stub in LIVE_STUBS:           # the stub HTTP servers on this Mac end with the run
                stub.close()
            del LIVE_STUBS[:]
            t.reset(scope='cpu')              # leave BASIC with no routine running
        return 1 if worst else 0
    return body() if args.no_lock else locked(host, body)


def selftest():
    for name, build in (('push_only', build_push_only), ('push_then_abort', build_push_then_abort),
                        ('probe', build_probe), ('settle', build_settle)):
        code = build()
        assert 0 < len(code) < 0x100, name
        print('%-16s %3d bytes  %s' % (name, len(code), code.hex()))
    # the stub server: a stall leg and a late leg against a local client
    for mode in ('stall', 'late'):
        srv = StubServer(mode=mode, late_s=0.5)
        c = socket.create_connection(('127.0.0.1', srv.port))
        c.sendall(b'GET /x25 HTTP/1.1\r\nHost: x\r\n\r\n')
        assert srv.wait_request(2), mode
        c.settimeout(1.5)
        try:
            got = c.recv(100)
        except socket.timeout:
            got = b''
        assert (got != b'') == (mode == 'late'), (mode, got)
        t0 = time.monotonic()
        c.close()
        closed = srv.wait_closed(2)
        assert closed and closed - t0 < 0.5, mode
        print('stub server %-5s ok (answer %r, close seen after %.0f ms)' % (mode, got[:12], (closed - t0) * 1000))
    print('selftest ok')
    return 0


def dump(d):
    """Write each routine as NAME.prg (2-byte load address $2000 + code) and NAME.hex."""
    os.makedirs(d, exist_ok=True)
    for name, build in (('push_only', build_push_only), ('push_then_abort', build_push_then_abort),
                        ('probe', build_probe), ('settle', build_settle)):
        code = build()
        with open(os.path.join(d, name + '.prg'), 'wb') as f:
            f.write(bytes([CODE & 0xFF, CODE >> 8]) + code)
        with open(os.path.join(d, name + '.hex'), 'w') as f:
            f.write(code.hex() + '\n')
        print('%-16s %3d bytes' % (name, len(code)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='what', required=True)
    sub.add_parser('selftest')
    r = sub.add_parser('run')
    r.add_argument('--host', required=True, help='address of the Ultimate (REST + UCI)')
    r.add_argument('--expect-git', help='refuse to run unless /v1/info git_commit_hash starts with this')
    r.add_argument('--legs', default='abort,reset,late')
    r.add_argument('--out', default='probe_1072.jsonl')
    r.add_argument('--no-config', action='store_true', help='do not set CPU Speed/Turbo/NTSC/Command Interface')
    r.add_argument('--no-lock', action='store_true', help='do not take the harness DeviceLock')
    d = sub.add_parser('dump')
    d.add_argument('dir')
    args = ap.parse_args()
    if args.what == 'dump':
        return dump(args.dir)
    return selftest() if args.what == 'selftest' else run(args)


if __name__ == '__main__':
    sys.exit(main())
