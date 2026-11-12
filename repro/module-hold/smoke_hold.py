#!/usr/bin/env python3
"""Drives the hold on an Ultimate 64 Elite / U64 through the c64-test-harness package (pip install c64-test-harness;
REST, UCI and the device lock all go through it). Needs the "Command Interface" setting; the script enables it.

  U64_HOST=<ethernet address of the device> python3 smoke_hold.py --wifi-ip <WiFi address of the device> --out run.json

While it runs: Ethernet ping every 100 ms, a REST call every 200 ms, and a steady UDP stream (--rate packets/s, default 300) to
the device's WiFi address, so that the host's WiFi transmit path stays busy. Legs, in this order:
  ident     03 E5 00 00 00 00        "00,OK" + 8 data bytes: the hold module is installed ("99,HOLD NOT SUPPORTED": it is not)
  h1071     3 x 3000 ms hold, RTS on (--plan full only); ping gap / loss and REST latency per hold
  rts_on    1 x 1500 ms hold, RTS on
  rts_off   1 x (--plan full) or 2 x (--plan 1500) 1500 ms hold with bit 31 set (RTS off); last, because on a build without
            the #1078 fix it can leave the module dead
  after     asks the module again (03 E5 0) and pings the WiFi address
The end-of-hold event (Ev 6E) is a console line, not a reply: with --boot the script sets "Log to Syslog Server" to this
machine (--syslog-port), saves the config, reboots the device (only valid when the device runs from flash; a JTAG RAM load
survives a soft reboot) and reads the lines from the syslog; without --boot read it on the console. The syslog setting is
put back (blank) at the end. Result: a JSON file with the windows per hold and the 6E sequences found."""
import argparse, json, os, re, socket, subprocess, sys, threading, time

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client

CAT, ITEM = 'Network Settings', 'Log to Syslog Server'
RTS_OFF = 0x80000000


def my_ip_towards(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9)); return s.getsockname()[0]
    finally:
        s.close()


class Pinger:
    """System ping every 100 ms; the reply times give the gaps and the loss."""
    def __init__(self, ip):
        self.p = subprocess.Popen(['ping', '-i', '0.1', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.replies = []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        for line in self.p.stdout:
            m = re.search(r'icmp_seq=(\d+).*time=([\d.]+)', line)
            if m:
                self.replies.append((time.time(), float(m.group(2)), int(m.group(1))))

    def stop(self):
        self.p.terminate()

    def window(self, t0, t1):
        r = [x for x in self.replies if t0 <= x[0] <= t1]
        ts = [t0] + [x[0] for x in r] + [t1]
        gap = max(b - a for a, b in zip(ts, ts[1:]))
        seqs = sorted(x[2] for x in r)
        span = (seqs[-1] - seqs[0] + 1) if seqs else 0
        return dict(replies=len(r), max_gap_ms=round(gap * 1000, 1), max_rtt_ms=max([x[1] for x in r], default=None),
                    loss_pct=round(100.0 * (span - len(seqs)) / span, 1) if span else None)


class Stream:
    """UDP datagrams to a closed port of the device at about rate_hz (the replies are what the WiFi path transmits)."""
    def __init__(self, ip, rate_hz, size=1024, port=9):
        self.ip, self.port, self.dt, self.payload = ip, port, 1.0 / rate_hz, b'\xa5' * size
        self.sent = 0; self.stopev = threading.Event()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.t = threading.Thread(target=self.run, daemon=True); self.t.start()

    def run(self):
        nxt = time.time()
        while not self.stopev.is_set():
            try:
                self.s.sendto(self.payload, (self.ip, self.port)); self.sent += 1
            except OSError:
                pass
            nxt += self.dt
            time.sleep(max(0, nxt - time.time()))

    def stop(self):
        self.stopev.set(); self.t.join(2); self.s.close()


class RestLoop:
    def __init__(self, client):
        self.c = client; self.samples = []; self.stopev = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True); self.t.start()

    def run(self):
        while not self.stopev.is_set():
            t0 = time.time()
            try:
                self.c.get_info(); ok = True
            except Exception:
                ok = False
            self.samples.append((t0, time.time() - t0, ok))
            time.sleep(0.2)

    def stop(self):
        self.stopev.set(); self.t.join(15)

    def window(self, t0, t1):
        s = [x for x in self.samples if t0 <= x[0] <= t1]
        return dict(calls=len(s), failed=sum(1 for x in s if not x[2]), max_ms=round(max([x[1] for x in s], default=0) * 1000, 1))


class Sink:
    """UDP syslog receiver; every line is kept in a file."""
    def __init__(self, port, path):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port)); self.s.settimeout(0.5)
        self.f = open(path, 'a'); self.stop_ = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True); self.t.start()

    def run(self):
        while not self.stop_.is_set():
            try:
                data, addr = self.s.recvfrom(8192)
            except socket.timeout:
                continue
            for line in data.decode('latin-1').splitlines():
                self.f.write('%.3f %s %s\n' % (time.time(), addr[0], line)); self.f.flush()

    def close(self):
        self.stop_.set(); self.t.join(2); self.f.close(); self.s.close()


def uci_hold(t, arg):
    """03 E5 <arg u32 LE> on the network target; returns the status text."""
    import c64_test_harness.uci_network as un
    from c64_test_harness.uci_network import build_uci_command, _execute_uci_routine
    code = build_uci_command(target=un.TARGET_NETWORK, cmd=0xE5, params=arg.to_bytes(4, 'little'))
    _execute_uci_routine(t, code, timeout=15.0)  # the host waits for the module's reply only, never for the hold
    slen = t.read_memory(un._STAT_LEN_ADDR, 1)[0]
    return t.read_memory(un._STATUS_ADDR, slen).decode('ascii', 'replace') if slen else ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wifi-ip', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--rate', type=int, default=300, help='UDP packets/s to the WiFi address')
    ap.add_argument('--plan', choices=['full', '1500'], default='full')
    ap.add_argument('--boot', action='store_true', help='set + save the syslog target, reboot, expect --expect-git')
    ap.add_argument('--expect-git', help='git hash the device must report after --boot')
    ap.add_argument('--syslog-port', type=int, default=5514)
    a = ap.parse_args()
    host = os.environ['U64_HOST']
    rec = dict(host=host, started=time.strftime('%FT%T%z'), legs={}, errors=[])
    with DeviceLock(host, allow_nested=True):
        c = Ultimate64Client(host, warn_unlocked=False)
        info = c.get_info()
        rec['info'] = {k: info.get(k) for k in ('product', 'firmware_version', 'git_commit_hash')}
        was = c.get_config_item(CAT, ITEM).get('current')
        rec['syslog_was'] = was
        sink = None
        t = Ultimate64Transport(host)
        try:
            if a.boot:
                c.set_config_item(CAT, ITEM, '%s:%d' % (my_ip_towards(host), a.syslog_port))
                c.save_config_to_flash()
                c.reboot(); time.sleep(20)
                for _ in range(60):
                    try:
                        info = c.get_info(); break
                    except Exception:
                        time.sleep(3)
                rec['git_after_boot'] = info.get('git_commit_hash')
                if a.expect_git and not str(info.get('git_commit_hash', '')).startswith(a.expect_git):
                    raise RuntimeError('device runs %s after the reboot, not %s (a JTAG RAM load survives a soft reboot)'
                                       % (info.get('git_commit_hash'), a.expect_git))
                time.sleep(45)  # the module and WiFi come up
            log = a.out + '.syslog.log'
            sink = Sink(a.syslog_port, log)
            from c64_test_harness.uci_network import enable_uci
            c.set_config_item('C64 and Cartridge Settings', 'Cartridge Preference', 'Auto')
            enable_uci(c)

            def hold(arg):
                try:
                    return uci_hold(t, arg)
                except Exception as e:
                    return 'error: %r' % e

            def events():
                try:
                    return [int(m.group(1)) for m in re.finditer(r'Ev 6E.*?Seq: (\d+)', open(log, errors='replace').read())]
                except OSError:
                    return []

            rec['legs']['ident'] = hold(0)
            time.sleep(2)
            ping = Pinger(host); rest = RestLoop(c); stream = Stream(a.wifi_ip, a.rate)
            time.sleep(10)
            rec['legs']['baseline'] = dict(ping=ping.window(time.time() - 10, time.time()), rest=rest.window(time.time() - 10, time.time()))
            plan = ([('h1071', 3000)] * 3 if a.plan == 'full' else []) + [('rts_on', 1500)] + \
                   [('rts_off', 1500 | RTS_OFF)] * (1 if a.plan == 'full' else 2)
            holds = []
            for name, arg in plan:
                n0 = len(events()); h0 = time.time()
                st = hold(arg)
                time.sleep(max(0.0, (arg & ~RTS_OFF) / 1000.0 + 1.0 - (time.time() - h0)))
                h1 = time.time(); time.sleep(6)
                ev = events()[n0:]
                holds.append(dict(leg=name, arg=hex(arg), uci=st, ping=ping.window(h0, h1), rest=rest.window(h0, h1),
                                  ev6e_seq=[hex(x) for x in ev]))
            rec['legs']['holds'] = holds
            stream.stop(); rec['udp_sent'] = stream.sent
            time.sleep(3)
            rec['legs']['after'] = dict(module=hold(0), wifi_ping=subprocess.run(['ping', '-c', '3', a.wifi_ip], capture_output=True,
                                                                                text=True).stdout.splitlines()[-2:])
            ping.stop(); rest.stop()
        except Exception as e:
            rec['errors'].append(repr(e))
        finally:
            if a.boot:
                try:
                    c.set_config_item(CAT, ITEM, was or ''); c.save_config_to_flash()
                except Exception as e:
                    rec['errors'].append('restoring the syslog setting: %r' % e)
            if sink:
                sink.close()
            t.close()
    rec['finished'] = time.strftime('%FT%T%z')
    json.dump(rec, open(a.out, 'w'), indent=1)
    print(json.dumps(rec, indent=1))


if __name__ == '__main__':
    main()
