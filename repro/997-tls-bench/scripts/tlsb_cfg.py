#!/usr/bin/env python3
"""tlsb_cfg.py: SET the device settings a tls-bench leg needs, read each back, record (harness public API only).
    python3 -I tlsb_cfg.py set turbo|slow [--host H] [--out cfg.json]     turbo = Turbo Control Manual + CPU Speed 48; slow = Turbo Control Off only (that is 1 MHz; the read-back of Turbo Control = Off is the record)
    python3 -I tlsb_cfg.py show [--out f]    python3 -I tlsb_cfg.py selftest
Both profiles also set: WiFi Enabled = Enabled (entropy for the ESP build; one-way
on the U64E), SNTP Enable = Enabled (CUSTOM trust needs trusted time), Command Interface = Enabled. System Mode (PAL/NTSC) is NOT changed: it is read and recorded with its PHI2, which every timing conversion uses. Runtime only, nothing saved
to flash. Exit 1 on any read-back difference.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tlsb

U64 = 'U64 Specific Settings'
COMMON = [('WiFi settings', 'WiFi Enabled', 'Enabled'),
          ('Network Settings', 'SNTP Enable', 'Enabled'), ('C64 and Cartridge Settings', 'Command Interface', 'Enabled')]
PROFILES = {'turbo': [(U64, 'Turbo Control', 'Manual'), (U64, 'CPU Speed', '48')],
            'slow': [(U64, 'Turbo Control', 'Off')]}   # Turbo Off IS 1 MHz and disables CPU Speed (an exact-enum REST write of '1' would 400: the value is ' 1')


def norm(v):
    return str(v).strip().lower()


def apply(c, items):
    rec = []
    for cat, item, want in items:
        c.set_config_item(cat, item, want)
        got = c.get_config_value(cat, item)
        rec.append({'category': cat, 'item': item, 'want': want, 'got': str(got).strip(), 'ok': norm(got) == norm(want)})
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('cmd', choices=['set', 'show', 'selftest'])
    ap.add_argument('profile', nargs='?', choices=list(PROFILES))
    ap.add_argument('--host', default=tlsb.DEFAULT_HOST)
    ap.add_argument('--out')
    a = ap.parse_args()
    if a.cmd != 'selftest':
        tlsb.need_host(ap, a.host)
    if a.cmd == 'selftest':
        class F:      # rejects values that are not exact enum members, like the REST route
            ENUM = {'Turbo Control': {'Off', 'Manual'}, 'CPU Speed': {' 1', ' 2', ' 3', '48'}, 'WiFi Enabled': {'Enabled', 'Disabled'},
                    'SNTP Enable': {'Enabled', 'Disabled'}, 'Command Interface': {'Enabled', 'Disabled'}}
            def __init__(s): s.v = {}
            def set_config_item(s, cat, item, val):
                if val not in s.ENUM[item]: raise ValueError('400 %s=%r' % (item, val))
                s.v[(cat, item)] = val
            def get_config_value(s, cat, item): return s.v.get((cat, item), 'NTSC')
        r = apply(F(), COMMON + PROFILES['slow'])
        assert all(x['ok'] for x in r) and len(r) == 4 and r[-1]['item'] == 'Turbo Control' and r[-1]['got'] == 'Off'
        try:
            apply(F(), [(U64, 'CPU Speed', '1')]); raise SystemExit('fake accepted CPU Speed 1')
        except ValueError: pass
        for bad in ('PAL-60', 'NTSC-50', 'pal', 'PAL '+'x'):
            try: tlsb.phi2_for_mode(bad); raise SystemExit('accepted ' + bad)
            except ValueError: pass
        assert tlsb.phi2_for_mode(' NTSC ') == 1022727.0 and tlsb.phi2_for_mode('PAL') == 985248.0
        assert tlsb.read_phi2(F())[0] == 1022727.0
        print('selftest ok'); return 0
    items = COMMON + PROFILES[a.profile] if a.cmd == 'set' else COMMON + PROFILES['turbo']
    def body():
        c = tlsb.client(a.host)
        if a.cmd == 'show':
            return [{'category': k, 'item': i, 'got': str(c.get_config_value(k, i)).strip()} for k, i, _ in items]
        return apply(c, items)
    def body2():
        c = tlsb.client(a.host)
        r = body()
        phi2, mode = tlsb.read_phi2(c)
        return {'profile': a.profile, 'items': r, 'system_mode': mode, 'phi2_hz': phi2} if a.cmd == 'set' else {'items': r, 'system_mode': mode, 'phi2_hz': phi2}
    rec = tlsb.locked(a.host, body2)
    if a.out:
        json.dump(rec, open(a.out, 'w'), indent=1)
    print(json.dumps(rec, indent=1))
    return 0 if all(x.get('ok', True) for x in rec['items']) else 1

if __name__ == '__main__':
    sys.exit(main())
