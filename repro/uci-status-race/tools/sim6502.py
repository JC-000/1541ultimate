#!/usr/bin/env python3
"""A small 6502 interpreter (documented NMOS opcodes) with a mock Ultimate Command Interface,
used to run probe.prg off-device. It checks the PRG's logic (command bytes, reply parsing,
byte check, result block layout, error paths). It does NOT check real UCI timing, the real
firmware's answers, or the race itself: those are the device's job.

Cycle counts are per-instruction base counts without page-crossing penalties, which is all the
timers here need (they only have to be monotonic and proportional).
"""

import struct

# opcode -> (mnemonic, mode, cycles); built from the aaabbbcc scheme for the groups used.
IMP, IMM, ZP, ZPX, ZPY, ABS, ABX, ABY, IND, INX, INY, ACC, REL = range(13)
OPS = {}


def _add(op, name, mode, cyc):
    OPS[op] = (name, mode, cyc)


_G1 = ["ora", "and", "eor", "adc", "sta", "lda", "cmp", "sbc"]
_G1_MODES = {0: INX, 1: ZP, 2: IMM, 3: ABS, 4: INY, 5: ZPX, 6: ABY, 7: ABX}
for a, n in enumerate(_G1):
    for b, m in _G1_MODES.items():
        if n == "sta" and m == IMM:
            continue
        _add((a << 5) | (b << 2) | 1, n, m, 4)
_G2 = ["asl", "rol", "lsr", "ror", "stx", "ldx", "dec", "inc"]
_G2_MODES = {1: ZP, 2: ACC, 3: ABS, 5: ZPX, 7: ABX}
for a, n in enumerate(_G2):
    for b, m in _G2_MODES.items():
        if n in ("stx", "ldx"):
            if b == 2 and n == "stx":
                continue
            if b == 2:
                continue
            if b == 5:
                m = ZPY
            if b == 7:
                if n == "stx":
                    continue
                m = ABY
        if n in ("dec", "inc") and b == 2:
            continue
        _add((a << 5) | (b << 2) | 2, n, m, 5)
_add(0xA2, "ldx", IMM, 2)
_G3 = {0xA0: ("ldy", IMM), 0xA4: ("ldy", ZP), 0xAC: ("ldy", ABS), 0xB4: ("ldy", ZPX),
       0xBC: ("ldy", ABX), 0x84: ("sty", ZP), 0x8C: ("sty", ABS), 0x94: ("sty", ZPX),
       0xC0: ("cpy", IMM), 0xC4: ("cpy", ZP), 0xCC: ("cpy", ABS),
       0xE0: ("cpx", IMM), 0xE4: ("cpx", ZP), 0xEC: ("cpx", ABS),
       0x4C: ("jmp", ABS), 0x20: ("jsr", ABS), 0x24: ("bit", ZP), 0x2C: ("bit", ABS)}
for op, (n, m) in _G3.items():
    _add(op, n, m, 4)
for op, n in {0x10: "bpl", 0x30: "bmi", 0x50: "bvc", 0x70: "bvs", 0x90: "bcc", 0xB0: "bcs",
              0xD0: "bne", 0xF0: "beq"}.items():
    _add(op, n, REL, 2)
for op, n in {0x18: "clc", 0x38: "sec", 0x58: "cli", 0x78: "sei", 0xB8: "clv", 0xD8: "cld",
              0xF8: "sed", 0xAA: "tax", 0x8A: "txa", 0xA8: "tay", 0x98: "tya", 0xBA: "tsx",
              0x9A: "txs", 0xE8: "inx", 0xCA: "dex", 0xC8: "iny", 0x88: "dey", 0x48: "pha",
              0x68: "pla", 0x08: "php", 0x28: "plp", 0x60: "rts", 0xEA: "nop"}.items():
    _add(op, n, IMP, 2)


class Halt(Exception):
    pass


class CPU:
    def __init__(self, mem):
        self.m = mem                    # object with read(addr) / write(addr, v)
        self.a = self.x = self.y = 0
        self.sp = 0xFF
        self.pc = 0
        self.c = self.z = self.n = self.v = self.i = self.d = 0
        self.cycles = 0

    def r(self, a):
        return self.m.read(a & 0xFFFF)

    def w(self, a, v):
        self.m.write(a & 0xFFFF, v & 0xFF)

    def push(self, v):
        self.w(0x100 + self.sp, v)
        self.sp = (self.sp - 1) & 0xFF

    def pull(self):
        self.sp = (self.sp + 1) & 0xFF
        return self.r(0x100 + self.sp)

    def nz(self, v):
        v &= 0xFF
        self.z = int(v == 0)
        self.n = v >> 7
        return v

    def fetch(self):
        v = self.r(self.pc)
        self.pc = (self.pc + 1) & 0xFFFF
        return v

    def addr(self, mode):
        if mode == ZP:
            return self.fetch()
        if mode == ZPX:
            return (self.fetch() + self.x) & 0xFF
        if mode == ZPY:
            return (self.fetch() + self.y) & 0xFF
        if mode == ABS:
            lo = self.fetch()
            return lo | (self.fetch() << 8)
        if mode == ABX:
            lo = self.fetch()
            return ((lo | (self.fetch() << 8)) + self.x) & 0xFFFF
        if mode == ABY:
            lo = self.fetch()
            return ((lo | (self.fetch() << 8)) + self.y) & 0xFFFF
        if mode == INX:
            z = (self.fetch() + self.x) & 0xFF
            return self.r(z) | (self.r((z + 1) & 0xFF) << 8)
        if mode == INY:
            z = self.fetch()
            return ((self.r(z) | (self.r((z + 1) & 0xFF) << 8)) + self.y) & 0xFFFF
        raise ValueError(mode)

    def flags(self):
        return (self.c | self.z << 1 | self.i << 2 | self.d << 3 | 0x30 | self.v << 6 | self.n << 7)

    def setflags(self, f):
        self.c, self.z, self.i, self.d, self.v, self.n = f & 1, f >> 1 & 1, f >> 2 & 1, f >> 3 & 1, f >> 6 & 1, f >> 7 & 1

    def adc(self, v):
        assert not self.d
        s = self.a + v + self.c
        self.v = int(~(self.a ^ v) & (self.a ^ s) & 0x80 != 0)
        self.c = int(s > 0xFF)
        self.a = self.nz(s)

    def cmp(self, reg, v):
        s = reg - v
        self.c = int(reg >= v)
        self.nz(s)

    def step(self):
        op = self.fetch()
        if op not in OPS:
            raise Halt(f"bad opcode {op:02X} at {self.pc - 1:04X}")
        n, mode, cyc = OPS[op]
        self.cycles += cyc
        if mode == REL:
            off = self.fetch()
            off = off - 256 if off > 127 else off
            take = {"bpl": not self.n, "bmi": self.n, "bvc": not self.v, "bvs": self.v,
                    "bcc": not self.c, "bcs": self.c, "bne": not self.z, "beq": self.z}[n]
            if take:
                self.pc = (self.pc + off) & 0xFFFF
                self.cycles += 1
            return
        if mode == IMP:
            self.imp(n)
            return
        if mode == ACC:
            v = self.a
            self.a = self.rmw(n, v)
            return
        if n == "jmp":
            self.pc = self.addr(ABS)
            return
        if n == "jsr":
            t = self.addr(ABS)
            ret = (self.pc - 1) & 0xFFFF
            self.push(ret >> 8)
            self.push(ret & 0xFF)
            self.pc = t
            return
        if mode == IMM:
            val = self.fetch()
            ea = None
        else:
            ea = self.addr(mode)
            val = None
        def get():
            return val if ea is None else self.r(ea)
        if n == "lda":
            self.a = self.nz(get())
        elif n == "ldx":
            self.x = self.nz(get())
        elif n == "ldy":
            self.y = self.nz(get())
        elif n == "sta":
            self.w(ea, self.a)
        elif n == "stx":
            self.w(ea, self.x)
        elif n == "sty":
            self.w(ea, self.y)
        elif n == "and":
            self.a = self.nz(self.a & get())
        elif n == "ora":
            self.a = self.nz(self.a | get())
        elif n == "eor":
            self.a = self.nz(self.a ^ get())
        elif n == "adc":
            self.adc(get())
        elif n == "sbc":
            self.adc(get() ^ 0xFF)
        elif n == "cmp":
            self.cmp(self.a, get())
        elif n == "cpx":
            self.cmp(self.x, get())
        elif n == "cpy":
            self.cmp(self.y, get())
        elif n == "bit":
            v = get()
            self.z = int(self.a & v == 0)
            self.n = v >> 7
            self.v = v >> 6 & 1
        elif n in ("inc", "dec", "asl", "lsr", "rol", "ror"):
            self.w(ea, self.rmw(n, self.r(ea)))
        else:
            raise Halt(f"unimplemented {n}")

    def rmw(self, n, v):
        if n == "inc":
            return self.nz(v + 1)
        if n == "dec":
            return self.nz(v - 1)
        if n == "asl":
            self.c = v >> 7
            return self.nz(v << 1)
        if n == "lsr":
            self.c = v & 1
            return self.nz(v >> 1)
        if n == "rol":
            c = self.c
            self.c = v >> 7
            return self.nz(v << 1 | c)
        if n == "ror":
            c = self.c
            self.c = v & 1
            return self.nz(v >> 1 | c << 7)
        raise Halt(n)

    def imp(self, n):
        if n == "clc": self.c = 0
        elif n == "sec": self.c = 1
        elif n == "cli": self.i = 0
        elif n == "sei": self.i = 1
        elif n == "clv": self.v = 0
        elif n == "cld": self.d = 0
        elif n == "sed": self.d = 1
        elif n == "tax": self.x = self.nz(self.a)
        elif n == "txa": self.a = self.nz(self.x)
        elif n == "tay": self.y = self.nz(self.a)
        elif n == "tya": self.a = self.nz(self.y)
        elif n == "tsx": self.x = self.nz(self.sp)
        elif n == "txs": self.sp = self.x
        elif n == "inx": self.x = self.nz(self.x + 1)
        elif n == "dex": self.x = self.nz(self.x - 1)
        elif n == "iny": self.y = self.nz(self.y + 1)
        elif n == "dey": self.y = self.nz(self.y - 1)
        elif n == "pha": self.push(self.a)
        elif n == "pla": self.a = self.nz(self.pull())
        elif n == "php": self.push(self.flags())
        elif n == "plp": self.setflags(self.pull())
        elif n == "rts":
            lo = self.pull()
            self.pc = ((lo | self.pull() << 8) + 1) & 0xFFFF
        elif n == "nop": pass
        else:
            raise Halt(n)


# ----------------------------------------------------------------------------------- the UCI
class MockUci:
    """Just enough of the network target for the benchmark PRG. Answers are the documented ones
    (doc/uci_tls.md); how the real firmware blocks a READ is not modelled."""

    def __init__(self, payload=262144, corrupt_at=None, tls_open_status=b"00,OK",
                 status_per_block=False, nodata_every=0, cut_at=None, eof_status=b"01,CONNECTION CLOSED BY HOST",
                 never_reply=False, cap_ready=0x0F, bad_header_at=None, block_size=895):
        self.block_size = block_size
        self.payload = payload
        self.corrupt_at = corrupt_at
        self.tls_open_status = tls_open_status
        self.status_per_block = status_per_block
        self.nodata_every = nodata_every
        self.cut_at = cut_at
        self.eof_status = eof_status
        self.never_reply = never_reply
        self.cap_ready = cap_ready
        self.bad_header_at = bad_header_at
        self.cmd = bytearray()
        self.state = 0                  # 0 idle, 1 busy (counts down), 2 data last, 3 data more
        self.busy_reads = 0
        self.blocks = []
        self.cur = None                 # (data bytearray, status bytearray)
        self.log = []                   # every command
        self.streams = {}               # handle -> dict
        self.next_handle = 0
        self.status_reads = 0
        self.trust = None

    # registers
    def read(self, a):
        if a == 0xDF1C:
            if self.state == 1:
                self.busy_reads -= 1
                if self.busy_reads <= 0:
                    self._arrive()
                return 0x11
            if self.state == 0:
                return 0
            d, s = self.cur
            return (self.state << 4) | (0x80 if d else 0) | (0x40 if s else 0)
        if a == 0xDF1E:
            d, s = self.cur if self.cur else (bytearray(), bytearray())
            return d.pop(0) if d else 0
        if a == 0xDF1F:
            self.status_reads += 1
            d, s = self.cur if self.cur else (bytearray(), bytearray())
            return s.pop(0) if s else 0
        return 0

    def write(self, a, v):
        if a == 0xDF1D:
            self.cmd.append(v)
        elif a == 0xDF1C:
            if v & 1:
                self._push()
            if v & 2:
                self._accept()
            if v & 8:
                pass

    def _accept(self):
        if self.state == 3:
            self.cur = self.blocks.pop(0)
            self.state = 2 if not self.blocks else 3
            if self.state == 2 and len(self.blocks) == 0:
                pass
        elif self.state == 2:
            self.state = 0
            self.cur = None

    def _push(self):
        assert self.state == 0, "PUSH while not idle"
        cmd = bytes(self.cmd)
        self.cmd = bytearray()
        self.log.append(cmd)
        if self.never_reply:
            self.state = 1
            self.busy_reads = 10 ** 9
            return
        self.reply = self._handle(cmd)
        self.state = 1
        self.busy_reads = 3

    def _arrive(self):
        data, status = self.reply
        # split data into 895-byte blocks
        bs = self.block_size
        chunks = [data[i:i + bs] for i in range(0, len(data), bs)] or [b""]
        blocks = []
        for i, ch in enumerate(chunks):
            last = i == len(chunks) - 1
            st = status if (last or self.status_per_block) else b""
            blocks.append((bytearray(ch), bytearray(st)))
        self.cur = blocks.pop(0)
        self.blocks = blocks
        self.state = 2 if not blocks else 3

    def _handle(self, c):
        assert c[0] == 3, c
        op = c[1]
        if op == 0x22:
            self.trust = c[2:]
            return b"", b"00,OK"
        if op == 0x23:
            if c[2] == 0xFF:
                cap = bytes([1, 4, 0, 7, self.cap_ready, 3, 1, 8, 0, 0, 0, 0, 0xB8, 0x0B, 0, 0])
                return cap, b"00,OK"
            info = struct.pack("<HHHBB", 0x0303, 0xCCA9, 0x0017, 1, 1) + bytes(32) + struct.pack("<I", 4321) + bytes(4)
            return info, b"00,OK"
        if op == 0x21:
            if self.tls_open_status != b"00,OK":
                return b"", self.tls_open_status
            h = self.next_handle
            self.next_handle += 1
            self.streams[h] = {"sent": 0, "tls": True, "polls": 0, "closed": False}
            return bytes([h]) + struct.pack("<HHHB", 0x0303, 0xCCA9, 0x0017, 1), b"00,OK"
        if op == 0x07:
            h = self.next_handle
            self.next_handle += 1
            self.streams[h] = {"sent": 0, "tls": False, "polls": 0, "closed": False}
            return bytes([h]), b"00,OK"
        if op == 0x11:
            return struct.pack("<H", len(c) - 3), b"00,OK"
        if op == 0x09:
            return b"", b"00,OK"
        if op == 0x10:
            h = c[2]
            maxlen = c[3] | c[4] << 8
            s = self.streams[h]
            limit = self.cut_at if self.cut_at is not None else self.payload
            if s["sent"] >= limit:
                if s["tls"]:
                    return struct.pack("<H", 0), self.eof_status
                return struct.pack("<H", 0), b"01,CONNECTION CLOSED BY HOST"
            s["polls"] += 1
            if self.nodata_every and s["polls"] % self.nodata_every == 0:
                return struct.pack("<H", 0xFFFF), b"02,NO DATA: 11"
            n = min(maxlen, limit - s["sent"], 1472)
            body = bytearray((s["sent"] + i) & 0xFF for i in range(n))
            if self.corrupt_at is not None and s["sent"] <= self.corrupt_at < s["sent"] + n:
                body[self.corrupt_at - s["sent"]] ^= 0xFF
            hdr_n = n
            if self.bad_header_at is not None and s["sent"] >= self.bad_header_at:
                hdr_n = n + 1
            s["sent"] += n
            return struct.pack("<H", hdr_n) + bytes(body), b"00,OK"
        raise AssertionError(f"unexpected command {c.hex(' ')}")


class Machine:
    """64 KiB RAM + the mock UCI at $DF1C-$DF1F + CIA2 timers driven by the cycle count."""

    def __init__(self, uci):
        self.ram = bytearray(65536)
        self.uci = uci
        self.cpu = CPU(self)
        self.io_reads = 0

    def _timer(self):
        v = (0xFFFFFFFF - self.cpu.cycles) & 0xFFFFFFFF
        return v

    def read(self, a):
        if 0xDF1C <= a <= 0xDF1F:
            self.io_reads += 1
            return self.uci.read(a)
        if 0xDD04 <= a <= 0xDD07:
            v = self._timer()
            # timer A is the low 16 bits, B the high 16
            return (v >> (8 * (a - 0xDD04))) & 0xFF
        return self.ram[a]

    def write(self, a, v):
        if 0xDF1C <= a <= 0xDF1F:
            self.uci.write(a, v)
        elif 0xD000 <= a < 0xE000:
            pass
        else:
            self.ram[a] = v

    def load_prg(self, data):
        addr = data[0] | data[1] << 8
        self.ram[addr:addr + len(data) - 2] = data[2:]
        return addr

    def run_until(self, stop, limit=400_000_000):
        """Run until stop(machine) is true or the CPU parks on `jmp *`."""
        cpu = self.cpu
        n = 0
        while n < limit:
            pc = cpu.pc
            cpu.step()
            n += 1
            if cpu.pc == pc and self.ram[pc] == 0x4C:
                return "parked"
            if stop(self):
                return "stopped"
        return "limit"
