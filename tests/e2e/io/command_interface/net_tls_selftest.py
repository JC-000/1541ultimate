#!/usr/bin/env python3
# Self-test: the M3 TLS suite against a simulated device; needs no hardware.

"""Check net_tls_test.py without a device: it must go GREEN, RED, and red for the right reason.

Three parts, none of which touches any Ultimate:

1. ER-1 deadlines on the REST route. `RestLink` drives the real `uci.Uci`
   against fake registers ($DF1B-$DF1F in Python) that stay busy as long as a
   test says. A reply inside its bound is collected; a reply past it is
   ABORTed and the link waits for bit 2; a bit 2 that never clears is a
   LinkLost at the deadline, never a hang.
2. The suite's own scenarios against net_tls_mock.MockDevice, with the real
   local fixture (servers on 127.0.0.1) and two stand-in "internet" hosts
   under a second throwaway root, which is the mock's bundle and the CA this
   machine verifies them with:
     m3     every scenario GREEN, except S22, whose second half needs the
            negotiated group that Python's ssl does not expose (a mock limit)
     stock  every TLS scenario RED with `21,UNKNOWN COMMAND` to its first TLS
            command, and every control PASS, so --expect red is met
3. Mutants of the mock, each breaking one rule: the scenario that claims to
   guard that rule must go red (signature FAIL, not RED).
4. The whole suite, main() and all, over real HTTP: tests/lib/device_double.py
   serves REST on loopback, with $DF1B-$DF1F backed by a register model whose
   commands run on the mock. That exercises the settings it sets and reads
   back, the lock check, the reset, the ready wait, RestLink's register
   protocol (multi-block replies, an ABORT in PROCESSING) and the result files,
   for Tier 1 without S30 (whose hosts are real). --expect green on the m3
   flavour and --expect red on stock must both exit 0, and swapped, both 1.

Usage: net_tls_selftest.py [--quick]   (--quick skips the m3 flavour's 15 s
handshake-timeout scenario and the 16 KB record)
"""

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

# The one stanza that puts the shared library on sys.path; see tests/lib/bootstrap.py.
sys.path.insert(0, str(next(p for p in Path(__file__).resolve().parents
                            if (p / "tests" / "lib").is_dir()) / "tests" / "lib"))
import bootstrap  # noqa: E402,F401
from report import Failure, check, detail, section, suite_fail, suite_ok, suite_skip  # noqa: E402
from device_double import DeviceDouble  # noqa: E402
from uci import MAX_BLOCK_BYTES, Uci  # noqa: E402

sys.path.insert(0, bootstrap.directory("e2e", "io", "command_interface"))
import net_tls_fixture as fx  # noqa: E402
import net_tls_proto as proto  # noqa: E402
import net_tls_test as suite  # noqa: E402
from net_tls_mock import MockDevice  # noqa: E402

SUITE = "net_tls_selftest"
STANDINS = (("H1", "h1.standin.test"), ("H2", "h2.standin.test"))


# -- part 1: fake registers --------------------------------------------------

class FakeRegisters:
    """$DF1B-$DF1F as a MachineApi: readmem / writemem, one command at a time."""

    def __init__(self, busy: float, reply: bytes = b"\x05", text: bytes = b"00,OK",
                 stuck_abort: bool = False) -> None:
        self.busy, self.reply, self.text, self.stuck = busy, reply, text, stuck_abort
        self.state = "idle"
        self.done_at = 0.0
        self.abort = False
        self.resp = bytearray()
        self.stat = bytearray()

    def _tick(self) -> None:
        if self.state == "busy" and time.monotonic() >= self.done_at:
            if self.abort:
                # The ABORT is serviced right after the command returns: the
                # reply is dropped and the state goes back to Idle.
                self.state = "idle"
                self.abort = self.stuck
            else:
                self.state = "reply"
                self.resp, self.stat = bytearray(self.reply), bytearray(self.text)

    def _status(self) -> int:
        self._tick()
        value = {"idle": 0x00, "busy": 0x11, "reply": 0x20}[self.state]
        if self.abort:
            value |= 0x04
        if self.state == "reply":
            value |= (0x80 if self.resp else 0) | (0x40 if self.stat else 0)
        return value

    def _read(self, address: int) -> int:
        if address == 0xDF1C:
            return self._status()
        if address == 0xDF1D:
            return 0xC9
        if address == 0xDF1E:
            return self.resp.pop(0) if self.resp else 0
        if address == 0xDF1F:
            return self.stat.pop(0) if self.stat else 0
        return 0x02

    def readmem(self, address: int, length: int = 1) -> bytes:
        return bytes(self._read(address + i) for i in range(length))

    def writemem(self, address: int, data: bytes, idempotent: bool = False) -> None:
        if address != 0xDF1C:
            return
        for bits in data:
            self._tick()
            if bits & 0x01:
                self.state, self.done_at = "busy", time.monotonic() + self.busy
            if bits & 0x02 and self.state == "reply":
                self.state = "idle"
            if bits & 0x04:
                # On an idle interface the ABORT is serviced at once.
                self.abort = self.state == "busy" or self.stuck


def part1() -> bool:
    section("part 1: ER-1 deadlines over fake registers")
    ok = True
    saved = proto.POST_ABORT_MIN
    proto.POST_ABORT_MIN = 1.5
    try:
        cases = [
            ("a reply inside its bound is collected", FakeRegisters(0.2), 2.0, "reply"),
            ("a reply past its bound is ABORTed; bit 2 clears when the command ends",
             FakeRegisters(1.0), 0.4, "aborted"),
            ("bit 2 that never clears is LinkLost at the deadline, not a hang",
             FakeRegisters(5.0, stuck_abort=True), 0.4, "lost"),
        ]
        for label, regs, bound, wanted in cases:
            try:
                with check(label):
                    link = proto.RestLink(Uci(regs, 30.0))
                    started = time.monotonic()
                    try:
                        result = link.command(proto.info_command(0xFF), bound)
                        got = "aborted" if result.aborted else "reply"
                        if got == "reply" and (result.data, result.status) != (b"\x05", b"00,OK"):
                            raise Failure(f"collected {result.describe()}")
                    except proto.LinkLost:
                        got = "lost"
                    took = time.monotonic() - started
                    detail(f"{got} after {took:.2f}s")
                    if got != wanted:
                        raise Failure(f"{got}, expected {wanted}")
                    if took > bound + proto.POST_ABORT_MIN + 1.0:
                        raise Failure(f"took {took:.2f}s, past the ER-1 deadline")
            except Failure:
                ok = False
        try:
            with check("abort_in_flight: ABORT lands in PROCESSING; bit 2 clears at the command's end"):
                regs = FakeRegisters(1.0)
                outcome = proto.RestLink(Uci(regs, 30.0)).abort_in_flight(
                    proto.info_command(0xFF), 0.3, bound=5.0)
                if not outcome.busy_at_abort or not 0.9 <= outcome.bit2_cleared_after <= 2.0:
                    raise Failure(str(outcome))
        except Failure:
            ok = False
    finally:
        proto.POST_ABORT_MIN = saved
    return ok


# -- parts 2 and 3: the mock -----------------------------------------------

class World:
    """The fixture PKI, a stand-in public PKI and its HTTP servers."""

    def __init__(self) -> None:
        self.pki = fx.Pki()
        self.public = fx.Pki()
        self.public_root = str(self.public.root_pem_file())
        self.servers = []
        self.hosts = []
        self.resolver = {}
        for hid, name in STANDINS:
            chain = self.public.issue(hid, name)
            server = fx.TlsServer("127.0.0.1", chain, fx.Behaviour(then="http"))
            self.servers.append(server)
            self.hosts.append(suite.Host(name, hid, ip="127.0.0.1", port=server.port))
            self.resolver[name] = "127.0.0.1"

    def device(self, flavour: str) -> MockDevice:
        return MockDevice(flavour, bundle_cafile=self.public_root, resolver=self.resolver,
                          system_bundle=False)

    def args(self) -> SimpleNamespace:
        return SimpleNamespace(module_minor=308, mac_cafile=self.public_root, strict_sni=True,
                               hosts=self.hosts)

    def run(self, flavour: str, sids: list[str]) -> dict[str, suite.Outcome]:
        device = self.device(flavour)

        def reset():
            device.reset()
            return device
        scenarios = [s for s in suite.SCENARIOS if s.sid in sids]
        outcomes, _ = suite.run_routes([(f"mock-{flavour}", lambda: device, reset)], scenarios,
                                       self.args(), self.pki, "127.0.0.1",
                                       {"peer", "fixture", "crypto", "internet"})
        device.reset()
        return {o.scenario.sid: o for o in outcomes}

    def close(self) -> None:
        for server in self.servers:
            server.close()
        self.pki.close()
        self.public.close()


# -- part 4: main() over HTTP ---------------------------------------------------

class UciDouble(DeviceDouble):
    """The repository's REST double, with a command interface run by a MockDevice."""

    def __init__(self, device: MockDevice) -> None:
        super().__init__()
        self.mock = device
        self.configs.update({
            "C64 and Cartridge Settings": {"Command Interface": "Disabled"},
            "WiFi settings": {"WiFi Enabled": "Enabled"},
            "Network Settings": {"SNTP Enable": "Disabled"},
            "U64 Specific Settings": {"Turbo Control": "Manual"},
        })
        self.cmd = bytearray()
        self.state = "idle"
        self.abort = False
        self.blocks: list[tuple[bytes, bytes]] = []
        self.resp = bytearray()
        self.stat = bytearray()
        self.uci_lock = threading.Lock()

    def route(self, method, path):
        if path == "/v1/machine:readmem" and method == "GET":
            return self._uci_read
        if path == "/v1/machine:writemem" and method == "PUT":
            return self._uci_write
        if path == "/v1/machine:reset" and method == "PUT":
            return self._reset
        return super().route(method, path)

    def _reset(self, params):
        self.mock.reset()
        return self._ok_json(params)

    def _run(self, command: bytes) -> None:
        data, text = self.mock._dispatch(command)
        with self.uci_lock:
            if self.abort:
                # The ABORT is serviced once the command returns: reply dropped.
                self.state, self.abort, self.blocks = "idle", False, []
                return
            chunks = [data[i:i + MAX_BLOCK_BYTES] for i in range(0, len(data), MAX_BLOCK_BYTES)]
            chunks = chunks or [b""]
            self.blocks = [(chunk, text if i == len(chunks) - 1 else b"")
                           for i, chunk in enumerate(chunks)]
            self._next_block()

    def _next_block(self) -> None:
        chunk, text = self.blocks.pop(0)
        self.resp, self.stat = bytearray(chunk), bytearray(text)
        self.state = "more" if self.blocks else "last"

    def _status(self) -> int:
        value = {"idle": 0x00, "busy": 0x11, "last": 0x20, "more": 0x30}[self.state]
        if self.abort:
            value |= 0x04
        if self.state in ("last", "more"):
            value |= (0x80 if self.resp else 0) | (0x40 if self.stat else 0)
        return value

    def _byte(self, address: int) -> int:
        if address == 0xDF1C:
            return self._status()
        if address == 0xDF1D:
            return 0xC9
        if address == 0xDF1E:
            return self.resp.pop(0) if self.resp else 0
        if address == 0xDF1F:
            return self.stat.pop(0) if self.stat else 0
        return 0x02

    def _uci_read(self, params):
        address = int(params.get("address", "0"), 16)
        if not 0xDF1B <= address <= 0xDF1F:
            return super()._readmem(params)
        length = int(params.get("length", "1"))
        with self.uci_lock:
            body = bytes(self._byte(address + i) for i in range(length))
        return 200, body, "application/octet-stream"

    def _uci_write(self, params):
        address = int(params.get("address", "0"), 16)
        data = bytes.fromhex(params.get("data", ""))
        with self.uci_lock:
            for value in data:
                if address == 0xDF1D:
                    self.cmd.append(value)
                elif address == 0xDF1C:
                    self._control(value)
        return self._ok_json(params)

    def _control(self, bits: int) -> None:
        if bits & 0x01 and self.state == "idle":
            command, self.cmd = bytes(self.cmd), bytearray()
            self.state = "busy"
            threading.Thread(target=self._run, args=(command,), daemon=True).start()
        if bits & 0x02:
            if self.state == "more":
                self._next_block()
            elif self.state == "last":
                self.state = "idle"
        if bits & 0x04:
            if self.state == "busy":
                self.abort = True
            else:
                self.state, self.blocks, self.cmd = "idle", [], bytearray()


def part4(world: "World") -> bool:
    section("part 4: main() over HTTP, against a REST double with a mocked network target")
    ok = True
    tier1 = ["S1", "S20", "S2", "S23", "S5", "S19e"]
    for flavour, expect, code in (("m3", "green", 0), ("stock", "red", 0),
                                  ("m3", "red", 1), ("stock", "green", 1)):
        double = UciDouble(world.device(flavour))
        saved = {k: os.environ.get(k) for k in double.environment()}
        os.environ.update(double.environment())
        try:
            with tempfile.TemporaryDirectory() as results:
                argv = ["-H", "127.0.0.1", "-t", "10", "--route", "rest", "--expect", expect,
                        "--results", results, "--module-minor", "308"]
                for sid in tier1:
                    argv += ["--test", sid]
                exit_code = suite.main(argv)
                run = json.loads((Path(results) / "run.json").read_text())
            try:
                with check(f"{flavour} with --expect {expect} exits {code}; run.json and settings"):
                    if exit_code != code:
                        raise Failure(f"exit {exit_code}")
                    settings = run.get("settings", {})
                    wanted = {"Command Interface": "Enabled", "WiFi Enabled": "Enabled",
                              "SNTP Enable": "Enabled", "Turbo Control": "Off"}
                    if settings != wanted:
                        raise Failure(f"settings read back {settings}")
                    restored = double.configs["C64 and Cartridge Settings"]["Command Interface"]
                    if restored != "Disabled":
                        raise Failure(f"Command Interface left {restored!r}, not restored")
                    if double.configs["WiFi settings"]["WiFi Enabled"] != "Enabled":
                        raise Failure("WiFi Enabled was written back (it is one-way)")
                    sigs = {o["sid"]: o["signature"] for o in run["scenarios"]}
                    detail(str(sigs))
                    if len(run["scenarios"]) != len(tier1) + 1:
                        raise Failure(f"{len(run['scenarios'])} scenario records")
                    resets = [r for r in double.calls("PUT", "/v1/machine:reset")]
                    if not resets:
                        raise Failure("the C64 was never reset")
            except Failure:
                ok = False
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            double.close()
    return ok


def judge_flavour(label: str, outcomes: dict, wanted: dict[str, str]) -> bool:
    """`wanted` maps a sid to the signature it must show."""
    ok = True
    for sid, signature in wanted.items():
        o = outcomes.get(sid)
        try:
            with check(f"{label}: {sid} shows {signature}"):
                if o is None:
                    raise Failure("not run")
                if o.signature != signature:
                    raise Failure(f"{o.signature}: {o.reason[:200]}")
        except Failure:
            ok = False
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    if not fx.HAVE_CRYPTOGRAPHY:
        suite_skip(SUITE, "the `cryptography` package is not installed")
        return 0
    ok = part1()
    world = World()
    try:
        everything = [s.sid for s in suite.SCENARIOS if s.default]
        if args.quick:
            everything = [sid for sid in everything if sid not in ("S10", "S13")]
        section("part 2: the m3 flavour goes GREEN")
        m3 = world.run("m3", everything)
        wanted = {sid: ("CONTROL-PASS" if suite.BY_NAME[sid].kind == "control" else "GREEN")
                  for sid in everything}
        wanted["S22"] = "FAIL"   # the mock cannot report the negotiated group
        ok &= judge_flavour("m3", m3, wanted)
        section("part 2: the stock flavour goes RED")
        stock = world.run("stock", everything)
        wanted = {sid: ("CONTROL-PASS" if suite.BY_NAME[sid].kind == "control" else "RED")
                  for sid in everything}
        ok &= judge_flavour("stock", stock, wanted)
        try:
            with check("--expect red is met by the stock run, and --expect green is not"):
                red, problems = suite.expectation_met(list(stock.values()), "red")
                green, _ = suite.expectation_met(list(stock.values()), "green")
                if not red or green:
                    raise Failure(f"red met {red}, green met {green}: {problems[:3]}")
        except Failure:
            ok = False
        section("part 3: each mutant turns its guard red")
        for flavour, sids in (("bundle-accepts-all", ["S0", "S5"]),
                              ("release-noop", ["S0", "S19e", "S19e2"]),
                              ("group-zero", ["S0", "S2"]),
                              ("info-ff-claims", ["S0", "S19e", "S19e2b"])):
            outcomes = world.run(flavour, sids)
            ok &= judge_flavour(flavour, outcomes, {sid: "FAIL" for sid in sids[1:]})
        if not args.quick:
            ok &= part4(world)
    finally:
        world.close()
    if ok:
        suite_ok(SUITE, "GREEN on m3, RED on stock, every mutant caught")
        return 0
    suite_fail(SUITE, "see the checks above")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
