#!/usr/bin/env python3
"""
Runs the crypto conformance suites against a host build of the ESP32's mbedTLS (run.sh builds
it) and prints one line per suite and a final CRYPTO_CONFORMANCE PASS|FAIL line.

Vectors are fetched at run time, never committed: Wycheproof and x509-limbo from git at the
commits in PINS, the RFCs and NIST CAVP files by URL, checked against the sha256 below (those
documents never change). Every file used is listed with its sha256 in <out>/sources.txt.

Each vector's expected outcome is Wycheproof's: "valid" must be accepted with the right output,
"invalid" rejected. An "acceptable" vector, or any known deviation, needs a line in the
expectations file saying which outcome mbedTLS gives and why; a vector without one fails, and so
does an expectations line that no vector used.
"""

import argparse
import base64
import datetime
import difflib
import fnmatch
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def switch(name):
    """A 0/1 setting: unset is 0, and anything else than 0 or 1 is an error, not a silent 0."""
    value = os.environ.get(name, "0")
    if value not in ("0", "1"):
        sys.exit("%s=%s: use 0 or 1" % (name, value))
    return value == "1"


# CRYPTO_OFFLINE=1: use what the cache holds, fetch nothing, and fail on anything missing
OFFLINE = switch("CRYPTO_OFFLINE")

# Documents fetched by URL: they are immutable, so the sha256 pins them.
DOCUMENTS = {
    "rfc5869": (
        "https://www.rfc-editor.org/rfc/rfc5869.txt",
        "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c",
    ),
    "rfc7748": (
        "https://www.rfc-editor.org/rfc/rfc7748.txt",
        "279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3",
    ),
    "rfc8439": (
        "https://www.rfc-editor.org/rfc/rfc8439.txt",
        "25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c",
    ),
    "rfc8448": (
        "https://www.rfc-editor.org/rfc/rfc8448.txt",
        "6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba",
    ),
    "cavp-sha": (
        "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
        "documents/shs/shabytetestvectors.zip",
        "929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8",
    ),
}

# What the TLS 1.3 client offers ("vectors offer" prints it from a real ClientHello), and the
# algorithms each offer needs a passing valid vector for. An offer not listed here fails the
# coverage suite: a new mbedTLS that offers something new needs vectors for it first.
AEAD_SHA256 = ["sha256", "hmac/sha256", "hkdf/sha256"]
OFFERS = {
    "suite 1301": ["aes-gcm/k128/t128", *AEAD_SHA256],  # TLS_AES_128_GCM_SHA256
    "suite 1302": [
        "aes-gcm/k256/t128",
        "sha384",
        "hmac/sha384",
        "hkdf/sha384",
    ],  # TLS_AES_256_GCM_SHA384
    "suite 1303": ["chacha20-poly1305/k256/t128", *AEAD_SHA256],  # TLS_CHACHA20_POLY1305_SHA256
    "suite 1304": ["aes-ccm/k128/t128", *AEAD_SHA256],  # TLS_AES_128_CCM_SHA256
    "suite 1305": ["aes-ccm/k128/t64", *AEAD_SHA256],  # TLS_AES_128_CCM_8_SHA256
    "suite 00ff": [],  # renegotiation SCSV, no algorithm
    "group 001d": ["x25519"],
    "group 001e": ["x448"],  # offered by mbedTLS 4's defaults
    "group 0017": ["ecdh/secp256r1"],
    "group 0018": ["ecdh/secp384r1"],
    "group 0019": ["ecdh/secp521r1"],
    "keyshare 001d": ["x25519"],
    "sigalg 0403": ["ecdsa/secp256r1/sha256"],
    "sigalg 0503": ["ecdsa/secp384r1/sha384"],
    "sigalg 0603": ["ecdsa/secp521r1/sha512", "sha512"],
    "sigalg 0804": ["pss/sha256"],  # rsa_pss_rsae_sha256
    "sigalg 0805": ["pss/sha384"],
    "sigalg 0806": ["pss/sha512", "sha512"],
    "sigalg 0401": ["pkcs1/sha256"],  # certificates only in TLS 1.3
    "sigalg 0501": ["pkcs1/sha384"],
    "sigalg 0601": ["pkcs1/sha512", "sha512"],
}

WYCHEPROOF = {
    "aes-gcm": ["aes_gcm_test.json"],
    "chacha20-poly1305": ["chacha20_poly1305_test.json"],
    "aes-ccm": ["aes_ccm_test.json"],
    "hmac": ["hmac_sha256_test.json", "hmac_sha384_test.json"],
    "hkdf": ["hkdf_sha256_test.json", "hkdf_sha384_test.json"],
    "x25519": ["x25519_test.json"],
    "x448": ["x448_test.json"],  # built only where the configuration has the curve
    "ecdh-nist": [
        "ecdh_secp256r1_ecpoint_test.json",
        "ecdh_secp384r1_ecpoint_test.json",
        "ecdh_secp521r1_ecpoint_test.json",
    ],
    # CertificateVerify binds curve and hash; a certificate's signature does not, hence the mixes
    "ecdsa": [
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256r1_sha512_test.json",
        "ecdsa_secp384r1_sha256_test.json",
        "ecdsa_secp384r1_sha384_test.json",
        "ecdsa_secp384r1_sha512_test.json",
        "ecdsa_secp521r1_sha512_test.json",
        # the certificate profile accepts brainpool curves in a chain (vectors profile)
        "ecdsa_brainpoolP256r1_sha256_test.json",
        "ecdsa_brainpoolP384r1_sha384_test.json",
        "ecdsa_brainpoolP512r1_sha512_test.json",
    ],
    "rsa-pkcs1": [
        "rsa_signature_%d_%s_test.json" % (b, h)
        for b in (2048, 3072, 4096)
        for h in ("sha256", "sha384", "sha512")
    ],
    # TLS 1.3 only uses rsa_pss_rsae with the salt as long as the hash (ssl_tls13_generic.c)
    "rsa-pss": [
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha384_mgf1_48_test.json",
        "rsa_pss_4096_sha512_mgf1_64_test.json",
    ],
}

HASHES = {
    "SHA-1": "sha1",
    "SHA-224": "sha224",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}
CURVE_BYTES = {"secp256r1": 32, "secp384r1": 48, "secp521r1": 66}


def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def read_pins(path):
    pins = {}
    for line in read(path).split("\n"):
        line = line.split("#", 1)[0].strip()
        if line:
            key, value = line.split("=", 1)
            pins[key] = value
    return pins


class Sources:
    """Fetches and caches what the suites read, and records the sha256 of each file used."""

    def __init__(self, cache, pins):
        self.cache = cache
        self.pins = pins
        self.used = []
        os.makedirs(cache, exist_ok=True)

    def note(self, name, data):
        self.used.append((name, hashlib.sha256(data).hexdigest()))
        return data

    def git(self, key, path):
        repo, commit = self.pins[key + "_REPO"], self.pins[key + "_COMMIT"]
        if not re.fullmatch("[0-9a-f]{40}", commit):
            sys.exit("PINS: %s_COMMIT is not a full SHA" % key)
        name = repo.rstrip("/").split("/")[-1]
        work = os.path.join(self.cache, "%s-%s" % (name, commit))
        if not os.path.isdir(os.path.join(work, ".git")):
            if OFFLINE:
                sys.exit(
                    "offline, and %s is not in the cache (%s): run once with the network"
                    % (key, work)
                )
            # A partial clone of the one commit: only the files read below are downloaded
            subprocess.run(["git", "init", "-q", work], check=True, timeout=60)
            subprocess.run(
                [
                    "git",
                    "-C",
                    work,
                    "fetch",
                    "-q",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    repo,
                    commit,
                ],
                check=True,
                timeout=600,
            )
        # git checks every object against its hash, so the content is what the commit says;
        # offline, a file the cache does not hold yet is an error rather than a download
        env = dict(os.environ, GIT_NO_LAZY_FETCH="1") if OFFLINE else None
        data = subprocess.run(
            ["git", "-C", work, "cat-file", "-p", "%s:%s" % (commit, path)],
            check=True,
            capture_output=True,
            env=env,
            timeout=600,
        ).stdout
        return self.note("%s@%s:%s" % (name, commit, path), data)

    def document(self, key):
        url, sha = DOCUMENTS[key]
        path = os.path.join(self.cache, "sha256-" + sha)
        if not os.path.exists(path):
            if OFFLINE:
                sys.exit(
                    "offline, and %s is not in the cache (%s): run once with the network"
                    % (url, path)
                )
            # csrc.nist.gov refuses Python's default User-Agent
            req = urllib.request.Request(
                url, headers={"User-Agent": "curl/8 (1541u crypto conformance)"}
            )
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            with open(path + ".tmp", "wb") as f:
                f.write(data)
            os.replace(path + ".tmp", path)
        data = read(path, "rb")
        if hashlib.sha256(data).hexdigest() != sha:
            sys.exit("%s: sha256 mismatch (%s)" % (url, path))
        return self.note(url, data)


class Harness:
    """The vectors program: one operation per line, one result per line."""

    def __init__(self, exe):
        self.proc = subprocess.Popen(
            [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def __call__(self, *fields):
        line = " ".join(str(f) if f != "" else "-" for f in fields)
        self.proc.stdin.write(line + "\n")
        answer = self.proc.stdout.readline()
        if not answer:
            raise RuntimeError("the vectors harness died on: %s" % line[:200])
        rc, _, out = answer.rstrip("\n").partition(" ")
        return int(rc), bytes.fromhex(out)


class Expectations:
    """Lines of "<vector file> tc=<id>|flag=<name> <outcome> <reason>", where <outcome> is one of
      accept | reject | skip       the outcome mbedTLS gives, where it is not the vector's own
      known-vulnerable <CVE> <v>   a vulnerability of the pinned mbedTLS, fixed in version <v>
      security-deviation <tag>     accepted where it should be refused, by design (bundle mode)
    An accept line whose reason starts "fail-open:<tag>" is a security-relevant fail-open deviation.
    The last two must show the opposite of the vector's verdict: when they no longer do, the run
    fails until the line is removed. A tc= line wins over flag= lines; among flag= lines the first
    in the file that names one of the vector's flags wins. With strict set, a vector under either
    of the last two fails."""

    def __init__(self, path, strict=False):
        self.strict = strict
        self.rules = {}
        self.notes = {}
        self.used = set()
        for n, line in enumerate(read(path).split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(None, 3)
            if len(fields) == 4 and fields[2] == "known-vulnerable":
                cve = fields[3].split(None, 2)
                if len(cve) < 3 or not re.fullmatch(r"CVE-\d{4}-\d+", cve[0]):
                    sys.exit(
                        '%s:%d: want "... known-vulnerable <CVE> <fixed in> <reason>"' % (path, n)
                    )
                self.notes[(fields[0], fields[1])] = "%s (fixed in mbedTLS %s)" % (cve[0], cve[1])
            elif len(fields) == 4 and fields[2] == "security-deviation":
                self.notes[(fields[0], fields[1])] = fields[3].split(None, 1)[0]
            elif len(fields) == 4 and fields[2] == "accept" and fields[3].startswith("fail-open:"):
                # a security-relevant fail-open deviation: "fail-open:<tag> <reason>"
                self.notes[(fields[0], fields[1])] = fields[3].split(None, 1)[0]
            elif (
                len(fields) < 4
                or fields[2] not in ("accept", "reject", "skip")
                or "=" not in fields[1]
            ):
                sys.exit('%s:%d: want "<file> tc=N|flag=F accept|reject|skip <reason>"' % (path, n))
            if (fields[0], fields[1]) in self.rules:
                sys.exit("%s:%d: %s %s is there twice" % (path, n, fields[0], fields[1]))
            self.rules[(fields[0], fields[1])] = (fields[2], n)

    def lookup(self, source, tc, flags):
        keys = [
            (source, "tc=%s" % tc),
            *sorted(
                ((source, "flag=" + f) for f in flags), key=lambda k: self.rules.get(k, (0, 0))[1]
            ),
        ]
        for key in keys:
            if key in self.rules:
                self.used.add(key)
                return self.rules[key][0], self.notes.get(key), key
        return None, None, None

    def unused(self):
        return sorted((self.rules[k][1], k) for k in self.rules if k not in self.used)


class Suite:
    def __init__(self, name, expectations):
        self.name = name
        self.expectations = expectations
        self.passed = self.failed = 0
        # how each vector was judged: by its own verdict, or by which expectations line and how
        self.own = self.na = 0
        self.by_line = {}
        self.kinds = {"fail-closed": 0, "fail-open": 0, "acceptable": 0, "agree": 0}
        # Vectors that show an insecure outcome as recorded: not counted as passed
        self.known = []  # (CVE, vector) for each vector that still shows a known vulnerability
        self.deviations = []  # (tag, vector) for each security deviation
        self.fail_open = []  # (tag, vector) for each security-relevant fail-open deviation
        self.failures = []
        self.covered = set()

    def fail(self, what):
        self.failed += 1
        self.failures.append(what)

    def not_applicable(self):
        self.na += 1

    def judge(self, source, tc, result, flags, observed, cover=None):
        """observed: 'accept', 'reject', 'skip', or 'wrong' (reported success with the wrong output)."""
        want, note, key = self.expectations.lookup(source, tc, flags)
        label = "%s tc=%s (%s, %s)" % (source, tc, result, " ".join(flags) or "-")
        if observed == "wrong":
            return self.fail("%s: WRONG OUTPUT" % label)
        own = {"valid": "accept", "invalid": "reject"}.get(result)
        if key:
            self.by_line[key] = self.by_line.get(key, 0) + 1
        if want in ("known-vulnerable", "security-deviation"):
            if observed == own:
                return self.fail("%s: %s no longer shows: remove its %s line" % (label, note, want))
            (self.known if want == "known-vulnerable" else self.deviations).append((note, tc))
            if self.expectations.strict:
                return self.fail("%s: %s, %s %s (CRYPTO_STRICT)" % (label, observed, want, note))
            return
        if want is None:
            if result == "acceptable":
                return self.fail(
                    "%s: %s, and no expectation says which outcome is right" % (label, observed)
                )
            want = own
            self.own += 1
        else:
            self.kinds[
                "acceptable"
                if own is None
                else "agree"
                if want == own
                else "fail-closed"
                if own == "accept"
                else "fail-open"
            ] += 1
        if observed != want:
            return self.fail("%s: %s, expected %s" % (label, observed, want))
        if note and note.startswith("fail-open:"):
            # in listed order (x509-misordered) the same behaviour is one more insecure outcome
            self.fail_open.append(
                (
                    note.split(":", 1)[1],
                    "%s%s" % (tc, "@given" if source.endswith("/given") else ""),
                )
            )
            if self.expectations.strict:
                return self.fail(
                    "%s: %s, security-relevant fail-open %s (CRYPTO_STRICT)"
                    % (label, observed, note)
                )
            return
        self.passed += 1
        if cover and (result == "valid") and (observed == "accept"):
            self.covered.add(cover)

    def insecure(self):
        return len(self.known) + len(self.deviations) + len(self.fail_open)

    def ok(self):
        return self.failed == 0 and (
            self.passed + self.insecure() > 0 or self.na > 0 or self.name == "expectations"
        )

    def line(self, detail=""):
        text = "SUITE %-18s %s %5d passed %3d failed" % (
            self.name,
            "PASS" if self.ok() else "FAIL",
            self.passed,
            self.failed,
        )
        by_lines = sum(self.by_line.values())
        if by_lines:
            parts = ["own verdict %d" % self.own, "by expectations %d" % by_lines]
            biggest = max(self.by_line.values())
            if biggest > 1:
                parts[-1] += " (largest line %d)" % biggest
            parts += ["%s %d" % (k, n) for k, n in self.kinds.items() if n]
            insecure = len(self.known) + len(self.deviations) + len(self.fail_open)
            parts += ["insecure outcomes %d (not in passed)" % insecure] if insecure else []
            text += ": " + ", ".join(parts)
        if self.na:
            text += "; not applicable %d" % self.na
        return text + (" " + detail if detail else "")


def outcome(rc, out, expected):
    if rc != 0:
        return "reject"
    return "accept" if expected is None or out == expected else "wrong"


# ---- Wycheproof ----------------------------------------------------------------------------


def run_aead(h, suite, source, g, t):
    aead = {"aes_gcm": "gcm", "aes_ccm": "ccm", "chacha20_poly1305": "chachapoly"}[
        source.rsplit("_test", 1)[0]
    ]
    ct, tag = bytes.fromhex(t["ct"]), bytes.fromhex(t["tag"])
    rc, pt = h("open", aead, t["key"], t["iv"], t["aad"], t["ct"], t["tag"])
    seen = outcome(rc, pt, bytes.fromhex(t["msg"]))
    if seen == "accept" and t["result"] != "invalid":
        # The same vector sealed must give the same ciphertext and tag
        rc, out = h("seal", aead, t["key"], t["iv"], t["aad"], t["msg"], len(tag))
        seen = outcome(rc, out, ct + tag)
    cover = "%s/k%d/t%d" % (suite.name, g["keySize"], g["tagSize"]) if g["ivSize"] == 96 else None
    suite.judge(source, t["tcId"], t["result"], t["flags"], seen, cover)


def run_mac(h, suite, source, g, t):
    alg = "sha" + source.split("_sha")[1].split("_")[0]
    rc, mac = h("hmac", alg, t["key"], t["msg"])
    seen = "accept" if rc == 0 and mac[: g["tagSize"] // 8] == bytes.fromhex(t["tag"]) else "reject"
    suite.judge(source, t["tcId"], t["result"], t["flags"], seen, "hmac/" + alg)


def run_hkdf(h, suite, source, g, t):
    alg = "sha" + source.split("_sha")[1].split("_")[0]
    rc, okm = h("hkdf", alg, t["ikm"], t["salt"], t["info"], t["size"])
    suite.judge(
        source,
        t["tcId"],
        t["result"],
        t["flags"],
        outcome(rc, okm, bytes.fromhex(t["okm"])),
        "hkdf/" + alg,
    )


def run_ecdh(h, suite, source, g, t):
    curve = g["curve"]
    priv = t["private"]
    if curve in CURVE_BYTES:
        # Wycheproof gives the scalar as an integer; PSA imports it at exactly the field size
        raw = int(priv, 16).to_bytes(
            max(CURVE_BYTES[curve], (int(priv, 16).bit_length() + 7) // 8), "big"
        )
        priv = raw.hex()
    group = {"curve25519": "x25519", "curve448": "x448"}.get(curve, curve)
    rc, shared = h("ecdh", group, priv, t["public"])
    suite.judge(
        source,
        t["tcId"],
        t["result"],
        t["flags"],
        outcome(rc, shared, bytes.fromhex(t["shared"])),
        group if group in ("x25519", "x448") else "ecdh/" + group,
    )


def run_verify(h, suite, source, g, t):
    alg = HASHES[g["sha"]]
    if g["type"] == "EcdsaVerify":
        scheme, slen, cover = "ecdsa", 0, "ecdsa/%s/%s" % (g["publicKey"]["curve"], alg)
    elif g["type"] == "RsassaPssVerify":
        if HASHES[g["mgfSha"]] != alg:
            sys.exit("%s: TLS 1.3 uses MGF1 with the signature hash" % source)
        scheme, slen, cover = "pss", g["sLen"], "pss/" + alg
    else:
        scheme, slen, cover = "pkcs1", 0, "pkcs1/" + alg
    rc, _ = h("verify", scheme, g["publicKeyDer"], alg, t["msg"], t["sig"], slen)
    suite.judge(
        source, t["tcId"], t["result"], t["flags"], "accept" if rc == 0 else "reject", cover
    )


RUNNERS = {
    "aes-gcm": run_aead,
    "chacha20-poly1305": run_aead,
    "aes-ccm": run_aead,
    "hmac": run_mac,
    "hkdf": run_hkdf,
    "x25519": run_ecdh,
    "x448": run_ecdh,
    "ecdh-nist": run_ecdh,
    "ecdsa": run_verify,
    "rsa-pkcs1": run_verify,
    "rsa-pss": run_verify,
}


def wycheproof(h, src, exp, name, conditions):
    suite = Suite(name, exp)
    if (name == "x448") and ("x448" not in conditions):
        suite.not_applicable()  # the curve is not in this configuration, and so not offered
        return suite
    for f in WYCHEPROOF[name]:
        data = json.loads(src.git("WYCHEPROOF", "testvectors_v1/" + f))
        for g in data["testGroups"]:
            for t in g["tests"]:
                RUNNERS[name](h, suite, f, g, t)
    return suite


# ---- RFC and NIST CAVP vectors -------------------------------------------------------------


def rfc_hex_after(text, label, start=0):
    """The bytes printed after a label line: one hex string, a hex dump or colon-separated."""
    i = text.index(label, start)
    out = ""
    for line in text[text.index("\n", i) + 1 :].split("\n"):
        tokens = line.split()
        if not tokens:
            if out:
                break
            continue
        if re.fullmatch(r"[0-9a-f]{3}", tokens[0]):  # "016  90 91 ...  ascii"
            for tok in tokens[1:17]:
                if not re.fullmatch("[0-9a-f]{2}", tok):
                    break
                out += tok
        elif re.fullmatch(r"([0-9a-f]{2}:)*[0-9a-f]{2}:?", tokens[0]):
            out += tokens[0].replace(":", "")
        elif re.fullmatch(r"[0-9a-f]+", tokens[0]) and len(tokens) == 1:
            out += tokens[0]
        else:
            break
    return bytes.fromhex(out)


def rfc_vectors(h, src, exp):
    suite = Suite("rfc", exp)

    # RFC 5869 appendix A.1-A.3 (the SHA-256 cases; A.4-A.7 are SHA-1, which TLS 1.3 does not use)
    text = src.document("rfc5869").decode()
    for case in ("A.1", "A.2", "A.3"):
        body = text[text.index("\n%s.  Test Case" % case) :]
        body = body[: body.index("\nA.", 1)]
        fields = {}
        for m in re.finditer(r"^   (\w+)\s*= (.*?)(?=^   \w+\s*=|\Z)", body, re.S | re.M):
            # a value ends at its "(n octets)", before any page footer
            fields[m.group(1)] = re.sub(r"\s|0x", "", m.group(2).split("(")[0])
        rc, okm = h("hkdf", "sha256", fields["IKM"], fields["salt"], fields["info"], fields["L"])
        suite.judge(
            "rfc5869",
            case,
            "valid",
            [],
            outcome(rc, okm, bytes.fromhex(fields["OKM"])),
            "hkdf/sha256",
        )

    # RFC 7748 section 5.2 (two X25519 vectors, then 1 and 1000 iterations) and 6.1 (the exchange)
    text = src.document("rfc7748").decode()
    sec = text[text.index("\n5.2.  Test Vectors") :]
    pos = 0
    for n in (1, 2):
        pos = sec.index("Input scalar:", pos)
        k, u = (
            rfc_hex_after(sec, "Input scalar:", pos),
            rfc_hex_after(sec, "Input u-coordinate:", pos),
        )
        want = rfc_hex_after(sec, "Output u-coordinate:", pos)
        rc, out = h("ecdh", "x25519", k.hex(), u.hex())
        suite.judge("rfc7748", "5.2-%d" % n, "valid", [], outcome(rc, out, want), "x25519")
        pos += 1
    k = u = (9).to_bytes(32, "little")
    done = 0
    for target, label in ((1, "After one iteration:"), (1000, "After 1,000 iterations:")):
        while done < target:
            rc, out = h("ecdh", "x25519", k.hex(), u.hex())
            if rc != 0:
                break
            k, u = out, k
            done += 1
        suite.judge(
            "rfc7748", label, "valid", [], outcome(rc, k, rfc_hex_after(sec, label)), "x25519"
        )
    sec = text[text.index("\n6.1.  Curve25519") :]
    a, b = (
        rfc_hex_after(sec, "Alice's private key, a:"),
        rfc_hex_after(sec, "Bob's private key, b:"),
    )
    base = (9).to_bytes(32, "little")
    for name, priv, pub, want in (
        ("6.1 K_A", a, base, rfc_hex_after(sec, "Alice's public key, X25519(a, 9):")),
        ("6.1 K_B", b, base, rfc_hex_after(sec, "Bob's public key, X25519(b, 9):")),
        (
            "6.1 K (Alice)",
            a,
            rfc_hex_after(sec, "Bob's public key, X25519(b, 9):"),
            rfc_hex_after(sec, "Their shared secret, K:"),
        ),
        (
            "6.1 K (Bob)",
            b,
            rfc_hex_after(sec, "Alice's public key, X25519(a, 9):"),
            rfc_hex_after(sec, "Their shared secret, K:"),
        ),
    ):
        rc, out = h("ecdh", "x25519", priv.hex(), pub.hex())
        suite.judge("rfc7748", name, "valid", [], outcome(rc, out, want), "x25519")

    # RFC 8439 section 2.8.2 (seal) and appendix A.5 (open)
    text = src.document("rfc8439").decode()
    sec = text.index("\n2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305")
    pt, aad, key = (rfc_hex_after(text, label, sec) for label in ("Plaintext:", "AAD:", "Key:"))
    nonce = rfc_hex_after(text, "32-bit fixed-common part:", sec) + rfc_hex_after(text, "IV:", sec)
    want = rfc_hex_after(text, "Ciphertext:", sec) + rfc_hex_after(text, "Tag:", sec)
    rc, out = h("seal", "chachapoly", key.hex(), nonce.hex(), aad.hex(), pt.hex(), 16)
    suite.judge(
        "rfc8439", "2.8.2", "valid", [], outcome(rc, out, want), "chacha20-poly1305/k256/t128"
    )
    sec = text.index("\nA.5.  ChaCha20-Poly1305 AEAD Decryption")
    key, ct, nonce, aad, tag, pt = (
        rfc_hex_after(text, label, sec)
        for label in (
            "The ChaCha20 Key",
            "Ciphertext:",
            "The nonce:",
            "The AAD:",
            "Received Tag:",
            "Plaintext::",
        )
    )
    rc, out = h("open", "chachapoly", key.hex(), nonce.hex(), aad.hex(), ct.hex(), tag.hex())
    suite.judge("rfc8439", "A.5", "valid", [], outcome(rc, out, pt), "chacha20-poly1305/k256/t128")
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    rc, out = h("open", "chachapoly", key.hex(), nonce.hex(), aad.hex(), ct.hex(), bad.hex())
    suite.judge("rfc8439", "A.5 tag flipped", "invalid", [], outcome(rc, out, None))

    rfc8448(h, suite, src)
    return suite


def rfc8448_octets(text, anchor, label):
    """A "label (n octets):  xx xx ..." value after an anchor line, checked against its n."""
    i = text.index(label + " (", text.index(anchor))
    m = re.match(r"[^(]*\((\d+) octets\):(.*?)\n\s*\n", text[i:], re.S)
    data = bytes.fromhex(m.group(2))
    if len(data) != int(m.group(1)):
        sys.exit(
            "rfc8448: %s / %s: %d octets, the text says %s" % (anchor, label, len(data), m.group(1))
        )
    return data


def rfc8448(h, suite, src):
    """RFC 8448 section 3 (the simple 1-RTT handshake): the X25519 exchange and the two
    application data records, opened with the traffic keys the trace gives."""
    text = src.document("rfc8448").decode()
    text = text[
        text.index("\n3.  Simple 1-RTT Handshake") : text.index("\n4.  Resumed 0-RTT Handshake")
    ]
    cpriv = rfc8448_octets(text, "{client}  create an ephemeral x25519 key pair", "private key")
    cpub = rfc8448_octets(text, "{client}  create an ephemeral x25519 key pair", "public key")
    spriv = rfc8448_octets(text, "{server}  create an ephemeral x25519 key pair", "private key")
    spub = rfc8448_octets(text, "{server}  create an ephemeral x25519 key pair", "public key")
    shared = rfc8448_octets(text, '{server}  extract secret "handshake"', "IKM")
    for name, priv, pub in (("3 client", cpriv, spub), ("3 server", spriv, cpub)):
        rc, out = h("ecdh", "x25519", priv.hex(), pub.hex())
        suite.judge("rfc8448", name + " ECDHE", "valid", [], outcome(rc, out, shared), "x25519")
    # The client's record is the first under its application keys; the server's comes after
    # the NewSessionTicket record it sent under the same keys
    for side, seq in (("client", 0), ("server", 1)):
        keys = "{%s}  derive write traffic keys for application data" % side
        key, iv = (
            rfc8448_octets(text, keys, "key expanded"),
            rfc8448_octets(text, keys, "iv expanded"),
        )
        record = "{%s}  send application_data record" % side
        payload = rfc8448_octets(text, record, "payload")
        rec = rfc8448_octets(text, record, "complete record")
        # The nonce is the IV XOR the sequence number (RFC 8446 5.3), the additional data the
        # record header, and the plaintext ends in the content type (5.2)
        nonce = (int.from_bytes(iv, "big") ^ seq).to_bytes(len(iv), "big")
        rc, out = h(
            "open", "gcm", key.hex(), nonce.hex(), rec[:5].hex(), rec[5:-16].hex(), rec[-16:].hex()
        )
        suite.judge(
            "rfc8448",
            "3 %s application_data" % side,
            "valid",
            [],
            outcome(rc, out, payload + b"\x17"),
            "aes-gcm/k128/t128",
        )


def cavp_sha(h, src, exp):
    suite = Suite("sha2-cavp", exp)
    archive = zipfile.ZipFile(io.BytesIO(src.document("cavp-sha")))
    for alg in ("SHA256", "SHA384", "SHA512"):
        for kind in ("ShortMsg", "LongMsg"):
            name = "shabytetestvectors/%s%s.rsp" % (alg, kind)
            text = archive.read(name).decode()
            for n, (bits, msg, md) in enumerate(
                re.findall(r"Len = (\d+)\s+Msg = (\w+)\s+MD = (\w+)", text)
            ):
                rc, out = h(
                    "hash",
                    alg.lower(),
                    msg if int(bits) else "",
                )
                suite.judge(name, n, "valid", [], outcome(rc, out, bytes.fromhex(md)), alg.lower())
    return suite


# ---- X.509 ---------------------------------------------------------------------------------


def pem_to_hex(pem):
    body = "".join(line for line in pem.strip().split("\n") if not line.startswith("-----"))
    return base64.b64decode(body).hex()


def pems_to_hex(text):
    return [
        pem_to_hex(m)
        for m in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    ]


# The limbo cases whose outcome depends on the order the intermediates come in: mbedTLS only
# looks for a parent after the child in the presented list (x509_crt.c:2400). x509-limbo runs
# every case in path order, as a server sends it; x509-misordered runs these in limbo's own
# order and records what mbedTLS does with a chain that is out of order.
MISORDERED = [
    "pathlen::intermediate-pathlen-may-increase",
    "pathlen::max-chain-depth-1-self-issued",
    "pathlen::intermediate-violates-pathlen-0",
    "bettertls::pathbuilding::tc2",
    "bettertls::pathbuilding::tc23",
    "bettertls::pathbuilding::tc30",
    "bettertls::pathbuilding::tc32",
    "bettertls::pathbuilding::tc35",
    "bettertls::pathbuilding::tc38",
    "bettertls::pathbuilding::tc71",
    "bettertls::pathbuilding::tc77",
    "bettertls::nameconstraints::tc736",
    "bettertls::nameconstraints::tc7297",
]


def not_applicable(t):
    """Why the engine cannot meet a case, or None: it only verifies servers (tls_engine.c), with
    no CRL (it passes NULL to mbedtls_ssl_conf_ca_chain()), and never without a peer name."""
    if t["validation_kind"] != "SERVER":
        return "CLIENT"
    if "has-crl" in (t.get("features") or []) or t.get("crls"):
        return "has-crl"
    if not t.get("expected_peer_name"):
        return "no peer name"
    return None


def der_tlv(tag, body):
    n = len(body)
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + (bytes([n]) if n < 0x80 else bytes([0x80 | len(size)]) + size) + body


def der_children(data):
    """The TLVs inside a DER constructed value, whole."""
    out, i = [], 2 + (data[1] & 0x7F if data[1] & 0x80 else 0)
    while i < len(data):
        n, h = data[i + 1], 2
        if n & 0x80:
            n, h = int.from_bytes(data[i + 2 : i + 2 + (n & 0x7F)], "big"), 2 + (n & 0x7F)
        out.append(data[i : i + h + n])
        i += h + n
    return out


# A P-256 key that belongs to nobody on any path here (Wycheproof's ecdsa_secp256r1_sha256 key)
DECOY_KEY = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d0301070342000404aaec73635726f213fb8a9e64da3b8632e4"
    "1495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d"
)
DECOY_VALIDITY = der_tlv(0x30, der_tlv(0x17, b"150101000000Z") + der_tlv(0x17, b"160101000000Z"))


def decoy(cert_hex):
    """An expired CA with the certificate's exact name and extensions, but DECOY_KEY and a 2015
    validity: what an attacker can make of any intermediate's name. Its own signature is left as
    it was (mbedTLS reads it only if the decoy were the child)."""
    cert = bytes.fromhex(cert_hex)
    tbs, alg, sig = der_children(cert)
    fields = der_children(tbs)
    first = 1 if fields[0][0] == 0xA0 else 0  # [0] version
    fields[first + 3] = DECOY_VALIDITY  # serial, signature, issuer, validity
    fields[first + 5] = DECOY_KEY  # subject, subjectPublicKeyInfo
    return der_tlv(0x30, der_tlv(0x30, b"".join(fields)) + alg + sig).hex()


class Limbo:
    """The limbo program: one case per line, one "<ret> <flags>" per line."""

    def __init__(self, exe):
        self.exe = exe
        self.proc = subprocess.Popen(
            [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def __call__(self, t, order="path", mode="ca", flip="none", trusted=None):
        when = t["validation_time"]
        when = int(datetime.datetime.fromisoformat(when).timestamp() if when else time.time())
        chain = [pem_to_hex(c) for c in t["untrusted_intermediates"]]
        trusted = trusted if trusted is not None else [pem_to_hex(c) for c in t["trusted_certs"]]
        leaf = pem_to_hex(t["peer_certificate"])
        self.proc.stdin.write(
            " ".join(
                [
                    str(when),
                    t["expected_peer_name"]["value"],
                    order,
                    mode,
                    flip,
                    leaf,
                    str(len(chain)),
                    *chain,
                    str(len(trusted)),
                    *trusted,
                    *([str(len(chain)), *(decoy(c) for c in chain)] if "+decoy" in flip else []),
                ]
            )
            + "\n"
        )
        answer = self.proc.stdout.readline()
        if not answer:
            raise RuntimeError("the limbo harness died on %s" % t["id"])
        ret, _ = answer.split()
        if ret in ("na", "end"):
            return {"na": "n/a", "end": "end"}[ret], []
        # Expectations can name a group of cases by an id prefix ("bettertls::nameconstraints"),
        # or by what is in the certificates: a critical nameConstraints extension (the DER of
        # its OID 2.5.29.30 followed by critical TRUE)
        parts = t["id"].split("::")
        flags = ["::".join(parts[:n]) for n in range(1, len(parts))]
        if any("0603551d1e0101ff" in c for c in [leaf, *chain, *trusted]):
            flags.append("critical-nameConstraints")
        return "accept" if int(ret) == 0 else "reject", flags

    def expired(self, when, certs):
        return [
            line
            for line in subprocess.run(
                [self.exe, "expired", str(when), *certs],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            ).stdout.split("\n")
            if line
        ]

    def bundle(self, certs):
        return subprocess.run(
            [self.exe, "bundle", *certs], capture_output=True, text=True, check=True, timeout=60
        ).stdout.strip()


def limbo_suite(lim, name, source, cases, exp, order="path", missing=()):
    """Cases in x509-limbo's format; returns the suite, a note, and the valid cases it accepted.
    A case that needs code this build does not have (missing) is not applicable."""
    suite = Suite(name, exp)
    skipped = {}
    accepted = []
    for t in cases:
        why = not_applicable(t) or next((n for n in t.get("needs", []) if n in missing), None)
        if why:
            skipped[why] = skipped.get(why, 0) + 1
            suite.not_applicable()
            continue
        # a case can ask for its own order: what mbedTLS does with the chain as listed
        seen, flags = lim(t, order=t.get("order", order), mode=t.get("mode", "ca"))
        result = "valid" if t["expected_result"] == "SUCCESS" else "invalid"
        suite.judge(source, t["id"], result, flags, seen)
        if result == "valid" and seen == "accept" and t.get("order", order) == "path":
            accepted.append((t, t.get("mode", "ca"), None))
    note = (
        ("(not applicable: %s)" % ", ".join("%d %s" % (n, k) for k, n in sorted(skipped.items())))
        if skipped
        else ""
    )
    return suite, note, accepted


def signatures(lim, accepted, exp):
    """Every valid chain accepted above (in CA and in bundle mode), with one byte of a signature
    flipped: the leaf's, and in turn each certificate's above it on the path to the trusted
    certificate. Each broken chain is presented three ways and must be refused each time: as the
    path in order; "spaced", with a filler certificate in front of every parent (so mbedTLS's
    parent search, not adjacency, finds it); and "decoy", with an expired CA of the parent's name
    and another key in front of every parent (so the search's time fallback is taken on the way).
    The unbroken chain with decoys must still be accepted. A flip on a certificate that another
    presented or trusted one also verifies the child of (so could stand in) is not applicable."""
    suite = Suite("x509-signatures", exp)
    for t, mode, trusted in accepted:
        # (only where the first path alone is accepted: a few chains are accepted by a later path)
        if (
            t["untrusted_intermediates"]
            and lim(t, mode=mode, flip="none+spaced", trusted=trusted)[0] == "accept"
        ):
            seen, _ = lim(t, mode=mode, flip="none+decoy", trusted=trusted)
            suite.judge("signatures", "%s/%s/none+decoy" % (t["id"], mode), "valid", [], seen)
        for depth in range(64):
            flip = "path%d" % depth if depth else "leaf"
            seen = None
            for layout in ("", "+spaced", "+decoy"):
                seen, _ = lim(t, mode=mode, flip=flip + layout, trusted=trusted)
                if seen == "end":
                    break
                if seen == "n/a":
                    suite.not_applicable()
                else:
                    suite.judge(
                        "signatures",
                        "%s/%s/%s%s" % (t["id"], mode, flip, layout),
                        "invalid",
                        [],
                        seen,
                    )
            if seen == "end":
                break
    return suite


def bundle_mode(lim, out, cases, local, exp):
    """tls_engine.c's TLS_OPEN_CA_BUNDLE path: ESP-IDF's esp_crt_bundle.c at ESP_IDF_COMMIT, as
    esp_crt_bundle_attach() sets it up (an empty CA chain and esp_crt_verify_callback()), on
    chains made here (x509/, mode "bundle", each with a bundle of its trusted certificates) and on
    real servers' chains from x509-limbo against the image's own bundle. Returns the suite, a note,
    and the valid chains it accepted, for x509-signatures to break in bundle mode too."""
    suite = Suite("x509-bundle", exp)
    accepted = []
    b = os.path.join(out, "esp_crt_bundle")
    # The bundle limbo.c makes, against the one ESP-IDF's generator made for its own test
    made = lim.bundle([read(os.path.join(b, "baltimore.der"), "rb").hex()])
    fixture = read(os.path.join(b, "baltimore_crt_bundle"), "rb").hex()
    suite.judge("x509-bundle", "format", "valid", [], "accept" if made == fixture else "reject")
    # The image's bundle (CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL) and real servers' chains
    real = pems_to_hex(
        read(os.path.join(b, "cacrt_all.pem")) + read(os.path.join(b, "cacrt_local.pem"))
    )
    for t in cases:
        if t["id"].startswith("online::") and not not_applicable(t):
            seen, _ = lim(t, mode="bundle", trusted=real)
            suite.judge(
                "x509-bundle",
                t["id"],
                "valid" if t["expected_result"] == "SUCCESS" else "invalid",
                [],
                seen,
            )
            if seen == "accept" and t["expected_result"] == "SUCCESS":
                accepted.append((t, "bundle", real))
    for t in local:
        seen, flags = lim(t, mode="bundle")
        result = "valid" if t["expected_result"] == "SUCCESS" else "invalid"
        suite.judge("x509", t["id"], result, flags, seen)
        if seen == "accept" and result == "valid":
            accepted.append((t, "bundle", None))
        # A chain from a root that is not in it: the image's bundle must refuse it too
        if t["id"] == "bundle::control::bundle":
            seen, _ = lim(t, mode="bundle", trusted=real)
            suite.judge("x509-bundle", "control-root-not-in-image-bundle", "invalid", [], seen)
    # The roots in the image's bundle that have expired: the bundle keeps no validity, so the
    # device still trusts what they sign (security deviation bundle-root-validity-unchecked)
    expired = lim.expired(int(time.time()), real)
    note = "(image bundle: %d certificates, %d expired: %s)" % (
        len(real),
        len(expired),
        "; ".join(expired),
    )
    return suite, note, accepted


# ---- mbedTLS's own TLS 1.3 key schedule tests -----------------------------------------------


def mbedtls_tls13(out, exp, conditions):
    """mbedTLS's test_suite_ssl cases for the TLS 1.3 key schedule, built with the configuration
    under test: they check HKDF-Expand-Label, Derive-Secret, the secret evolution, traffic keys
    and the PSK binder (mostly against RFC 8448) through the library's internal functions, which
    the public API cannot reach. Its record protection cases set up the transforms of both ends,
    so they only run where the configuration has a server side (MBEDTLS_SSL_SRV_C); without one
    they are counted as not applicable, and the rfc suite opens the RFC 8448 records instead.
    The rest of test_suite_ssl drives both ends of a connection."""
    suite = Suite("mbedtls-tls13-ks", exp)
    tests = os.path.join(out, "build", "tests")
    prefixes = ("SSL TLS 1.3 Key schedule",)
    if "ssl-srv" in conditions:
        prefixes += ("SSL TLS 1.3 Record Encryption",)
    cases = read(os.path.join(tests, "test_suite_ssl.datax")).split("\n\n")
    selected = [e for e in cases if e.startswith(prefixes)]
    na = sum(1 for e in cases if e.startswith("SSL TLS 1.3 Record Encryption")) - sum(
        1 for e in selected if e.startswith("SSL TLS 1.3 Record Encryption")
    )
    datax = os.path.join(out, "tls13_key_schedule.datax")
    with open(datax, "w") as f:
        f.write("\n\n".join(selected) + "\n")
    run = subprocess.run(
        [os.path.join(tests, "test_suite_ssl"), datax],
        cwd=tests,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    results = re.findall(r"^(SSL TLS 1\.3 .*?) ?\.* (PASS|FAILED|----)$", run.stdout, re.M)
    if len(results) != len(selected):
        suite.fail(
            "test_suite_ssl ran %d of the %d selected cases (exit %d)"
            % (len(results), len(selected), run.returncode)
        )
    for name, result in results:
        seen = {"PASS": "accept", "FAILED": "reject", "----": "skip"}[result]
        suite.judge("test_suite_ssl", name.replace(" ", "_"), "valid", [], seen)
    for _ in range(na):
        suite.not_applicable()
    return suite, "(not applicable: %d record protection, no server side)" % na if na else ""


# ---- regressions ---------------------------------------------------------------------------

# Inputs made here for fixed mbedTLS bugs that no vector set above reaches. The verdict is the
# same before and after the fix; the bug is a memory error, which a sanitizer build of the
# older version turns into a crash (run.sh with CRYPTO_CFLAGS='-fsanitize=address,undefined').
# Each names the build condition of the code it reaches, and is not applicable without it.
REGRESSIONS = [
    # mbedTLS 3.6.7 ChangeLog: 1-byte overread parsing a malformed ECC public key
    # (library/pk_ecc.c read the point format byte of an empty point)
    (
        "CVE-2026-50583 P-256 key with an empty point",
        "pk-psa-ec-data",
        (
            "verify",
            "ecdsa",
            "3018301306072a8648ce3d020106082a8648ce3d030107030100",
            "sha256",
            "",
            "3006020101020101",
            0,
        ),
    ),
]


def build_conditions(out):
    """Which conditional code of mbedTLS this build has, for the checks that need it:
    pk-psa-ec-data   MBEDTLS_PK_USE_PSA_EC_DATA (pk.h: USE_PSA_CRYPTO without ECP_C)
    sw-inet-pton     mbedTLS's own inet_pton (x509_crt.c: no AF_INET6, or MBEDTLS_TEST_SW_INET_PTON)
    ssl-srv          MBEDTLS_SSL_SRV_C
    x448             PSA_WANT_ECC_MONTGOMERY_448 (the X448 group)"""
    probe = os.path.join(out, "conditions.c")
    with open(probe, "w") as f:
        f.write(
            '#include "mbedtls/build_info.h"\n#include "mbedtls/pk.h"\n'
            "#if defined(__has_include)\n#if __has_include(<sys/socket.h>)\n#include <sys/socket.h>\n#endif\n"
            "#if __has_include(<arpa/inet.h>)\n#include <arpa/inet.h>\n#endif\n#endif\n"
        )
    flags = [
        f for f in os.environ.get("CRYPTO_CFLAGS", "").split() if f.startswith(("-D", "-U", "-I"))
    ]
    # the include paths and configuration defines build_mbedtls.sh says a program needs
    flags += read(os.path.join(out, "harness.flags")).splitlines()
    macros = subprocess.run(
        ["cc", "-E", "-dM", *flags, probe],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    have = set(re.findall(r"^#define (\w+)", macros, re.M))
    found = set()
    if "MBEDTLS_PK_USE_PSA_EC_DATA" in have:
        found.add("pk-psa-ec-data")
    if "AF_INET6" not in have or "MBEDTLS_TEST_SW_INET_PTON" in have:
        found.add("sw-inet-pton")
    if "MBEDTLS_SSL_SRV_C" in have:
        found.add("ssl-srv")
    if "PSA_WANT_ECC_MONTGOMERY_448" in have:
        found.add("x448")
    return found


def regressions(h, exp, conditions):
    suite = Suite("regressions", exp)
    for name, needs, op in REGRESSIONS:
        if needs not in conditions:
            suite.not_applicable()  # not compiled in this configuration: nothing to check
            continue
        rc, _ = h(*op)
        suite.judge(
            "regressions", name.split()[0], "invalid", [], "accept" if rc == 0 else "reject"
        )
    return suite


# ---- coverage ------------------------------------------------------------------------------

# tls_engine.c's verification surface, which offer() in vectors.c and limbo.c's two ways to
# verify copy, as text: every #define that names an mbedtls_ or esp_crt_ symbol; the whole of
# tls_setup() and tls_open() (the argument checks, the verify and clock gates, the session
# configuration), and tls_set_clock() and tls_build_time() (the clock's floor); every other function that touches the configuration, the BIO, the verify
# callback or the host name; and the functions installed as verify callbacks. Comments and blank
# lines are left out. It must equal engine_config.txt, or the coverage suite fails: the copies
# have to be looked at, and the file updated in the same commit. A text check catches edits, not
# a determined evasion; a test of the engine's behaviour would be stronger (M3).
ENGINE = os.path.join(HERE, "..", "..", "software", "wifi", "raw_u64", "main", "tls_engine.c")
ENGINE_CONFIG = os.path.join(HERE, "engine_config.txt")
ENGINE_FUNCTIONS = ("tls_setup", "tls_open", "tls_set_clock", "tls_build_time")
SURFACE = re.compile(
    r"\b(mbedtls_ssl_conf_\w+|mbedtls_ssl_config_\w+|mbedtls_ssl_set_\w+|mbedtls_ssl_setup|esp_crt_\w+)\s*\("
)


def engine_config(text):
    lines = [re.sub(r"\s*//.*$", "", line).rstrip() for line in text.split("\n")]
    # Top-level functions: a line at column 0 naming one, to the "}" at column 0 that ends it
    functions, i = {}, 0
    while i < len(lines):
        m = re.match(r"^[A-Za-z].*?\b(\w+)\s*\(", lines[i])
        if m and not lines[i].rstrip().endswith(";"):
            end = next((j for j in range(i + 1, len(lines)) if lines[j] == "}"), None)
            if end is not None and any("{" in line for line in lines[i : end + 1]):
                functions.setdefault(m.group(1), []).extend(lines[i : end + 1])
                i = end + 1
                continue
        i += 1
    names = [f for f in ENGINE_FUNCTIONS if f in functions]
    names += [
        f
        for f in functions
        if f not in names and any(SURFACE.search(line) for line in functions[f])
    ]
    callbacks = set(
        re.findall(
            r"mbedtls_ssl_conf_verify\s*\([^,]*,\s*(\w+)",
            "\n".join(line for body in functions.values() for line in body),
        )
    )
    names += sorted(c for c in callbacks if c in functions and c not in names)
    out = [
        line.strip()
        for line in lines
        if line.lstrip().startswith("#define") and re.search(r"mbedtls_|esp_crt_", line)
    ]
    for f in names:
        out += ["== %s" % f] + [line.strip() for line in functions[f] if line.strip()]
    missing = [f for f in ENGINE_FUNCTIONS if f not in functions]
    return [*out, "== missing: %s" % " ".join(missing)] if missing else out


# What a certificate chain may use under the default profile ("vectors profile"), and the
# passing valid vectors each needs: a signature with every allowed hash, on every allowed curve
PROFILE = {
    "md": lambda v: ["pkcs1/" + v, "ecdsa/*/" + v],
    "curve": lambda v: ["ecdsa/%s/*" % v],
    "rsa-min": lambda v: ["pkcs1/*", "pss/*"],
}


def coverage(vectors_exe, suites, exp):
    suite = Suite("coverage", exp)
    covered = set().union(*(s.covered for s in suites if s.ok()))

    def check(item, needs):
        missing = [a for a in needs if not fnmatch.filter(covered, a)]
        if missing:
            suite.fail(
                "%s, and there is no passing valid vector for %s" % (item, ", ".join(missing))
            )
        else:
            suite.passed += 1

    offer = [
        i
        for i in subprocess.run(
            [vectors_exe, "offer"], capture_output=True, text=True, check=True, timeout=60
        ).stdout.split("\n")
        if i
    ]
    for item in offer:
        if item not in OFFERS:
            suite.fail("%s is offered, and no vectors are mapped to it" % item)
        else:
            check("%s is offered" % item, OFFERS[item])
    profile = [
        i
        for i in subprocess.run(
            [vectors_exe, "profile"], capture_output=True, text=True, check=True, timeout=60
        ).stdout.split("\n")
        if i
    ]
    for item in profile:
        kind, value = item.split()
        check("the certificate profile accepts %s" % item, PROFILE[kind](value))
    if os.environ.get("CRYPTO_CONFIG"):
        suite.not_applicable()  # another client's configuration: nothing of tls_engine.c to compare
    elif not os.path.exists(ENGINE):
        suite.fail(
            "%s is not there: a moved or renamed engine is a change the copies must follow" % ENGINE
        )
    else:
        now, recorded = engine_config(read(ENGINE)), read(ENGINE_CONFIG).split("\n")[:-1]
        if now != recorded:
            diff = [
                d for d in difflib.unified_diff(recorded, now, lineterm="", n=0) if d[:1] in "+-"
            ][2:]
            suite.fail(
                "tls_engine.c's verification surface changed: look at offer() in vectors.c and limbo.c, "
                "then update engine_config.txt (%s)" % " | ".join(diff[:6])
            )
        else:
            suite.passed += 1
    return suite, offer


OVERRIDES = (
    "CRYPTO_PINS",
    "CRYPTO_SDKCONFIG",
    "CRYPTO_MACROS",
    "CRYPTO_CACHE",
    "CRYPTO_CONFIG",
    "CRYPTO_CFLAGS",
    "CRYPTO_EXPECTATIONS",
    "CRYPTO_STRICT",
    "CRYPTO_OFFLINE",
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="the build directory run.sh made")
    ap.add_argument(
        "--cache",
        default=os.environ.get("CRYPTO_CACHE", os.path.expanduser("~/.cache/1541u-build/crypto")),
    )
    ap.add_argument("--pins", default=os.environ.get("CRYPTO_PINS", os.path.join(HERE, "PINS")))
    ap.add_argument(
        "--expectations",
        default=os.environ.get("CRYPTO_EXPECTATIONS", os.path.join(HERE, "expectations")),
    )
    ap.add_argument("--verbose", action="store_true", help="list every failure, not the first ten")
    args = ap.parse_args()
    args.out = os.path.abspath(args.out)
    unknown = sorted(k for k in os.environ if k.startswith("CRYPTO_") and k not in OVERRIDES)
    if unknown:
        sys.exit("unknown setting %s (known: %s)" % (", ".join(unknown), ", ".join(OVERRIDES)))
    signal.signal(signal.SIGALRM, lambda *_: sys.exit("timed out after 30 minutes"))
    signal.alarm(1800)

    strict = switch("CRYPTO_STRICT")
    print(
        "expectations %s sha256 %s"
        % (args.expectations, hashlib.sha256(read(args.expectations, "rb")).hexdigest())
    )
    print(
        "strict: %s, offline: %s%s"
        % (
            "on" if strict else "off",
            "on" if OFFLINE else "off",
            ", cflags %s" % os.environ["CRYPTO_CFLAGS"] if os.environ.get("CRYPTO_CFLAGS") else "",
        )
    )
    sdkconfig = os.environ.get("CRYPTO_SDKCONFIG") or os.path.join(
        HERE, "..", "..", "software", "wifi", "raw_u64", "sdkconfig"
    )
    if os.path.exists(sdkconfig):
        spike = re.search(
            r"^(CONFIG_TLS_SPIKE=\S+|# CONFIG_TLS_SPIKE is not set)", read(sdkconfig), re.M
        )
        print(
            "engine: %s (tls_accept_any is %s)"
            % (
                spike.group(1) if spike else "CONFIG_TLS_SPIKE absent",
                "built in" if spike and spike.group(1).endswith("=y") else "not built",
            )
        )
    src = Sources(args.cache, read_pins(args.pins))
    # A build directory from other pins would test another mbedTLS than the summary names
    if os.path.isdir(os.path.join(args.out, "src", ".git")):
        head = subprocess.run(
            ["git", "-C", os.path.join(args.out, "src"), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        if head != src.pins["MBEDTLS_COMMIT"]:
            sys.exit(
                "%s was built from mbedTLS %s, not MBEDTLS_COMMIT %s: run run.sh"
                % (args.out, head, src.pins["MBEDTLS_COMMIT"])
            )
    exp = Expectations(args.expectations, strict)
    conditions = build_conditions(args.out)
    vectors = os.path.join(args.out, "vectors")
    h = Harness(vectors)
    suites = [wycheproof(h, src, exp, name, conditions) for name in WYCHEPROOF]
    suites += [rfc_vectors(h, src, exp), cavp_sha(h, src, exp), regressions(h, exp, conditions)]

    lim = Limbo(os.path.join(args.out, "limbo"))
    limbo_cases = json.loads(src.git("X509_LIMBO", "limbo.json"))["testcases"]
    x_limbo, note_limbo, accepted = limbo_suite(lim, "x509-limbo", "limbo.json", limbo_cases, exp)
    x_mis, note_mis, _ = limbo_suite(
        lim,
        "x509-misordered",
        "limbo.json/given",
        [t for t in limbo_cases if t["id"] in MISORDERED],
        exp,
        order="given",
    )
    # Chains made here for what limbo has no case for (x509/, each with the script that made it)
    local = []
    for f in sorted(os.listdir(os.path.join(HERE, "x509"))):
        if f.endswith(".json"):
            data = src.note("tests/crypto/x509/" + f, read(os.path.join(HERE, "x509", f), "rb"))
            local += json.loads(data)["testcases"]
    x_local, note_local, accepted_local = limbo_suite(
        lim,
        "x509-local",
        "x509",
        [t for t in local if t.get("mode") != "bundle"],
        exp,
        missing={"sw-inet-pton"} - conditions,
    )
    x_bundle, note_bundle, accepted_bundle = bundle_mode(
        lim, args.out, limbo_cases, [t for t in local if t.get("mode") == "bundle"], exp
    )
    x_sig = signatures(lim, accepted + accepted_local + accepted_bundle, exp)
    ks, ks_note = mbedtls_tls13(args.out, exp, conditions)
    suites += [x_limbo, x_mis, x_local, x_sig, x_bundle, ks]
    notes = {
        x_limbo: note_limbo,
        x_mis: note_mis,
        x_local: note_local,
        x_bundle: note_bundle,
        ks: ks_note,
    }
    cov, offer = coverage(vectors, suites, exp)
    suites.append(cov)
    notes[cov] = "offer: " + " ".join(offer)

    stale = Suite("expectations", exp)
    for n, key in exp.unused():
        stale.fail("line %d (%s %s) matched no vector: remove it, or find out why" % (n, *key))
    # The lines behind insecure outcomes are counted with them, not as passed
    insecure_lines = sum(1 for key in exp.used if key in exp.notes)
    stale.passed = len(exp.rules) - stale.failed - insecure_lines
    suites.append(stale)

    with open(os.path.join(args.out, "sources.txt"), "w") as f:
        for name, sha in src.used:
            f.write("%s %s\n" % (sha, name))
    for s in suites:
        print(s.line(notes.get(s, "")))
        for what in s.failures[: None if args.verbose else 10]:
            print("    " + what)
        if len(s.failures) > 10 and not args.verbose:
            print("    ... %d more (--verbose)" % (len(s.failures) - 10))
    passed = sum(s.passed for s in suites)
    failed = sum(s.failed for s in suites)
    ok = all(s.ok() for s in suites)
    replaced = os.path.join(args.out, "config", "replaced.txt")
    alts = read(replaced).split() if os.path.exists(replaced) else []
    if alts:
        print(
            "NOT COVERED: the device uses ESP-IDF hardware code for %s; this host run tests mbedTLS software paths"
            % " ".join(alts)
        )
    deviations = [d for s in suites for d in s.deviations]
    tags = sorted(set(tag for tag, _ in deviations))
    print("SECURITY DEVIATIONS %d%s" % (len(tags), (": " + ", ".join(tags)) if tags else ""))
    fail_open = [d for s in suites for d in s.fail_open]
    by_tag = {}
    for tag, tc in fail_open:
        by_tag.setdefault(tag, []).append(tc.split("::")[-1])
    print(
        "FAIL-OPEN DEVIATIONS %d%s"
        % (
            len(by_tag),
            (": " + "; ".join("%s (%s)" % (tag, " ".join(by_tag[tag])) for tag in sorted(by_tag)))
            if by_tag
            else "",
        )
    )
    known = [k for s in suites for k in s.known]
    cves = sorted(set(cve for cve, _ in known))
    print("KNOWN VULNERABILITIES %d%s" % (len(cves), (": " + ", ".join(cves)) if cves else ""))
    insecure = len(known) + len(deviations) + len(fail_open)
    print(
        "CRYPTO_CONFORMANCE %s %d passed %d failed %d suites; insecure outcomes %d (known-vulnerable %d, "
        "security-deviation %d, fail-open %d) and their %d expectation lines, not in passed"
        % (
            "PASS" if ok else "FAIL",
            passed,
            failed,
            len(suites),
            insecure,
            len(known),
            len(deviations),
            len(fail_open),
            insecure_lines,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SystemExit, Exception) as e:
        if isinstance(e, SystemExit) and not isinstance(e.code, str):
            raise
        # A source that cannot be fetched or does not match its pin, or a harness that crashed
        # (a sanitizer build stops at the first memory error), is a failed run too
        print("%s: %s" % (type(e).__name__, e))
        print("CRYPTO_CONFORMANCE FAIL aborted")
        sys.exit(1)
