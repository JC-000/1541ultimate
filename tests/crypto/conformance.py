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
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Documents fetched by URL: they are immutable, so the sha256 pins them.
DOCUMENTS = {
    'rfc5869': ('https://www.rfc-editor.org/rfc/rfc5869.txt',
                '7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c'),
    'rfc7748': ('https://www.rfc-editor.org/rfc/rfc7748.txt',
                '279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3'),
    'rfc8439': ('https://www.rfc-editor.org/rfc/rfc8439.txt',
                '25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c'),
    'rfc8448': ('https://www.rfc-editor.org/rfc/rfc8448.txt',
                '6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba'),
    'cavp-sha': ('https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/'
                 'documents/shs/shabytetestvectors.zip',
                 '929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8'),
}

# What the TLS 1.3 client offers ("vectors offer" prints it from a real ClientHello), and the
# algorithms each offer needs a passing valid vector for. An offer not listed here fails the
# coverage suite: a new mbedTLS that offers something new needs vectors for it first.
AEAD_SHA256 = ['sha256', 'hmac/sha256', 'hkdf/sha256']
OFFERS = {
    'suite 1301': ['aes-gcm/k128/t128'] + AEAD_SHA256,      # TLS_AES_128_GCM_SHA256
    'suite 1302': ['aes-gcm/k256/t128', 'sha384', 'hmac/sha384', 'hkdf/sha384'],  # TLS_AES_256_GCM_SHA384
    'suite 1303': ['chacha20-poly1305/k256/t128'] + AEAD_SHA256,  # TLS_CHACHA20_POLY1305_SHA256
    'suite 1304': ['aes-ccm/k128/t128'] + AEAD_SHA256,      # TLS_AES_128_CCM_SHA256
    'suite 1305': ['aes-ccm/k128/t64'] + AEAD_SHA256,       # TLS_AES_128_CCM_8_SHA256
    'suite 00ff': [],                                       # renegotiation SCSV, no algorithm
    'group 001d': ['x25519'],
    'group 0017': ['ecdh/secp256r1'],
    'group 0018': ['ecdh/secp384r1'],
    'group 0019': ['ecdh/secp521r1'],
    'keyshare 001d': ['x25519'],
    'sigalg 0403': ['ecdsa/secp256r1/sha256'],
    'sigalg 0503': ['ecdsa/secp384r1/sha384'],
    'sigalg 0603': ['ecdsa/secp521r1/sha512', 'sha512'],
    'sigalg 0804': ['pss/sha256'],                          # rsa_pss_rsae_sha256
    'sigalg 0805': ['pss/sha384'],
    'sigalg 0806': ['pss/sha512', 'sha512'],
    'sigalg 0401': ['pkcs1/sha256'],                        # certificates only in TLS 1.3
    'sigalg 0501': ['pkcs1/sha384'],
    'sigalg 0601': ['pkcs1/sha512', 'sha512'],
}

WYCHEPROOF = {
    'aes-gcm': ['aes_gcm_test.json'],
    'chacha20-poly1305': ['chacha20_poly1305_test.json'],
    'aes-ccm': ['aes_ccm_test.json'],
    'hmac': ['hmac_sha256_test.json', 'hmac_sha384_test.json'],
    'hkdf': ['hkdf_sha256_test.json', 'hkdf_sha384_test.json'],
    'x25519': ['x25519_test.json'],
    'ecdh-nist': ['ecdh_secp256r1_ecpoint_test.json', 'ecdh_secp384r1_ecpoint_test.json',
                  'ecdh_secp521r1_ecpoint_test.json'],
    # CertificateVerify binds curve and hash; a certificate's signature does not, hence the mixes
    'ecdsa': ['ecdsa_secp256r1_sha256_test.json', 'ecdsa_secp256r1_sha512_test.json',
              'ecdsa_secp384r1_sha256_test.json', 'ecdsa_secp384r1_sha384_test.json',
              'ecdsa_secp384r1_sha512_test.json', 'ecdsa_secp521r1_sha512_test.json'],
    'rsa-pkcs1': ['rsa_signature_%d_%s_test.json' % (b, h) for b in (2048, 3072, 4096)
                  for h in ('sha256', 'sha384', 'sha512')],
    # TLS 1.3 only uses rsa_pss_rsae with the salt as long as the hash (ssl_tls13_generic.c)
    'rsa-pss': ['rsa_pss_2048_sha256_mgf1_32_test.json', 'rsa_pss_2048_sha384_mgf1_48_test.json',
                'rsa_pss_3072_sha256_mgf1_32_test.json', 'rsa_pss_4096_sha256_mgf1_32_test.json',
                'rsa_pss_4096_sha384_mgf1_48_test.json', 'rsa_pss_4096_sha512_mgf1_64_test.json'],
}

HASHES = {'SHA-1': 'sha1', 'SHA-224': 'sha224', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512'}
CURVE_BYTES = {'secp256r1': 32, 'secp384r1': 48, 'secp521r1': 66}


def read_pins(path):
    pins = {}
    for line in open(path):
        line = line.split('#', 1)[0].strip()
        if line:
            key, value = line.split('=', 1)
            pins[key] = value
    return pins


class Sources:
    """Fetches and caches what the suites read, and records the sha256 of each file used."""

    def __init__(self, cache, pins):
        self.cache = cache
        self.pins = pins
        self.used = []
        os.makedirs(cache, exist_ok=True)

    def _note(self, name, data):
        self.used.append((name, hashlib.sha256(data).hexdigest()))
        return data

    def git(self, key, path):
        repo, commit = self.pins[key + '_REPO'], self.pins[key + '_COMMIT']
        if not re.fullmatch('[0-9a-f]{40}', commit):
            sys.exit('PINS: %s_COMMIT is not a full SHA' % key)
        name = repo.rstrip('/').split('/')[-1]
        work = os.path.join(self.cache, '%s-%s' % (name, commit))
        if not os.path.isdir(os.path.join(work, '.git')):
            # A partial clone of the one commit: only the files read below are downloaded
            subprocess.run(['git', 'init', '-q', work], check=True)
            subprocess.run(['git', '-C', work, 'fetch', '-q', '--depth', '1', '--filter=blob:none',
                            repo, commit], check=True)
        # git checks every object against its hash, so the content is what the commit says
        data = subprocess.run(['git', '-C', work, 'cat-file', '-p', '%s:%s' % (commit, path)],
                              check=True, capture_output=True).stdout
        return self._note('%s@%s:%s' % (name, commit, path), data)

    def document(self, key):
        url, sha = DOCUMENTS[key]
        path = os.path.join(self.cache, 'sha256-' + sha)
        if not os.path.exists(path):
            # csrc.nist.gov refuses Python's default User-Agent
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/8 (1541u crypto conformance)'})
            data = urllib.request.urlopen(req, timeout=60).read()
            with open(path + '.tmp', 'wb') as f:
                f.write(data)
            os.replace(path + '.tmp', path)
        data = open(path, 'rb').read()
        if hashlib.sha256(data).hexdigest() != sha:
            sys.exit('%s: sha256 mismatch (%s)' % (url, path))
        return self._note(url, data)


class Harness:
    """The vectors program: one operation per line, one result per line."""

    def __init__(self, exe):
        self.proc = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def __call__(self, *fields):
        line = ' '.join(str(f) if f != '' else '-' for f in fields)
        self.proc.stdin.write(line + '\n')
        answer = self.proc.stdout.readline()
        if not answer:
            raise RuntimeError('the vectors harness died on: %s' % line[:200])
        rc, _, out = answer.rstrip('\n').partition(' ')
        return int(rc), bytes.fromhex(out)


class Expectations:
    """Lines of "<vector file> tc=<id>|flag=<name> accept|reject|skip <reason>", or
    "<vector file> tc=<id>|flag=<name> known-vulnerable <CVE> <first fixed mbedTLS version> <reason>".
    A tc= line wins over flag= lines; among flag= lines the first in the file that names one of
    the vector's flags wins. With known_vulnerable False the known-vulnerable lines are ignored."""

    def __init__(self, path, known_vulnerable=True):
        self.rules = {}
        self.cves = {}
        self.used = set()
        for n, line in enumerate(open(path), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split(None, 3)
            if len(fields) == 4 and fields[2] == 'known-vulnerable':
                cve = fields[3].split(None, 2)
                if len(cve) < 3 or not re.fullmatch(r'CVE-\d{4}-\d+', cve[0]):
                    sys.exit('%s:%d: want "... known-vulnerable <CVE> <fixed in> <reason>"' % (path, n))
                if not known_vulnerable:
                    continue
                self.cves[(fields[0], fields[1])] = '%s (fixed in mbedTLS %s)' % (cve[0], cve[1])
            elif len(fields) < 4 or fields[2] not in ('accept', 'reject', 'skip') or '=' not in fields[1]:
                sys.exit('%s:%d: want "<file> tc=N|flag=F accept|reject|skip <reason>"' % (path, n))
            if (fields[0], fields[1]) in self.rules:
                sys.exit('%s:%d: %s %s is there twice' % (path, n, fields[0], fields[1]))
            self.rules[(fields[0], fields[1])] = (fields[2], n)

    def lookup(self, source, tc, flags):
        keys = [(source, 'tc=%s' % tc)] + sorted(((source, 'flag=' + f) for f in flags),
                                                 key=lambda k: self.rules.get(k, (0, 0))[1])
        for key in keys:
            if key in self.rules:
                self.used.add(key)
                return self.rules[key][0], self.cves.get(key)
        return None, None

    def unused(self):
        return sorted((self.rules[k][1], k) for k in self.rules if k not in self.used)


class Suite:
    def __init__(self, name, expectations):
        self.name = name
        self.expectations = expectations
        self.passed = self.failed = 0
        # vectors an expectations line judged: its outcome against the vector's own verdict
        self.decided = {'deviate': 0, 'acceptable': 0, 'agree': 0, 'known-vulnerable': 0}
        self.known = []  # (CVE text, vector) for each vector that still shows a known vulnerability
        self.failures = []
        self.covered = set()

    def fail(self, what):
        self.failed += 1
        self.failures.append(what)

    def judge(self, source, tc, result, flags, observed, cover=None):
        """observed: 'accept', 'reject', or 'wrong' (reported success with the wrong output)."""
        want, cve = self.expectations.lookup(source, tc, flags)
        label = '%s tc=%s (%s, %s)' % (source, tc, result, ' '.join(flags) or '-')
        if observed == 'wrong':
            return self.fail('%s: WRONG OUTPUT' % label)
        own = {'valid': 'accept', 'invalid': 'reject'}.get(result)
        if want == 'known-vulnerable':
            # The vector must still show the vulnerability; once it does not, the line has to go
            if observed == own:
                return self.fail('%s: %s no longer shows: remove its known-vulnerable line' % (label, cve))
            self.decided['known-vulnerable'] += 1
            self.known.append((cve, tc))
            self.passed += 1
            return
        if want is None:
            if result == 'acceptable':
                return self.fail('%s: %s, and no expectation says which outcome is right' % (label, observed))
            want = own
        else:
            self.decided['acceptable' if own is None else 'agree' if want == own else 'deviate'] += 1
        if observed != want:
            return self.fail('%s: %s, expected %s' % (label, observed, want))
        self.passed += 1
        if cover and (result == 'valid') and (observed == 'accept'):
            self.covered.add(cover)

    def ok(self):
        return self.failed == 0 and (self.passed > 0 or self.name == 'expectations')

    def line(self, detail=''):
        text = 'SUITE %-18s %s %5d passed %3d failed' % (self.name, 'PASS' if self.ok() else 'FAIL', self.passed,
                                                          self.failed)
        if any(self.decided.values()):
            text += ' (expectations: %(deviate)d deviate, %(acceptable)d acceptable, %(agree)d agree' % self.decided
            text += (', %(known-vulnerable)d known-vulnerable)' % self.decided) if self.known else ')'
        return text + (' ' + detail if detail else '')


def outcome(rc, out, expected):
    if rc != 0:
        return 'reject'
    return 'accept' if expected is None or out == expected else 'wrong'


# ---- Wycheproof ----------------------------------------------------------------------------

def run_aead(h, suite, source, g, t):
    aead = {'aes_gcm': 'gcm', 'aes_ccm': 'ccm', 'chacha20_poly1305': 'chachapoly'}[source.rsplit('_test', 1)[0]]
    ct, tag = bytes.fromhex(t['ct']), bytes.fromhex(t['tag'])
    rc, pt = h('open', aead, t['key'], t['iv'], t['aad'], t['ct'], t['tag'])
    seen = outcome(rc, pt, bytes.fromhex(t['msg']))
    if seen == 'accept' and t['result'] != 'invalid':
        # The same vector sealed must give the same ciphertext and tag
        rc, out = h('seal', aead, t['key'], t['iv'], t['aad'], t['msg'], len(tag))
        seen = outcome(rc, out, ct + tag)
    cover = '%s/k%d/t%d' % (suite.name, g['keySize'], g['tagSize']) if g['ivSize'] == 96 else None
    suite.judge(source, t['tcId'], t['result'], t['flags'], seen, cover)


def run_mac(h, suite, source, g, t):
    alg = 'sha' + source.split('_sha')[1].split('_')[0]
    rc, mac = h('hmac', alg, t['key'], t['msg'])
    seen = 'accept' if rc == 0 and mac[:g['tagSize'] // 8] == bytes.fromhex(t['tag']) else 'reject'
    suite.judge(source, t['tcId'], t['result'], t['flags'], seen, 'hmac/' + alg)


def run_hkdf(h, suite, source, g, t):
    alg = 'sha' + source.split('_sha')[1].split('_')[0]
    rc, okm = h('hkdf', alg, t['ikm'], t['salt'], t['info'], t['size'])
    suite.judge(source, t['tcId'], t['result'], t['flags'], outcome(rc, okm, bytes.fromhex(t['okm'])),
                'hkdf/' + alg)


def run_ecdh(h, suite, source, g, t):
    curve = g['curve']
    priv = t['private']
    if curve in CURVE_BYTES:
        # Wycheproof gives the scalar as an integer; PSA imports it at exactly the field size
        raw = int(priv, 16).to_bytes(max(CURVE_BYTES[curve], (int(priv, 16).bit_length() + 7) // 8), 'big')
        priv = raw.hex()
    group = 'x25519' if curve == 'curve25519' else curve
    rc, shared = h('ecdh', group, priv, t['public'])
    suite.judge(source, t['tcId'], t['result'], t['flags'], outcome(rc, shared, bytes.fromhex(t['shared'])),
                group if group == 'x25519' else 'ecdh/' + group)


def run_verify(h, suite, source, g, t):
    alg = HASHES[g['sha']]
    if g['type'] == 'EcdsaVerify':
        scheme, slen, cover = 'ecdsa', 0, 'ecdsa/%s/%s' % (g['publicKey']['curve'], alg)
    elif g['type'] == 'RsassaPssVerify':
        if HASHES[g['mgfSha']] != alg:
            sys.exit('%s: TLS 1.3 uses MGF1 with the signature hash' % source)
        scheme, slen, cover = 'pss', g['sLen'], 'pss/' + alg
    else:
        scheme, slen, cover = 'pkcs1', 0, 'pkcs1/' + alg
    rc, _ = h('verify', scheme, g['publicKeyDer'], alg, t['msg'], t['sig'], slen)
    suite.judge(source, t['tcId'], t['result'], t['flags'], 'accept' if rc == 0 else 'reject', cover)


RUNNERS = {'aes-gcm': run_aead, 'chacha20-poly1305': run_aead, 'aes-ccm': run_aead, 'hmac': run_mac,
           'hkdf': run_hkdf, 'x25519': run_ecdh, 'ecdh-nist': run_ecdh, 'ecdsa': run_verify,
           'rsa-pkcs1': run_verify, 'rsa-pss': run_verify}


def wycheproof(h, src, exp, name):
    suite = Suite(name, exp)
    for f in WYCHEPROOF[name]:
        data = json.loads(src.git('WYCHEPROOF', 'testvectors_v1/' + f))
        for g in data['testGroups']:
            for t in g['tests']:
                RUNNERS[name](h, suite, f, g, t)
    return suite


# ---- RFC and NIST CAVP vectors -------------------------------------------------------------

def rfc_hex_after(text, label, start=0):
    """The bytes printed after a label line: one hex string, a hex dump or colon-separated."""
    i = text.index(label, start)
    out = ''
    for line in text[text.index('\n', i) + 1:].split('\n'):
        tokens = line.split()
        if not tokens:
            if out:
                break
            continue
        if re.fullmatch(r'[0-9a-f]{3}', tokens[0]):  # "016  90 91 ...  ascii"
            for tok in tokens[1:17]:
                if not re.fullmatch('[0-9a-f]{2}', tok):
                    break
                out += tok
        elif re.fullmatch(r'([0-9a-f]{2}:)*[0-9a-f]{2}:?', tokens[0]):
            out += tokens[0].replace(':', '')
        elif re.fullmatch(r'[0-9a-f]+', tokens[0]) and len(tokens) == 1:
            out += tokens[0]
        else:
            break
    return bytes.fromhex(out)


def rfc_vectors(h, src, exp):
    suite = Suite('rfc', exp)

    # RFC 5869 appendix A.1-A.3 (the SHA-256 cases; A.4-A.7 are SHA-1, which TLS 1.3 does not use)
    text = src.document('rfc5869').decode()
    for case in ('A.1', 'A.2', 'A.3'):
        body = text[text.index('\n%s.  Test Case' % case):]
        body = body[:body.index('\nA.', 1)]
        fields = {}
        for m in re.finditer(r'^   (\w+)\s*= (.*?)(?=^   \w+\s*=|\Z)', body, re.S | re.M):
            # a value ends at its "(n octets)", before any page footer
            fields[m.group(1)] = re.sub(r'\s|0x', '', m.group(2).split('(')[0])
        rc, okm = h('hkdf', 'sha256', fields['IKM'], fields['salt'], fields['info'], fields['L'])
        suite.judge('rfc5869', case, 'valid', [], outcome(rc, okm, bytes.fromhex(fields['OKM'])), 'hkdf/sha256')

    # RFC 7748 section 5.2 (two X25519 vectors, then 1 and 1000 iterations) and 6.1 (the exchange)
    text = src.document('rfc7748').decode()
    sec = text[text.index('\n5.2.  Test Vectors'):]
    pos = 0
    for n in (1, 2):
        pos = sec.index('Input scalar:', pos)
        k, u = rfc_hex_after(sec, 'Input scalar:', pos), rfc_hex_after(sec, 'Input u-coordinate:', pos)
        want = rfc_hex_after(sec, 'Output u-coordinate:', pos)
        rc, out = h('ecdh', 'x25519', k.hex(), u.hex())
        suite.judge('rfc7748', '5.2-%d' % n, 'valid', [], outcome(rc, out, want), 'x25519')
        pos += 1
    k = u = (9).to_bytes(32, 'little')
    done = 0
    for target, label in ((1, 'After one iteration:'), (1000, 'After 1,000 iterations:')):
        while done < target:
            rc, out = h('ecdh', 'x25519', k.hex(), u.hex())
            if rc != 0:
                break
            k, u = out, k
            done += 1
        suite.judge('rfc7748', label, 'valid', [], outcome(rc, k, rfc_hex_after(sec, label)), 'x25519')
    sec = text[text.index('\n6.1.  Curve25519'):]
    a, b = rfc_hex_after(sec, "Alice's private key, a:"), rfc_hex_after(sec, "Bob's private key, b:")
    base = (9).to_bytes(32, 'little')
    for name, priv, pub, want in (
            ('6.1 K_A', a, base, rfc_hex_after(sec, "Alice's public key, X25519(a, 9):")),
            ('6.1 K_B', b, base, rfc_hex_after(sec, "Bob's public key, X25519(b, 9):")),
            ('6.1 K (Alice)', a, rfc_hex_after(sec, "Bob's public key, X25519(b, 9):"),
             rfc_hex_after(sec, 'Their shared secret, K:')),
            ('6.1 K (Bob)', b, rfc_hex_after(sec, "Alice's public key, X25519(a, 9):"),
             rfc_hex_after(sec, 'Their shared secret, K:'))):
        rc, out = h('ecdh', 'x25519', priv.hex(), pub.hex())
        suite.judge('rfc7748', name, 'valid', [], outcome(rc, out, want), 'x25519')

    # RFC 8439 section 2.8.2 (seal) and appendix A.5 (open)
    text = src.document('rfc8439').decode()
    sec = text.index('\n2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305')
    pt, aad, key = (rfc_hex_after(text, label, sec) for label in ('Plaintext:', 'AAD:', 'Key:'))
    nonce = rfc_hex_after(text, '32-bit fixed-common part:', sec) + rfc_hex_after(text, 'IV:', sec)
    want = rfc_hex_after(text, 'Ciphertext:', sec) + rfc_hex_after(text, 'Tag:', sec)
    rc, out = h('seal', 'chachapoly', key.hex(), nonce.hex(), aad.hex(), pt.hex(), 16)
    suite.judge('rfc8439', '2.8.2', 'valid', [], outcome(rc, out, want), 'chacha20-poly1305/k256/t128')
    sec = text.index('\nA.5.  ChaCha20-Poly1305 AEAD Decryption')
    key, ct, nonce, aad, tag, pt = (rfc_hex_after(text, label, sec) for label in (
        'The ChaCha20 Key', 'Ciphertext:', 'The nonce:', 'The AAD:', 'Received Tag:', 'Plaintext::'))
    rc, out = h('open', 'chachapoly', key.hex(), nonce.hex(), aad.hex(), ct.hex(), tag.hex())
    suite.judge('rfc8439', 'A.5', 'valid', [], outcome(rc, out, pt), 'chacha20-poly1305/k256/t128')
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    rc, out = h('open', 'chachapoly', key.hex(), nonce.hex(), aad.hex(), ct.hex(), bad.hex())
    suite.judge('rfc8439', 'A.5 tag flipped', 'invalid', [], outcome(rc, out, None))

    rfc8448(h, suite, src)
    return suite


def rfc8448_octets(text, anchor, label):
    """A "label (n octets):  xx xx ..." value after an anchor line, checked against its n."""
    i = text.index(label + ' (', text.index(anchor))
    m = re.match(r'[^(]*\((\d+) octets\):(.*?)\n\s*\n', text[i:], re.S)
    data = bytes.fromhex(m.group(2))
    if len(data) != int(m.group(1)):
        sys.exit('rfc8448: %s / %s: %d octets, the text says %s' % (anchor, label, len(data), m.group(1)))
    return data


def rfc8448(h, suite, src):
    """RFC 8448 section 3 (the simple 1-RTT handshake): the X25519 exchange and the two
    application data records, opened with the traffic keys the trace gives."""
    text = src.document('rfc8448').decode()
    text = text[text.index('\n3.  Simple 1-RTT Handshake'):text.index('\n4.  Resumed 0-RTT Handshake')]
    cpriv = rfc8448_octets(text, '{client}  create an ephemeral x25519 key pair', 'private key')
    cpub = rfc8448_octets(text, '{client}  create an ephemeral x25519 key pair', 'public key')
    spriv = rfc8448_octets(text, '{server}  create an ephemeral x25519 key pair', 'private key')
    spub = rfc8448_octets(text, '{server}  create an ephemeral x25519 key pair', 'public key')
    shared = rfc8448_octets(text, '{server}  extract secret "handshake"', 'IKM')
    for name, priv, pub in (('3 client', cpriv, spub), ('3 server', spriv, cpub)):
        rc, out = h('ecdh', 'x25519', priv.hex(), pub.hex())
        suite.judge('rfc8448', name + ' ECDHE', 'valid', [], outcome(rc, out, shared), 'x25519')
    # The client's record is the first under its application keys; the server's comes after
    # the NewSessionTicket record it sent under the same keys
    for side, seq in (('client', 0), ('server', 1)):
        keys = '{%s}  derive write traffic keys for application data' % side
        key, iv = rfc8448_octets(text, keys, 'key expanded'), rfc8448_octets(text, keys, 'iv expanded')
        record = '{%s}  send application_data record' % side
        payload = rfc8448_octets(text, record, 'payload')
        rec = rfc8448_octets(text, record, 'complete record')
        # The nonce is the IV XOR the sequence number (RFC 8446 5.3), the additional data the
        # record header, and the plaintext ends in the content type (5.2)
        nonce = (int.from_bytes(iv, 'big') ^ seq).to_bytes(len(iv), 'big')
        rc, out = h('open', 'gcm', key.hex(), nonce.hex(), rec[:5].hex(), rec[5:-16].hex(), rec[-16:].hex())
        suite.judge('rfc8448', '3 %s application_data' % side, 'valid', [],
                    outcome(rc, out, payload + b'\x17'), 'aes-gcm/k128/t128')


def cavp_sha(h, src, exp):
    suite = Suite('sha2-cavp', exp)
    archive = zipfile.ZipFile(io.BytesIO(src.document('cavp-sha')))
    for alg in ('SHA256', 'SHA384', 'SHA512'):
        for kind in ('ShortMsg', 'LongMsg'):
            name = 'shabytetestvectors/%s%s.rsp' % (alg, kind)
            text = archive.read(name).decode()
            for n, (bits, msg, md) in enumerate(re.findall(r'Len = (\d+)\s+Msg = (\w+)\s+MD = (\w+)', text)):
                rc, out = h('hash', alg.lower(), msg if int(bits) else '', )
                suite.judge(name, n, 'valid', [], outcome(rc, out, bytes.fromhex(md)), alg.lower())
    return suite


# ---- x509-limbo ----------------------------------------------------------------------------

def pem_to_hex(pem):
    body = ''.join(l for l in pem.strip().split('\n') if not l.startswith('-----'))
    return base64.b64decode(body).hex()


def limbo(exe, name, source, cases, exp):
    """SERVER cases in x509-limbo's format through limbo.c. Not applicable, and counted as such:
    CLIENT cases (the engine only verifies servers), cases with CRLs (it configures none:
    tls_engine.c passes no CRL to mbedtls_ssl_conf_ca_chain()), and cases without a peer name
    (it refuses to verify without one)."""
    suite = Suite(name, exp)
    skipped = {'CLIENT': 0, 'has-crl': 0, 'no peer name': 0}
    run = []
    for t in cases:
        if t['validation_kind'] != 'SERVER':
            skipped['CLIENT'] += 1
        elif 'has-crl' in (t.get('features') or []) or t.get('crls'):
            skipped['has-crl'] += 1
        elif not t.get('expected_peer_name'):
            skipped['no peer name'] += 1
        else:
            run.append(t)
    proc = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    for t in run:
        when = t['validation_time']
        when = int(datetime.datetime.fromisoformat(when).timestamp()) if when else int(datetime.datetime.now().timestamp())
        chain = [pem_to_hex(c) for c in t['untrusted_intermediates']]
        trusted = [pem_to_hex(c) for c in t['trusted_certs']]
        leaf = pem_to_hex(t['peer_certificate'])
        proc.stdin.write(' '.join([str(when), t['expected_peer_name']['value'], leaf, str(len(chain))] + chain +
                                  [str(len(trusted))] + trusted) + '\n')
        answer = proc.stdout.readline()
        if not answer:
            raise RuntimeError('the limbo harness died on %s' % t['id'])
        ret, flags = answer.split()
        seen = 'accept' if int(ret) == 0 else 'reject'
        result = 'valid' if t['expected_result'] == 'SUCCESS' else 'invalid'
        # Expectations can name a group of cases by an id prefix ("bettertls::nameconstraints"),
        # or by what is in the certificates: a critical nameConstraints extension (the DER of
        # its OID 2.5.29.30 followed by critical TRUE)
        parts = t['id'].split('::')
        flags = ['::'.join(parts[:n]) for n in range(1, len(parts))]
        if any('0603551d1e0101ff' in c for c in [leaf] + chain + trusted):
            flags.append('critical-nameConstraints')
        suite.judge(source, t['id'], result, flags, seen)
    proc.stdin.close()
    proc.wait()
    return suite, 'not applicable: %s' % ', '.join('%d %s' % (n, k) for k, n in skipped.items())


# ---- mbedTLS's own TLS 1.3 key schedule tests -----------------------------------------------

def mbedtls_tls13(out, exp):
    """mbedTLS's test_suite_ssl cases for the TLS 1.3 key schedule, built with the configuration
    under test: they check HKDF-Expand-Label, Derive-Secret, the secret evolution, traffic keys
    and the PSK binder (mostly against RFC 8448) through the library's internal functions, which
    the public API cannot reach. Its record protection cases set up the transforms of both ends,
    so they only run where the configuration has a server side (MBEDTLS_SSL_SRV_C); without one
    they are counted as not applicable, and the rfc suite opens the RFC 8448 records instead.
    The rest of test_suite_ssl drives both ends of a connection."""
    suite = Suite('mbedtls-tls13-ks', exp)
    tests = os.path.join(out, 'build', 'tests')
    macros = subprocess.run(['cc', '-E', '-dM', '-I', os.path.join(out, 'config'), '-I', os.path.join(out, 'src', 'include'),
                             '-DMBEDTLS_CONFIG_FILE="mbedtls_host.h"',
                             os.path.join(out, 'src', 'include', 'mbedtls', 'build_info.h')],
                            capture_output=True, text=True, check=True).stdout
    prefixes = ('SSL TLS 1.3 Key schedule',)
    if re.search(r'^#define MBEDTLS_SSL_SRV_C\b', macros, re.M):
        prefixes += ('SSL TLS 1.3 Record Encryption',)
    cases = open(os.path.join(tests, 'test_suite_ssl.datax')).read().split('\n\n')
    selected = [e for e in cases if e.startswith(prefixes)]
    na = sum(1 for e in cases if e.startswith('SSL TLS 1.3 Record Encryption')) - \
        sum(1 for e in selected if e.startswith('SSL TLS 1.3 Record Encryption'))
    datax = os.path.join(out, 'tls13_key_schedule.datax')
    with open(datax, 'w') as f:
        f.write('\n\n'.join(selected) + '\n')
    run = subprocess.run([os.path.join(tests, 'test_suite_ssl'), datax], cwd=tests, capture_output=True, text=True)
    results = re.findall(r'^(SSL TLS 1\.3 .*?) ?\.* (PASS|FAILED|----)$', run.stdout, re.M)
    if len(results) != len(selected):
        suite.fail('test_suite_ssl ran %d of the %d selected cases (exit %d)' % (len(results), len(selected), run.returncode))
    for name, result in results:
        seen = {'PASS': 'accept', 'FAILED': 'reject', '----': 'skip'}[result]
        suite.judge('test_suite_ssl', name.replace(' ', '_'), 'valid', [], seen)
    return suite, ('not applicable: %d record protection (no server side)' % na) if na else ''


# ---- regressions ---------------------------------------------------------------------------

# Inputs made here for fixed mbedTLS bugs that no vector set above reaches. The verdict is the
# same before and after the fix; the bug is a memory error, which a sanitizer build of the
# older version turns into a crash (run.sh with CRYPTO_CFLAGS='-fsanitize=address,undefined').
REGRESSIONS = [
    # mbedTLS 3.6.7 ChangeLog: 1-byte overread parsing a malformed ECC public key
    # (library/pk_ecc.c read the point format byte of an empty point). That code is only built
    # with MBEDTLS_PK_USE_PSA_EC_DATA (USE_PSA_CRYPTO without ECP_C), which the ESP32's
    # configuration does not have; a main-CPU configuration may.
    ('CVE-2026-50583 P-256 key with an empty point',
     ('verify', 'ecdsa', '3018301306072a8648ce3d020106082a8648ce3d030107030100', 'sha256', '', '3006020101020101', 0)),
]


def regressions(h, exp):
    suite = Suite('regressions', exp)
    for name, op in REGRESSIONS:
        rc, _ = h(*op)
        suite.judge('regressions', name.split()[0], 'invalid', [], 'accept' if rc == 0 else 'reject')
    return suite


# ---- coverage ------------------------------------------------------------------------------

def coverage(vectors_exe, suites, exp):
    suite = Suite('coverage', exp)
    offer = subprocess.run([vectors_exe, 'offer'], capture_output=True, text=True, check=True).stdout.split('\n')
    covered = set().union(*(s.covered for s in suites if s.ok()))
    for item in filter(None, offer):
        if item not in OFFERS:
            suite.fail('%s is offered, and no vectors are mapped to it' % item)
            continue
        missing = [a for a in OFFERS[item] if a not in covered]
        if missing:
            suite.fail('%s is offered, and has no passing valid vector for %s' % (item, ', '.join(missing)))
        else:
            suite.passed += 1
    return suite, [i for i in offer if i]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, help='the build directory run.sh made')
    ap.add_argument('--cache', default=os.environ.get('CRYPTO_CACHE', os.path.expanduser('~/.cache/1541u-build/crypto')))
    ap.add_argument('--pins', default=os.environ.get('CRYPTO_PINS', os.path.join(HERE, 'PINS')))
    ap.add_argument('--expectations', default=os.environ.get('CRYPTO_EXPECTATIONS', os.path.join(HERE, 'expectations')))
    ap.add_argument('--verbose', action='store_true', help='list every failure, not the first ten')
    args = ap.parse_args()
    args.out = os.path.abspath(args.out)

    src = Sources(args.cache, read_pins(args.pins))
    # CRYPTO_KNOWN_VULNERABLE=0 ignores the known-vulnerable lines, to show what they hold back
    exp = Expectations(args.expectations, os.environ.get('CRYPTO_KNOWN_VULNERABLE', '1') != '0')
    vectors = os.path.join(args.out, 'vectors')
    h = Harness(vectors)
    suites = [wycheproof(h, src, exp, name) for name in WYCHEPROOF]
    suites += [rfc_vectors(h, src, exp), cavp_sha(h, src, exp), regressions(h, exp)]
    lim, lim_note = limbo(os.path.join(args.out, 'limbo'), 'x509-limbo', 'limbo.json',
                          json.loads(src.git('X509_LIMBO', 'limbo.json'))['testcases'], exp)
    # Chains made here for what limbo has no case for (x509/, each with the script that made it)
    local = [(f, json.load(open(os.path.join(HERE, 'x509', f)))['testcases'])
             for f in sorted(os.listdir(os.path.join(HERE, 'x509'))) if f.endswith('.json')]
    cve, _ = limbo(os.path.join(args.out, 'limbo'), 'x509-local', 'x509', [t for _, ts in local for t in ts], exp)
    ks, ks_note = mbedtls_tls13(args.out, exp)
    suites += [lim, cve, ks]
    cov, offer = coverage(vectors, suites, exp)
    suites.append(cov)

    stale = Suite('expectations', exp)
    for n, key in exp.unused():
        stale.fail('line %d (%s %s) matched no vector: remove it, or find out why' % (n, *key))
    stale.passed = len(exp.rules) - stale.failed
    suites.append(stale)

    with open(os.path.join(args.out, 'sources.txt'), 'w') as f:
        for name, sha in src.used:
            f.write('%s %s\n' % (sha, name))
    for s in suites:
        detail = ('offer: ' + ' '.join(offer)) if s is cov else lim_note if s is lim else ks_note if s is ks else ''
        print(s.line(detail))
        for what in s.failures[:None if args.verbose else 10]:
            print('    ' + what)
        if len(s.failures) > 10 and not args.verbose:
            print('    ... %d more (--verbose)' % (len(s.failures) - 10))
    passed = sum(s.passed for s in suites)
    failed = sum(s.failed for s in suites)
    ok = all(s.ok() for s in suites)
    known = [k for s in suites for k in s.known]
    cves = sorted(set(cve for cve, _ in known))
    if cves:
        print('KNOWN VULNERABILITIES %d: %s' % (len(cves), ', '.join(cves)))
    print('CRYPTO_CONFORMANCE %s %d passed %d failed %d suites%s' % (
        'PASS' if ok else 'FAIL', passed, failed, len(suites), ' known-vulnerable %d' % len(known) if known else ''))
    return 0 if ok else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (SystemExit, Exception) as e:
        if isinstance(e, SystemExit) and not isinstance(e.code, str):
            raise
        # A source that cannot be fetched or does not match its pin, or a harness that crashed
        # (a sanitizer build stops at the first memory error), is a failed run too
        print('%s: %s' % (type(e).__name__, e))
        print('CRYPTO_CONFORMANCE FAIL aborted')
        sys.exit(1)
