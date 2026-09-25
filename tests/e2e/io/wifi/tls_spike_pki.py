#!/usr/bin/env python3
"""The test PKI for the ESP32 TLS spike (M2): one root, five server chains.

SPIKE CODE, not for upstream, like the firmware route it serves.

Everything is written under one directory, `.pki` beside this file unless
`--pki-dir` or $TLS_SPIKE_PKI says otherwise. That directory is git-ignored
(`tests/e2e/io/wifi/.gitignore`): the private keys never enter the repository.

The root is made once and then kept, because the firmware carries its
certificate: a root made afresh on every run would be one the device has never
seen, and every verify-on case would fail for the wrong reason. Leaves and
intermediates are cheap and are re-issued with `--reissue`. The root's SHA-256
fingerprint is in `manifest.json` and in the C snippet, so a run can say which
root a firmware was built with.

    .pki/test-ca.pem            the root certificate, verbatim, for the firmware
    .pki/test_ca_pem.h          the same bytes as a NUL-terminated C string
    .pki/manifest.json          what each chain is meant to be, read by the suite
    .pki/root/                  root.pem, root.key
    .pki/untrusted-root/        a root the device must not trust
    .pki/chains/<name>/         chain.pem (leaf then intermediate), key.pem

Chains, each served as leaf + intermediate (two certificates on the wire), with
the root left for the client's trust store:

    ecdsa      P-256 leaf, P-256 intermediate, for tls-spike.test
    rsa        RSA-2048 leaf, RSA-2048 intermediate, for tls-spike.test
    mismatch   P-256, valid and trusted, but for wrong-host.test only
    expired    P-256, trusted, for tls-spike.test, notAfter 2000-01-01
    untrusted  P-256, for tls-spike.test, under untrusted-root

The root is P-256, so the rsa chain's intermediate carries an ECDSA signature
from it; only the two certificates the server sends hold RSA keys.

Validity starts at 1970-01-01 for every certificate. A device whose clock was
never set still sees the good chains as valid, so a missing clock cannot make
the positive cases fail; only the expired case needs a real clock, which is
exactly what it is testing.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

OPENSSL_ENV = "OPENSSL"
PKI_ENV = "TLS_SPIKE_PKI"
DEFAULT_PKI = Path(__file__).resolve().parent / ".pki"

SNI = "tls-spike.test"
WRONG_HOST = "wrong-host.test"

NOT_BEFORE = "19700101000000Z"
NOT_AFTER = "20491231235959Z"
EXPIRED_NOT_AFTER = "20000101000000Z"

# The alert mbedTLS 3.6.0 sends for each verification failure in TLS 1.3
# (library/ssl_tls13_generic.c:760-777 in the mbedtls ESP-IDF v5.3.1 pins).
# The name is OpenSSL's reason for the alert as the server receives it.
ALERT_BAD_CERT = "SSLV3_ALERT_BAD_CERTIFICATE"         # 42, CN/SAN mismatch
ALERT_CERT_EXPIRED = "SSLV3_ALERT_CERTIFICATE_EXPIRED"  # 45
ALERT_UNKNOWN_CA = "TLSV1_ALERT_UNKNOWN_CA"            # 48

# name -> (key type, subject name, issuing root, notAfter, the alert a verifying
# client must send, and what the chain is for)
CHAINS = {
    "ecdsa": ("ec", SNI, "root", NOT_AFTER, None, "valid P-256 chain"),
    "rsa": ("rsa", SNI, "root", NOT_AFTER, None, "valid RSA-2048 chain"),
    "mismatch": ("ec", WRONG_HOST, "root", NOT_AFTER, ALERT_BAD_CERT,
                 "trusted, but names another host"),
    "expired": ("ec", SNI, "root", EXPIRED_NOT_AFTER, ALERT_CERT_EXPIRED,
                "trusted, right name, expired in 2000"),
    "untrusted": ("ec", SNI, "untrusted-root", NOT_AFTER, ALERT_UNKNOWN_CA,
                  "right name, issued by a root the device does not hold"),
}


def openssl() -> str:
    found = os.environ.get(OPENSSL_ENV) or shutil.which("openssl")
    if not found:
        raise SystemExit("no openssl on PATH; set $OPENSSL")
    return found


def run(*argv: str) -> None:
    result = subprocess.run([openssl(), *argv], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"openssl {' '.join(argv)} failed:\n{result.stderr}")


def pki_dir(explicit: str | None = None) -> Path:
    return Path(explicit or os.environ.get(PKI_ENV) or DEFAULT_PKI)


def new_key(path: Path, kind: str) -> None:
    if kind == "ec":
        run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(path))
    else:
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
            "-out", str(path))
    path.chmod(0o600)


def write_ext(directory: Path, text: str) -> Path:
    path = directory / "ext.cnf"
    path.write_text(text)
    return path


def make_root(directory: Path, common_name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / "root.key", directory / "root.pem"
    if key.exists() and cert.exists():
        return
    new_key(key, "ec")
    ext = write_ext(directory, "[v3]\nbasicConstraints=critical,CA:TRUE\n"
                               "keyUsage=critical,keyCertSign,cRLSign\n"
                               "subjectKeyIdentifier=hash\n")
    run("req", "-new", "-x509", "-key", str(key), "-out", str(cert),
        "-subj", f"/O=1541U TLS spike test/CN={common_name}",
        "-not_before", NOT_BEFORE, "-not_after", NOT_AFTER,
        "-config", str(ext), "-extensions", "v3", "-sha256")
    ext.unlink()


def issue(directory: Path, name: str, key_type: str, subject: str, issuer_cert: Path,
          issuer_key: Path, not_after: str, extensions: str) -> Path:
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    cert = directory / f"{name}.pem"
    new_key(key, key_type)
    run("req", "-new", "-key", str(key), "-out", str(csr), "-subj", subject)
    ext = write_ext(directory, f"[v3]\n{extensions}")
    run("x509", "-req", "-in", str(csr), "-CA", str(issuer_cert), "-CAkey", str(issuer_key),
        "-set_serial", "0x" + os.urandom(8).hex(), "-out", str(cert),
        "-not_before", NOT_BEFORE, "-not_after", not_after,
        "-extfile", str(ext), "-extensions", "v3", "-sha256")
    csr.unlink()
    ext.unlink()
    return cert


def make_chain(pki: Path, name: str) -> None:
    key_type, host, root_name, not_after, _, _ = CHAINS[name]
    directory = pki / "chains" / name
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    root = pki / root_name
    intermediate = issue(
        directory, "int", key_type, f"/O=1541U TLS spike test/CN={name} intermediate",
        root / "root.pem", root / "root.key", NOT_AFTER,
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    usage = "digitalSignature" if key_type == "ec" else "digitalSignature,keyEncipherment"
    leaf = issue(
        directory, "leaf", key_type, f"/O=1541U TLS spike test/CN={host}",
        intermediate, directory / "int.key", not_after,
        "basicConstraints=critical,CA:FALSE\n"
        f"keyUsage=critical,{usage}\nextendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{host}\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    (directory / "chain.pem").write_text(leaf.read_text() + intermediate.read_text())
    (directory / "leaf.key").rename(directory / "key.pem")
    (directory / "int.key").unlink()


def fingerprint(pem_path: Path) -> str:
    der = subprocess.run([openssl(), "x509", "-in", str(pem_path), "-outform", "DER"],
                         capture_output=True, check=True).stdout
    return hashlib.sha256(der).hexdigest()


def c_snippet(pem: str, digest: str) -> str:
    lines = [
        "/* Test root CA for the M2 TLS spike. NOT A SECRET and NOT FOR UPSTREAM.",
        " * Generated by tests/e2e/io/wifi/tls_spike_pki.py; regenerate it, never edit it.",
        f" * SHA-256 of the DER certificate: {digest}",
        " * mbedtls_x509_crt_parse() takes PEM only with the terminating NUL counted:",
        " * pass sizeof(tls_spike_test_ca_pem), not strlen(). */",
        "static const char tls_spike_test_ca_pem[] =",
    ]
    body = [f'    "{line}\\n"' for line in pem.strip().splitlines()]
    body[-1] += ";"
    return "\n".join(lines + body) + "\n"


def generate(pki: Path, reissue: bool = False) -> dict:
    pki.mkdir(parents=True, exist_ok=True)
    make_root(pki / "root", "TLS spike test root")
    make_root(pki / "untrusted-root", "TLS spike UNTRUSTED root")
    for name in CHAINS:
        if reissue or not (pki / "chains" / name / "chain.pem").exists():
            make_chain(pki, name)
    root_pem = (pki / "root" / "root.pem").read_text()
    (pki / "test-ca.pem").write_text(root_pem)
    digest = fingerprint(pki / "root" / "root.pem")
    (pki / "test_ca_pem.h").write_text(c_snippet(root_pem, digest))
    manifest = {
        "sni": SNI,
        "root_sha256": digest,
        "untrusted_root_sha256": fingerprint(pki / "untrusted-root" / "root.pem"),
        "chains": {
            name: {
                "key_type": key_type, "host": host, "root": root_name,
                "not_after": not_after, "expected_alert": alert, "purpose": purpose,
                "leaf_sha256": fingerprint(pki / "chains" / name / "chain.pem"),
            }
            for name, (key_type, host, root_name, not_after, alert, purpose) in CHAINS.items()
        },
    }
    (pki / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def verify_fixtures(pki: Path) -> list[str]:
    """What openssl verify says about each chain, against the intended outcome.

    Returns the problems; empty means every fixture is what its name claims.
    This is the host's own verifier, independent of the server and the device,
    so a fixture that is accidentally valid (or accidentally broken) is caught
    before any case relies on it.
    """
    problems = []
    for name, (_, _, _, _, alert, _) in CHAINS.items():
        directory = pki / "chains" / name
        with tempfile.TemporaryDirectory() as scratch:
            leaf_path = Path(scratch) / "leaf.pem"
            int_path = Path(scratch) / "int.pem"
            pem = (directory / "chain.pem").read_text()
            marker = "-----END CERTIFICATE-----\n"
            leaf, intermediate = pem.split(marker)[0] + marker, pem.split(marker)[1] + marker
            leaf_path.write_text(leaf)
            int_path.write_text(intermediate)
            result = subprocess.run(
                [openssl(), "verify", "-CAfile", str(pki / "test-ca.pem"),
                 "-untrusted", str(int_path), "-verify_hostname", SNI,
                 "-purpose", "sslserver", str(leaf_path)],
                capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        expected = {None: "OK", ALERT_BAD_CERT: "hostname mismatch",
                    ALERT_CERT_EXPIRED: "certificate has expired",
                    ALERT_UNKNOWN_CA: "unable to get local issuer certificate"}[alert]
        ok = (result.returncode == 0) == (alert is None) and expected in output
        if not ok:
            problems.append(f"{name}: openssl verify said {output.strip()!r}, "
                            f"expected {expected!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pki-dir", help=f"output directory (default ${PKI_ENV}, "
                                          f"else {DEFAULT_PKI})")
    parser.add_argument("--reissue", action="store_true",
                        help="re-issue every chain; the two roots are always kept")
    args = parser.parse_args()
    pki = pki_dir(args.pki_dir)
    manifest = generate(pki, args.reissue)
    problems = verify_fixtures(pki)
    for problem in problems:
        print(f"FIXTURE WRONG: {problem}", file=sys.stderr)
    print(f"{pki}: root sha256 {manifest['root_sha256']}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
