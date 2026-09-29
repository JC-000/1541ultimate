#!/usr/bin/env python3
"""
Writes x509-limbo style SERVER cases for fixed mbedTLS bugs that x509-limbo has no case for.

cve-2026-49300.json: CVE-2026-49300, where mbedTLS up to
3.6.6 read a malformed basicConstraints as cA=TRUE, so that a certificate every other parser
takes for an end entity could issue certificates. Fixed in mbedTLS 3.6.7 by Mbed-TLS/mbedtls
07f45b87 ("Fix lax basicConstraints parsing") and f67b8e5b ("Stop accepting basicConstraints
with only pathLenConstraint"); see its ChangeLog.

Each case is root -> X -> a leaf for victim.example signed with X's key, and must FAIL unless X
really is a CA.

cve-2026-25833.json: CVE-2026-25833, a read before the host name in mbedTLS's own IPv6 parser
(x509_inet_pton_ipv6(), fixed in 3.6.6), reached when a certificate has an IP address
subjectAltName and the name has a ':'. The verdict does not change with the fix: a sanitizer
build shows the read. mbedTLS only compiles that parser where the platform has no inet_pton
(no AF_INET6) or with MBEDTLS_TEST_SW_INET_PTON; a macOS or Linux host uses the libc one.

signatures.json: chains where one signature does not verify, which must be refused, and a
cross-signed pair where only one of two same-named issuers verifies, which must be accepted.

bundle.json: the checks ESP-IDF's certificate bundle (esp_crt_verify_callback() in
esp_crt_bundle.c) leaves out, each chain once with the root as the CA chain ("ca") and once with
the root in a bundle ("bundle"): a SHA-1 signature under the root, an expired root, an RSA-1024
root. The bundle keeps only a root's name and key, and its callback clears the flags once that
key verifies the signature below it.

The keys are made fresh and thrown away; only the certificates are written. Needs the
"cryptography" package; conformance.py only reads the JSON.
"""

import ipaddress
import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.UTC)
VALIDATION_TIME = "2027-01-01T00:00:00+00:00"
BASIC_CONSTRAINTS = x509.ObjectIdentifier("2.5.29.19")

# The basicConstraints values X carries (the extnValue contents, DER)
X_VARIANTS = {
    # SEQUENCE { INTEGER 1 }: RFC 5280 reads a pathLenConstraint with cA absent (FALSE);
    # mbedTLS <= 3.6.6 read the INTEGER as cA and took 1 as TRUE (f67b8e5b)
    "integer-as-ca": bytes.fromhex("3003020101"),
    # SEQUENCE {} followed by BOOLEAN TRUE inside the extension: the SEQUENCE is empty, so cA is
    # FALSE; mbedTLS <= 3.6.6 read on past the SEQUENCE's end to the end of the extension (07f45b87)
    "bool-after-empty-sequence": bytes.fromhex("30000101ff"),
    # Controls: a well-formed cA=FALSE (must fail on every version) and a real CA (must pass)
    "control-not-ca": bytes.fromhex("3000"),
    "control-ca": bytes.fromhex("30030101ff"),
}


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def der(tag, body):
    n = len(body)
    length = (
        bytes([n])
        if n < 0x80
        else bytes([0x80 | ((n.bit_length() + 7) // 8)])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + length + body


def children(data):
    """The TLVs inside a DER constructed value, whole."""
    out, i = [], 2 + (data[1] & 0x7F if data[1] & 0x80 else 0)
    while i < len(data):
        n, h = data[i + 1], 2
        if n & 0x80:
            n, h = int.from_bytes(data[i + 2 : i + 2 + (n & 0x7F)], "big"), 2 + (n & 0x7F)
        out.append(data[i : i + h + n])
        i += h + n
    return out


def resign_sha1(c, issuer_key):
    """The certificate re-signed with ecdsa-with-SHA1 (cryptography refuses to make one): the
    signature algorithm in the TBS and outside it replaced, and the TBS signed again."""
    sha1 = der(0x30, der(0x06, bytes.fromhex("2a8648ce3d0401")))  # 1.2.840.10045.4.1
    tbs = children(c.public_bytes(serialization.Encoding.DER))[0]
    fields = children(tbs)
    fields[2] = sha1
    tbs = der(0x30, b"".join(fields))
    sig = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA1()))
    return x509.load_der_x509_certificate(der(0x30, tbs + sha1 + der(0x03, b"\0" + sig)))


def cert(
    subject,
    key,
    issuer,
    issuer_key,
    extensions,
    sha1=False,
    not_after=NOT_AFTER,
    not_before=NOT_BEFORE,
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical)
    c = builder.sign(issuer_key, hashes.SHA256())
    return resign_sha1(c, issuer_key) if sha1 else c


CA = [
    (x509.BasicConstraints(ca=True, path_length=None), True),
    (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
]


def server(host):
    return [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
        (x509.SubjectAlternativeName([x509.DNSName(host)]), False),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
    ]


def p256():
    return ec.generate_private_key(ec.SECP256R1())


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


def case(case_id, description, root, intermediates, leaf, peer_name, result, **extra):
    return {
        "id": case_id,
        "description": description,
        "validation_kind": "SERVER",
        "trusted_certs": [pem(r) for r in (root if isinstance(root, list) else [root])],
        "untrusted_intermediates": [pem(c) for c in intermediates],
        "peer_certificate": pem(leaf),
        "validation_time": VALIDATION_TIME,
        "expected_peer_name": {
            "kind": "IP" if peer_name[0].isdigit() else "DNS",
            "value": peer_name,
        },
        "expected_result": result,
        "features": [],
        "crls": [],
        **extra,
    }


def write(filename, cases):
    with open(os.path.join(HERE, filename), "w") as f:
        json.dump({"version": 1, "testcases": cases}, f, indent=1)
        f.write("\n")


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = cert(
        "cve-2026-49300 root",
        root_key,
        "cve-2026-49300 root",
        root_key,
        [
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
        ],
    )
    cases = []
    for variant, bc in X_VARIANTS.items():
        # X with no keyUsage, as mbedTLS then lets it sign certificates; and X with the
        # digitalSignature-only keyUsage a server certificate has, which mbedTLS refuses as a parent
        for ku in (None, "digitalsignature"):
            x_key = ec.generate_private_key(ec.SECP256R1())
            x_ext = [
                (x509.UnrecognizedExtension(BASIC_CONSTRAINTS, bc), True),
                (x509.SubjectAlternativeName([x509.DNSName("x.example")]), False),
                (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
            ]
            if ku:
                x_ext.append(
                    (
                        x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                        True,
                    )
                )
            x_cert = cert("cve-2026-49300 X", x_key, "cve-2026-49300 root", root_key, x_ext)
            leaf_key = ec.generate_private_key(ec.SECP256R1())
            leaf = cert(
                "victim.example",
                leaf_key,
                "cve-2026-49300 X",
                x_key,
                [
                    (x509.BasicConstraints(ca=False, path_length=None), True),
                    (
                        x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                        True,
                    ),
                    (x509.SubjectAlternativeName([x509.DNSName("victim.example")]), False),
                    (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
                ],
            )
            cases.append(
                case(
                    "cve-2026-49300::%s%s" % (variant, "-ku-digitalsignature" if ku else ""),
                    "root -> X -> victim.example; X basicConstraints extnValue %s%s"
                    % (bc.hex(), ", keyUsage digitalSignature" if ku else ", no keyUsage"),
                    root,
                    [x_cert],
                    leaf,
                    "victim.example",
                    "SUCCESS" if variant == "control-ca" and not ku else "FAILURE",
                )
            )
    write("cve-2026-49300.json", cases)

    # A server certificate for 192.0.2.1 straight from the root
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = cert(
        "192.0.2.1",
        leaf_key,
        "cve-2026-49300 root",
        root_key,
        [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
            (
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("192.0.2.1"))]),
                False,
            ),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        ],
    )
    write(
        "cve-2026-25833.json",
        [
            # IPv4 digits first and a ':' later: the old parser walked back past the name's start
            case(
                "cve-2026-25833::ipv4-then-colons",
                'IP SAN 192.0.2.1, peer name "1.2.3.4::"',
                root,
                [],
                leaf,
                "1.2.3.4::",
                "FAILURE",
                needs=["sw-inet-pton"],
            ),
            case(
                "cve-2026-25833::control",
                'IP SAN 192.0.2.1, peer name "192.0.2.1"',
                root,
                [],
                leaf,
                "192.0.2.1",
                "SUCCESS",
            ),
        ],
    )

    # One signature that does not verify: the names chain, the key is another one
    ica_key, other = p256(), p256()
    ica = cert("sig ICA", ica_key, "cve-2026-49300 root", root_key, CA)
    ica_wrong = cert("sig ICA", ica_key, "cve-2026-49300 root", other, CA)
    leaf_key = p256()
    cases = [
        case(
            "signatures::leaf-signed-by-other-key",
            "root -> leaf, the leaf signed by a key not the root's",
            root,
            [],
            cert(
                "victim.example", leaf_key, "cve-2026-49300 root", other, server("victim.example")
            ),
            "victim.example",
            "FAILURE",
        ),
        case(
            "signatures::intermediate-signed-by-other-key",
            "root -> ICA (signed by another key) -> leaf",
            root,
            [ica_wrong],
            cert("victim.example", leaf_key, "sig ICA", ica_key, server("victim.example")),
            "victim.example",
            "FAILURE",
        ),
        # In the order listed, the ICA that does not verify first: what mbedTLS does itself
        case(
            "signatures::cross-signed-one-good",
            "two ICAs of one name and key, only the second signed by the root",
            root,
            [ica_wrong, ica],
            cert("victim.example", leaf_key, "sig ICA", ica_key, server("victim.example")),
            "victim.example",
            "SUCCESS",
            order="given",
        ),
        case(
            "signatures::control",
            "root -> ICA -> leaf",
            root,
            [ica],
            cert("victim.example", leaf_key, "sig ICA", ica_key, server("victim.example")),
            "victim.example",
            "SUCCESS",
        ),
    ]
    # Two trust anchors of one name: mbedTLS skips a trusted candidate whose key does not verify
    # the child (x509_crt.c:2320), so the second, right one is used
    anchor_key = p256()
    anchor = cert("sig anchor", anchor_key, "sig anchor", anchor_key, CA)
    impostor_key = p256()
    impostor = cert("sig anchor", impostor_key, "sig anchor", impostor_key, CA)
    leaf = cert("victim.example", p256(), "sig anchor", anchor_key, server("victim.example"))
    cases += [
        case(
            "signatures::two-anchors-first-wrong-key",
            "two trusted roots of one name, the first with another key",
            [impostor, anchor],
            [],
            leaf,
            "victim.example",
            "SUCCESS",
        ),
        case(
            "signatures::two-anchors-both-wrong-key",
            "two trusted roots of the leaf issuer's name, neither its key",
            [impostor, cert("sig anchor", p256(), "sig anchor", impostor_key, CA)],
            [],
            leaf,
            "victim.example",
            "FAILURE",
        ),
    ]
    # A forged leaf (another key, the real intermediate's name as issuer) with an unrelated filler
    # in front of the real intermediate: the parent is not the next certificate presented
    filler_key = p256()
    filler = cert("sig filler", filler_key, "sig filler", filler_key, CA)
    forged = cert("victim.example", leaf_key, "sig ICA", other, server("victim.example"))
    for order in ("path", "given"):
        cases.append(
            case(
                "signatures::forged-leaf-filler-first::%s" % order,
                "forged leaf, [filler, real ICA]",
                root,
                [filler, ica],
                forged,
                "victim.example",
                "FAILURE",
                order=order,
            )
        )
    good = cert("victim.example", leaf_key, "sig ICA", ica_key, server("victim.example"))
    cases.append(
        case(
            "signatures::good-leaf-filler-first",
            "root -> ICA -> leaf, [filler, ICA]",
            root,
            [filler, ica],
            good,
            "victim.example",
            "SUCCESS",
            order="given",
        )
    )
    # A self-issued intermediate (same name, next key) under the real one, and a forged one (same
    # name, signed with another key) between the leaf and the real one
    ica2_key = p256()
    self_issued = cert("sig ICA", ica2_key, "sig ICA", ica_key, CA)
    forged_self = cert("sig ICA", other, "sig ICA", other, CA)
    cases += [
        case(
            "signatures::self-issued-intermediate",
            "root -> ICA -> ICA (self-issued, next key) -> leaf",
            root,
            [self_issued, ica],
            cert("victim.example", p256(), "sig ICA", ica2_key, server("victim.example")),
            "victim.example",
            "SUCCESS",
        ),
        case(
            "signatures::forged-self-issued",
            "root -> ICA -> forged self-issued ICA -> leaf",
            root,
            [forged_self, ica],
            cert("victim.example", p256(), "sig ICA", other, server("victim.example")),
            "victim.example",
            "FAILURE",
            order="given",
        ),
    ]
    # An expired CA with the real intermediate's name and the attacker's key, in front of the real
    # intermediate: mbedTLS keeps it as a time fallback on its way to the real parent
    expired_decoy = cert(
        "sig ICA",
        other,
        "sig ICA",
        other,
        CA,
        not_before=datetime.datetime(2015, 1, 1, tzinfo=datetime.UTC),
        not_after=datetime.datetime(2016, 1, 1, tzinfo=datetime.UTC),
    )
    for order in ("path", "given"):
        cases.append(
            case(
                "signatures::forged-leaf-expired-decoy::%s" % order,
                "forged leaf, [expired attacker CA named like the ICA, real ICA]",
                root,
                [expired_decoy, ica],
                forged,
                "victim.example",
                "FAILURE",
                order=order,
            )
        )
    cases.append(
        case(
            "signatures::good-leaf-expired-decoy",
            "root -> ICA -> leaf, [expired attacker CA named like the ICA, ICA]",
            root,
            [expired_decoy, ica],
            good,
            "victim.example",
            "SUCCESS",
            order="given",
        )
    )
    # A forged intermediate one level up: a leaf under "evil ICA" (the attacker's key, the real
    # ICA's name as issuer), with a CA filler in front of the real ICA
    evil_key = p256()
    evil = cert("sig evil ICA", evil_key, "sig ICA", other, CA)
    for order in ("path", "given"):
        cases.append(
            case(
                "signatures::forged-intermediate-ca-filler::%s" % order,
                "leaf -> forged ICA (issuer: the real ICA), [forged ICA, CA filler, real ICA]",
                root,
                [evil, filler, ica],
                cert("victim.example", p256(), "sig evil ICA", evil_key, server("victim.example")),
                "victim.example",
                "FAILURE",
                order=order,
            )
        )
    # Two trust anchors of one name and key, the expired one first: mbedTLS keeps it only as a
    # fallback and uses the valid one
    expired_anchor = cert(
        "sig anchor",
        anchor_key,
        "sig anchor",
        anchor_key,
        CA,
        not_before=datetime.datetime(2015, 1, 1, tzinfo=datetime.UTC),
        not_after=datetime.datetime(2016, 1, 1, tzinfo=datetime.UTC),
    )
    cases.append(
        case(
            "signatures::two-anchors-first-expired",
            "two trusted roots of one name and key, the expired one first",
            [expired_anchor, anchor],
            [],
            leaf,
            "victim.example",
            "SUCCESS",
        )
    )
    write("signatures.json", cases)

    # What the certificate bundle does not check: each chain with the root as the CA chain and
    # with the root in a bundle. SHA-1 signatures come from the old crypto the ESP-IDF note on
    # esp_crt_verify_callback() ("a weak signature hash alg" on "a trusted cert") has in mind.
    cases = []
    broot_key = p256()
    broot = cert("bundle root", broot_key, "bundle root", broot_key, CA)
    old = datetime.datetime(2015, 1, 1, tzinfo=datetime.UTC)
    expired_key = p256()
    expired = cert(
        "bundle root expired",
        expired_key,
        "bundle root expired",
        expired_key,
        CA,
        not_before=old,
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC),
    )
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    rsa_root = cert("bundle root rsa1024", rsa_key, "bundle root rsa1024", rsa_key, CA)
    other_key = p256()
    other_root = cert("bundle other root", other_key, "bundle other root", other_key, CA)
    impostor_root = cert("bundle root", other_key, "bundle root", other_key, CA)
    old_ica_key = p256()
    old_ica = cert(
        "bundle ICA old",
        old_ica_key,
        "bundle root",
        broot_key,
        CA,
        not_before=old,
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC),
    )
    new_ica_key = p256()
    new_ica = cert(
        "bundle ICA new",
        new_ica_key,
        "bundle root",
        broot_key,
        CA,
        not_before=datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC),
        not_after=datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC),
    )
    b_ica1_key, b_ica2_key = p256(), p256()
    b_ica1 = cert("bundle ICA 1", b_ica1_key, "bundle root", broot_key, CA)
    b_ica2 = cert("bundle ICA 2", b_ica2_key, "bundle ICA 1", b_ica1_key, CA)
    b_leaf1 = cert("victim.example", p256(), "bundle ICA 1", b_ica1_key, server("victim.example"))
    b_leaf2 = cert("victim.example", p256(), "bundle ICA 2", b_ica2_key, server("victim.example"))
    sha1_ica_key = p256()
    sha1_ica = cert("bundle ICA sha1", sha1_ica_key, "bundle root", broot_key, CA, sha1=True)
    chains = {
        # tag: (description, root, intermediates, leaf, peer name, result)
        "control": (
            "root -> leaf",
            broot,
            [],
            cert("victim.example", p256(), "bundle root", broot_key, server("victim.example")),
            "victim.example",
            "SUCCESS",
        ),
        "wrong-name": (
            "root -> leaf, another host name",
            broot,
            [],
            cert("victim.example", p256(), "bundle root", broot_key, server("victim.example")),
            "other.example",
            "FAILURE",
        ),
        "sha1-leaf": (
            "root -> leaf signed with ecdsa-with-SHA1",
            broot,
            [],
            cert(
                "victim.example",
                p256(),
                "bundle root",
                broot_key,
                server("victim.example"),
                sha1=True,
            ),
            "victim.example",
            "FAILURE",
        ),
        "sha1-intermediate": (
            "root -> ICA signed with ecdsa-with-SHA1 -> leaf",
            broot,
            [sha1_ica],
            cert(
                "victim.example", p256(), "bundle ICA sha1", sha1_ica_key, server("victim.example")
            ),
            "victim.example",
            "FAILURE",
        ),
        "expired-root": (
            "root expired 2021 -> leaf",
            expired,
            [],
            cert(
                "victim.example",
                p256(),
                "bundle root expired",
                expired_key,
                server("victim.example"),
            ),
            "victim.example",
            "FAILURE",
        ),
        # The callback's own decision: an issuer not in the bundle, and one whose name is there
        # with another key, must be refused
        "root-not-in-bundle": (
            "root -> leaf, another root in the bundle",
            other_root,
            [],
            cert("victim.example", p256(), "bundle root", broot_key, server("victim.example")),
            "victim.example",
            "FAILURE",
        ),
        "name-with-other-key": (
            "root -> leaf, the bundle has the root's name with another key",
            impostor_root,
            [],
            cert("victim.example", p256(), "bundle root", broot_key, server("victim.example")),
            "victim.example",
            "FAILURE",
        ),
        "expired-intermediate": (
            "root -> ICA expired 2021 -> leaf",
            broot,
            [old_ica],
            cert("victim.example", p256(), "bundle ICA old", old_ica_key, server("victim.example")),
            "victim.example",
            "FAILURE",
        ),
        "future-intermediate": (
            "root -> ICA valid from 2030 -> leaf",
            broot,
            [new_ica],
            cert("victim.example", p256(), "bundle ICA new", new_ica_key, server("victim.example")),
            "victim.example",
            "FAILURE",
        ),
        # With intermediates: the callback decides for the top one, not the leaf
        "control-depth1": (
            "root -> ICA -> leaf",
            broot,
            [b_ica1],
            b_leaf1,
            "victim.example",
            "SUCCESS",
        ),
        "control-depth2": (
            "root -> ICA -> ICA2 -> leaf",
            broot,
            [b_ica2, b_ica1],
            b_leaf2,
            "victim.example",
            "SUCCESS",
        ),
        "root-not-in-bundle-depth1": (
            "root -> ICA -> leaf, another root in the bundle",
            other_root,
            [b_ica1],
            b_leaf1,
            "victim.example",
            "FAILURE",
        ),
        "root-not-in-bundle-depth2": (
            "root -> ICA -> ICA2 -> leaf, another root in the bundle",
            other_root,
            [b_ica2, b_ica1],
            b_leaf2,
            "victim.example",
            "FAILURE",
        ),
        "rsa1024-root": (
            "RSA-1024 root -> leaf",
            rsa_root,
            [],
            cert(
                "victim.example", p256(), "bundle root rsa1024", rsa_key, server("victim.example")
            ),
            "victim.example",
            "FAILURE",
        ),
    }
    for tag, (description, root_cert, inter, leaf_cert, host, result) in chains.items():
        for mode in ("ca", "bundle"):
            cases.append(
                case(
                    "bundle::%s::%s" % (tag, mode),
                    description,
                    root_cert,
                    inter,
                    leaf_cert,
                    host,
                    result,
                    mode=mode,
                )
            )
    write("bundle.json", cases)


if __name__ == "__main__":
    main()
