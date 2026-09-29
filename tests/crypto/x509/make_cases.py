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

The keys are made fresh and thrown away; only the certificates are written. Needs the
"cryptography" package; conformance.py only reads the JSON.
"""
import ipaddress
import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
VALIDATION_TIME = '2027-01-01T00:00:00+00:00'
BASIC_CONSTRAINTS = x509.ObjectIdentifier('2.5.29.19')

# The basicConstraints values X carries (the extnValue contents, DER)
X_VARIANTS = {
    # SEQUENCE { INTEGER 1 }: RFC 5280 reads a pathLenConstraint with cA absent (FALSE);
    # mbedTLS <= 3.6.6 read the INTEGER as cA and took 1 as TRUE (f67b8e5b)
    'integer-as-ca': bytes.fromhex('3003020101'),
    # SEQUENCE {} followed by BOOLEAN TRUE inside the extension: the SEQUENCE is empty, so cA is
    # FALSE; mbedTLS <= 3.6.6 read on past the SEQUENCE's end to the end of the extension (07f45b87)
    'bool-after-empty-sequence': bytes.fromhex('30000101ff'),
    # Controls: a well-formed cA=FALSE (must fail on every version) and a real CA (must pass)
    'control-not-ca': bytes.fromhex('3000'),
    'control-ca': bytes.fromhex('30030101ff'),
}


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, key, issuer, issuer_key, extensions):
    builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER))
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical)
    return builder.sign(issuer_key, hashes.SHA256())


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


def case(case_id, description, root, intermediates, leaf, peer_name, result):
    return {'id': case_id, 'description': description, 'validation_kind': 'SERVER',
            'trusted_certs': [pem(root)], 'untrusted_intermediates': [pem(c) for c in intermediates],
            'peer_certificate': pem(leaf), 'validation_time': VALIDATION_TIME,
            'expected_peer_name': {'kind': 'IP' if peer_name[0].isdigit() else 'DNS', 'value': peer_name},
            'expected_result': result, 'features': [], 'crls': []}


def write(filename, cases):
    with open(os.path.join(HERE, filename), 'w') as f:
        json.dump({'version': 1, 'testcases': cases}, f, indent=1)
        f.write('\n')


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = cert('cve-2026-49300 root', root_key, 'cve-2026-49300 root', root_key, [
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)])
    cases = []
    for variant, bc in X_VARIANTS.items():
        # X with no keyUsage, as mbedTLS then lets it sign certificates; and X with the
        # digitalSignature-only keyUsage a server certificate has, which mbedTLS refuses as a parent
        for ku in (None, 'digitalsignature'):
            x_key = ec.generate_private_key(ec.SECP256R1())
            x_ext = [(x509.UnrecognizedExtension(BASIC_CONSTRAINTS, bc), True),
                     (x509.SubjectAlternativeName([x509.DNSName('x.example')]), False),
                     (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)]
            if ku:
                x_ext.append((x509.KeyUsage(True, False, False, False, False, False, False, False, False), True))
            x_cert = cert('cve-2026-49300 X', x_key, 'cve-2026-49300 root', root_key, x_ext)
            leaf_key = ec.generate_private_key(ec.SECP256R1())
            leaf = cert('victim.example', leaf_key, 'cve-2026-49300 X', x_key, [
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
                (x509.SubjectAlternativeName([x509.DNSName('victim.example')]), False),
                (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)])
            cases.append(case('cve-2026-49300::%s%s' % (variant, '-ku-digitalsignature' if ku else ''),
                              'root -> X -> victim.example; X basicConstraints extnValue %s%s' % (
                                  bc.hex(), ', keyUsage digitalSignature' if ku else ', no keyUsage'),
                              root, [x_cert], leaf, 'victim.example',
                              'SUCCESS' if variant == 'control-ca' and not ku else 'FAILURE'))
    write('cve-2026-49300.json', cases)

    # A server certificate for 192.0.2.1 straight from the root
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = cert('192.0.2.1', leaf_key, 'cve-2026-49300 root', root_key, [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
        (x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('192.0.2.1'))]), False),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)])
    write('cve-2026-25833.json', [
        # IPv4 digits first and a ':' later: the old parser walked back past the name's start
        case('cve-2026-25833::ipv4-then-colons', 'IP SAN 192.0.2.1, peer name "1.2.3.4::"',
             root, [], leaf, '1.2.3.4::', 'FAILURE'),
        case('cve-2026-25833::control', 'IP SAN 192.0.2.1, peer name "192.0.2.1"',
             root, [], leaf, '192.0.2.1', 'SUCCESS')])


if __name__ == '__main__':
    main()
