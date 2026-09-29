#!/usr/bin/env python3
"""Tests for the Mozilla root store's build gate (ca_store.py) and its cross-sign anchors.
Needs no network: the anchors are checked against chains recorded from real servers
(test_chains.pem) with a plain RSA check."""

import contextlib
import datetime
import hashlib
import base64
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import ca_store


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMMITTED = (REPO_ROOT / ca_store.STORE_DIR / ca_store.PEM_NAME).read_text()
ANCHORS = (REPO_ROOT / ca_store.STORE_DIR / ca_store.ANCHORS_NAME).read_bytes()
ANCHOR_COUNT = len(ca_store.certificates(ANCHORS.decode()))
OLD_DATE = "Tue Jul 14 03:12:01 2026 GMT"
NEW_DATE = "Fri Sep 25 03:12:01 2026 GMT"
OLD_ISO = "2026-07-14T03:12:01Z"
NEW_ISO = "2026-09-25T03:12:01Z"
NOW = datetime.datetime(2026, 9, 29, 12, 0, 0)
OLD_REF = "mozilla-firefox/firefox@" + "1" * 40
NEW_REF = "mozilla-firefox/firefox@" + "2" * 40

SDKCONFIG = """\
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
# CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL is not set
# CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_CMN is not set
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y
CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y
CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH="%s"
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=%d
"""

HEADER = """\
#define IDENT_STRING "ESP32 WiFi Bridge V1.%d"
#define IDENT_MAJOR   1
// 1.%d: something earlier.
#define IDENT_MINOR   %d
"""


def pem(date, first=0, count=20):
    """A store in curl's layout: its header with the given date, then some real roots."""
    header, _, body = COMMITTED.partition("\n\n")
    header = "\n".join(ca_store.DATE_PREFIX + date if line.startswith(ca_store.DATE_PREFIX)
                       else line for line in header.split("\n"))
    blocks = body.strip("\n").split("\n\n")
    return header + "\n\n\n" + "\n\n".join(blocks[first:first + count]) + "\n"


def der_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def rekeyed(text, victim, donor):
    """text with certificate number `victim` given the public key of number `donor`, keeping its
    subject and label: the swap a compromised mirror would make."""
    ders = ca_store.certificates(text)
    der = ders[victim]
    _, start, _ = ca_store._tlv(der, 0)
    _, tbs_start, tbs_end = ca_store._tlv(der, start)
    fields, pos = [], tbs_start
    while pos < tbs_end:
        _, _, end = ca_store._tlv(der, pos)
        fields.append(der[pos:end])
        pos = end
    key_at = 6 if fields[0][0] == 0xA0 else 5
    fields[key_at] = ca_store.subject_and_key(ders[donor])[1]
    tbs = b"".join(fields)
    tbs = bytes([0x30]) + der_length(len(tbs)) + tbs
    body = tbs + der[tbs_end:]
    swapped = bytes([0x30]) + der_length(len(body)) + body
    old_b64 = base64.encodebytes(der).decode().replace("\n", "")
    new_b64 = base64.b64encode(swapped).decode()
    old_block = "\n".join(old_b64[i:i + 76] for i in range(0, len(old_b64), 76))
    new_block = "\n".join(new_b64[i:i + 76] for i in range(0, len(new_b64), 76))
    assert old_block in text
    return text.replace(old_block, new_block)


def with_key(der, key):
    """der with its SubjectPublicKeyInfo replaced (the signature no longer matches)."""
    _, start, _ = ca_store._tlv(der, 0)
    _, tbs_start, tbs_end = ca_store._tlv(der, start)
    fields, pos = [], tbs_start
    while pos < tbs_end:
        _, _, end = ca_store._tlv(der, pos)
        fields.append(der[pos:end])
        pos = end
    fields[6 if fields[0][0] == 0xA0 else 5] = key
    tbs = b"".join(fields)
    tbs = bytes([0x30]) + der_length(len(tbs)) + tbs
    body = tbs + der[tbs_end:]
    return bytes([0x30]) + der_length(len(body)) + body


def pem_block(der):
    text = base64.b64encode(der).decode()
    return (ca_store.BEGIN + "\n" + "\n".join(text[i:i + 76] for i in range(0, len(text), 76))
            + "\n" + ca_store.END + "\n")


class Tree:
    """A repository with the store, two projects that use it (one attaches the bundle) and one
    that does not use it."""

    def __init__(self, root, date=OLD_DATE, max_certs=200):
        self.root = pathlib.Path(root)
        store = self.root / ca_store.STORE_DIR
        store.mkdir(parents=True)
        self.pem = store / ca_store.PEM_NAME
        self.pins = store / ca_store.PINS_NAME
        text = pem(date)
        self.pem.write_text(text)
        self.pins.write_text(
            "# comment kept\nCA_SOURCE_URL=https://curl.se/ca/cacert.pem\n"
            "CA_MOZILLA_DATE=%s\nCA_SHA256=%s\nCA_MAX_AGE_DAYS=180\nCA_CERTDATA_REF=%s\n"
            "CA_ANCHORS_SHA256=%s\nCA_BUNDLE_SET_SHA256=%s\n"
            % (ca_store.iso(date), hashlib.sha256(text.encode()).hexdigest(), OLD_REF,
               hashlib.sha256(ANCHORS).hexdigest(),
               ca_store.bundle_set_sha256(ca_store.certificates(text)
                                          + ca_store.certificates(ANCHORS.decode()))))
        self.anchors = store / ca_store.ANCHORS_NAME
        self.anchors.write_bytes(ANCHORS)
        # raw_a attaches the bundle; u64ctrl uses the store but does not, so its image has
        # no bundle and its version never moves for one.
        self.project("software/wifi/raw_a", "../ca_store", 6, max_certs)
        (self.root / "software/wifi/raw_a/main/tls.c").write_text(
            "void setup(void) { esp_crt_bundle_attach(&conf); }\n")
        self.project("software/u64ctrl", "../wifi/ca_store", 14, max_certs)
        other = self.root / "software/wifi/raw_none"
        (other / "main").mkdir(parents=True)
        (other / "sdkconfig").write_text("# CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is not set\n")
        (other / "main/rpc_dispatch.h").write_text(HEADER % (3, 3, 3))

    def project(self, path, relative, minor, max_certs):
        project = self.root / path
        (project / "main").mkdir(parents=True)
        (project / "sdkconfig").write_text(SDKCONFIG % (relative, max_certs))
        (project / "main/rpc_dispatch.h").write_text(HEADER % (minor, minor, minor))

    def snapshot(self):
        return {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(self.tmp)  # as of 2026-07-14, limit 180 days

    def test_a_fresh_store_passes(self):
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2027, 1, 10), now=NOW), ([], []))

    def test_a_stale_store_warns(self):
        errors, warnings = ca_store.check(self.tree.root, today=datetime.date(2027, 1, 11), now=NOW)
        self.assertEqual(errors, [])
        self.assertIn("181 days old", warnings[0])

    def test_a_stale_store_fails_a_release(self):
        errors, warnings = ca_store.check(self.tree.root, release=True,
                                          today=datetime.date(2027, 1, 11), now=NOW)
        self.assertEqual(warnings, [])
        self.assertIn("181 days old", errors[0])

    def test_a_fresh_store_passes_a_release(self):
        self.assertEqual(ca_store.check(self.tree.root, release=True,
                                        today=datetime.date(2026, 9, 29), now=NOW), ([], []))

    def test_the_release_flag_sets_the_exit_status(self):
        arguments = ["check", "--repo-root", str(self.tree.root), "--today", "2027-06-01"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca_store.main(arguments), 0)
            self.assertEqual(ca_store.main([*arguments, "--release"]), 1)

    def test_a_pins_date_that_disagrees_with_the_store_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_ISO, NEW_ISO))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertIn("is from %s, CA_MOZILLA_DATE says %s" % (OLD_ISO, NEW_ISO), errors[0])

    def test_a_pins_date_that_is_not_iso_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_ISO, "2026-07-14"))
        with self.assertRaisesRegex(ca_store.StoreError, "not of the form"):
            ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)

    def test_more_certificates_than_the_bundle_allows_fails(self):
        shutil.rmtree(self.tree.root)
        limit = 20 + ANCHOR_COUNT
        self.tree = Tree(self.tree.root, max_certs=limit - 1)
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertEqual(len(errors), 2)
        self.assertIn("MAX_CERTS=%d, the store has %d" % (limit - 1, limit), errors[0])
        shutil.rmtree(self.tree.root)
        self.tree = Tree(self.tree.root, max_certs=limit)
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW),
                         ([], []))

    def test_a_date_in_the_future_fails(self):
        errors, _ = ca_store.check(self.tree.root, now=datetime.datetime(2026, 7, 13, 3, 12, 0))
        self.assertIn("in the future", errors[0])

    def test_a_certdata_ref_that_is_not_a_commit_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_REF, "firefox@release"))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertIn("CA_CERTDATA_REF=firefox@release", errors[0])

    def test_a_malformed_pins_file_is_an_error_not_a_crash(self):
        text = self.tree.pins.read_text()
        for broken in (text + "garbage\n",
                       text.replace("CA_MAX_AGE_DAYS=180", "CA_MAX_AGE_DAYS=x")):
            self.tree.pins.write_text(broken)
            with self.assertRaises(ca_store.StoreError):
                ca_store.check(self.tree.root)

    def test_an_sdkconfig_in_a_build_directory_is_ignored(self):
        # ESP-IDF writes build/config/sdkconfig.* only, so this guards against a copy there.
        # One that names the store and one that does not: both would be errors if counted.
        stray = self.tree.root / "software/wifi/raw_a/build/config"
        stray.mkdir(parents=True)
        (stray / "sdkconfig").write_text(SDKCONFIG % ("../../../ca_store", 200))
        other = self.tree.root / "software/u64ctrl/build"
        (other / "sdkconfig").parent.mkdir(parents=True)
        (other / "sdkconfig").write_text("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y\n"
                                         "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y\n")
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW),
                         ([], []))
        self.assertEqual(len(ca_store.projects(self.tree.root)), 2)

    @unittest.skipUnless(hasattr(__import__("time"), "tzset"), "needs time.tzset")
    def test_the_age_is_counted_in_utc_not_local_time(self):
        import time
        now = datetime.datetime.now(datetime.timezone.utc)
        # A zone whose date differs from UTC's at this moment.
        zone = "Etc/GMT-14" if now.hour >= 10 else "Etc/GMT+12"
        shutil.rmtree(self.tree.root)
        # Exactly CA_MAX_AGE_DAYS old by UTC's date, so any other date makes it stale or not.
        date = (now - datetime.timedelta(days=180)).strftime("%a %b %d 00:00:00 %Y GMT")
        self.tree = Tree(self.tree.root, date=date)
        saved = os.environ.get("TZ")
        os.environ["TZ"] = zone
        time.tzset()
        try:
            errors, warnings = ca_store.check(self.tree.root, release=True)
        finally:
            if saved is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = saved
            time.tzset()
        self.assertEqual((errors, warnings), ([], []))

    def test_a_store_edited_by_hand_fails(self):
        self.tree.pem.write_text(self.tree.pem.read_text() + "\n")
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertIn("does not match CA_SHA256", errors[0])

    def test_a_project_back_on_the_default_bundle_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y\n"
                             "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y\n"
                             "# CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE is not set\n")
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertEqual(len(errors), 2)
        self.assertIn("software/u64ctrl/sdkconfig", errors[0])

    def test_a_project_that_adds_the_default_bundle_to_the_store_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text(sdkconfig.read_text().replace(
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y",
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y"))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)
        self.assertIn("DEFAULT_NONE", errors[0])


class BundleSetTest(unittest.TestCase):
    """CA_BUNDLE_SET_SHA256, the IDENT rule it drives, and `pin`."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(self.tmp)
        self.raw_a = self.tree.root / "software/wifi/raw_a/main/rpc_dispatch.h"
        self.u64ctrl = self.tree.root / "software/u64ctrl/main/rpc_dispatch.h"

    def errors(self):
        return ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=NOW)[0]

    def edit_anchors(self, data):
        # A reviewed hand edit: anchors.pem and its own pin, but not the set pin.
        self.tree.anchors.write_bytes(data)
        pins = self.tree.pins.read_text()
        self.tree.pins.write_text(pins.replace(hashlib.sha256(ANCHORS).hexdigest(),
                                               hashlib.sha256(data).hexdigest()))

    def test_an_anchor_edit_without_the_set_pin_fails_and_names_what_to_bump(self):
        one = ANCHORS.decode()
        second = one.index("\n## Why:\n##   Some servers send this root itself")
        self.edit_anchors(one[:second].rstrip("\n").encode() + b"\n")
        errors = self.errors()
        self.assertEqual(len(errors), 1)
        self.assertIn("CA_BUNDLE_SET_SHA256 did not", errors[0])
        self.assertIn("IDENT_MINOR of software/wifi/raw_a", errors[0])
        self.assertNotIn("u64ctrl", errors[0])

    def test_a_comment_only_edit_changes_no_certificate(self):
        self.edit_anchors(b"## another comment\n" + ANCHORS)
        self.assertEqual(self.errors(), [])

    def test_pin_moves_both_pins_and_bumps_only_modules_that_attach_the_bundle(self):
        one = ANCHORS.decode()
        second = one.index("\n## Why:\n##   Some servers send this root itself")
        self.tree.anchors.write_bytes(one[:second].rstrip("\n").encode() + b"\n")
        written, bumped = ca_store.pin_bundle(self.tree.root, "2026-09-29")
        self.assertEqual(self.errors(), [])
        self.assertEqual([str(p.relative_to(self.tree.root)) for p, _ in bumped],
                         ["software/wifi/raw_a"])
        self.assertIn("// 1.7: the Mozilla root store as of 2026-09-29.", self.raw_a.read_text())
        self.assertEqual(self.u64ctrl.read_text(), HEADER % (14, 14, 14))
        self.assertEqual(written, [self.tree.pins, self.raw_a])

    def test_pin_with_nothing_changed_bumps_nothing(self):
        before = self.raw_a.read_text()
        _, bumped = ca_store.pin_bundle(self.tree.root, "2026-09-29")
        self.assertEqual(bumped, [])
        self.assertEqual(self.raw_a.read_text(), before)

    def test_the_set_does_not_depend_on_order_or_file(self):
        ders = ca_store.certificates(COMMITTED)[:5]
        self.assertEqual(ca_store.bundle_set_sha256(ders),
                         ca_store.bundle_set_sha256(list(reversed(ders))))
        self.assertNotEqual(ca_store.bundle_set_sha256(ders), ca_store.bundle_set_sha256(ders[1:]))

    def test_attaching_reads_only_the_projects_own_sources(self):
        self.assertTrue(ca_store.attaching(self.tree.root / "software/wifi/raw_a"))
        self.assertFalse(ca_store.attaching(self.tree.root / "software/u64ctrl"))

    def test_two_roots_with_one_subject_fail(self):
        store = ca_store.certificates(self.tree.pem.read_text())
        double = with_key(store[0], ca_store.subject_and_key(store[1])[1])
        self.edit_anchors(ANCHORS + b"\nDouble\n======\n" + pem_block(double).encode())
        errors = self.errors()
        self.assertTrue(any("same subject" in e for e in errors), errors)

    def test_a_store_path_without_the_custom_bundle_switch_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text(sdkconfig.read_text().replace(
            "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y\n",
            "# CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE is not set\n"))
        self.assertIn("does not set CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y", self.errors()[0])


class BuildStampTest(unittest.TestCase):
    """An edit in place does not change the store directory's time, which is all ESP-IDF's build
    watches, so `check` drops a bundle generated from a different store."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(self.tmp)
        self.build = self.tree.root / "software/wifi/raw_a/build"
        self.bundle = self.build / ca_store.BUNDLE_OUTPUT
        self.bundle.parent.mkdir(parents=True)
        self.bundle.write_bytes(b"old bundle")

    def run_check(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = ca_store.main(["check", "--repo-root", str(self.tree.root),
                                    "--today", "2026-09-29"])
        self.assertEqual(status, 0)
        return out.getvalue()

    def test_a_build_without_a_stamp_has_its_bundle_made_again(self):
        out = self.run_check()
        self.assertIn("raw_a has no stamp yet; its bundle will be made again", out)
        self.assertNotIn("changed", out)
        self.assertFalse(self.bundle.exists())
        self.assertEqual((self.build / ca_store.STAMP_NAME).read_text().strip(),
                         ca_store.store_stamp(self.tree.anchors.parent))

    def test_a_matching_stamp_keeps_the_bundle(self):
        self.run_check()
        self.bundle.write_bytes(b"new bundle")
        self.assertNotIn("was built", self.run_check())
        self.assertEqual(self.bundle.read_bytes(), b"new bundle")

    def test_an_edit_in_place_drops_the_bundle(self):
        self.run_check()
        self.bundle.write_bytes(b"bundle of the old store")
        inode = self.tree.pem.stat().st_ino
        text = self.tree.pem.read_text()
        with open(self.tree.pem, "r+") as f:           # in place, as an editor does
            f.write(text.replace("COMODO", "COMODX", 1))
        self.assertEqual(self.tree.pem.stat().st_ino, inode)
        self.tree.pins.write_text(self.tree.pins.read_text().replace(
            ca_store.read_pins(self.tree.pins)["CA_SHA256"],
            hashlib.sha256(self.tree.pem.read_bytes()).hexdigest()))
        self.assertIn("raw_a was built", self.run_check())
        self.assertFalse(self.bundle.exists())

    def test_a_bundle_removed_by_another_check_meanwhile_is_no_error(self):
        # Two makes checking at once: the other one removes the bundle between our exists()
        # and our unlink().
        real = pathlib.Path.exists

        def gone_after(path):
            here = real(path)
            if path == self.bundle and here:
                path.unlink()
            return here
        with mock.patch.object(pathlib.Path, "exists", gone_after):
            dropped = ca_store.restamp_builds(self.tree.root)
        self.assertEqual([p.name for p, _ in dropped], ["raw_a"])
        self.assertTrue((self.build / ca_store.STAMP_NAME).exists())

    def test_a_project_never_built_is_left_alone(self):
        self.run_check()
        self.assertFalse((self.tree.root / "software/u64ctrl/build").exists())

    def test_a_failing_check_stamps_nothing(self):
        self.tree.pem.write_text(self.tree.pem.read_text() + "\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca_store.main(["check", "--repo-root", str(self.tree.root)]), 1)
        self.assertTrue(self.bundle.exists())
        self.assertFalse((self.build / ca_store.STAMP_NAME).exists())


class AnchorFileTest(unittest.TestCase):
    """What `check` requires of anchors.pem and the store directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(self.tmp)

    def errors(self, now=None):
        return ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29), now=now)

    def test_anchors_edited_without_the_pin_fail(self):
        self.tree.anchors.write_bytes(ANCHORS + b"\n")
        self.assertIn("does not match CA_ANCHORS_SHA256", self.errors()[0][0])

    def test_a_missing_anchors_file_fails(self):
        self.tree.anchors.unlink()
        self.assertIn("anchors.pem is missing", self.errors()[0])

    def test_an_anchor_that_mozilla_trusts_again_fails(self):
        # Mozilla puts an anchor back: it is then in cacert.pem and must leave anchors.pem.
        anchor = ANCHORS.decode()
        start = anchor.index(ca_store.BEGIN)
        block = anchor[start:anchor.index(ca_store.END) + len(ca_store.END) + 1]
        self.tree.pem.write_text(self.tree.pem.read_text() + "\nAgain\n=====\n" + block)
        self.tree.pins.write_text(self.tree.pins.read_text().replace(
            ca_store.read_pins(self.tree.pins)["CA_SHA256"],
            hashlib.sha256(self.tree.pem.read_bytes()).hexdigest()))
        self.assertIn("is in cacert.pem again", self.errors()[0][0])

    def test_a_stray_pem_in_the_store_fails(self):
        (self.tree.anchors.parent / "extra.pem").write_bytes(ANCHORS)
        self.assertIn("extra.pem would go into every module's bundle", self.errors()[0][0])

    def test_a_path_to_cacert_alone_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text(sdkconfig.read_text().replace(
            '"../wifi/ca_store"', '"../wifi/ca_store/cacert.pem"'))
        self.assertIn("leaves out anchors.pem", self.errors()[0][0])

    def test_an_anchor_about_to_expire_is_reported_ninety_days_ahead(self):
        _, warnings = self.errors(now=datetime.datetime(2027, 10, 31))
        self.assertEqual(len(warnings), 1)
        self.assertIn("GlobalSign Root CA expires on 2028-01-28 12:00:00 UTC", warnings[0])
        self.assertEqual(self.errors(now=datetime.datetime(2027, 10, 29, 11, 59))[1], [])

    def test_an_expired_anchor_is_reported(self):
        _, warnings = self.errors(now=datetime.datetime(2028, 2, 1))
        self.assertIn("GlobalSign Root CA expired on 2028-01-28", warnings[0])

    def test_not_after_reads_both_time_forms(self):
        ders = ca_store.certificates(ANCHORS.decode())
        self.assertEqual([ca_store.not_after(der) for der in ders],
                         [datetime.datetime(2028, 1, 28, 12, 0, 0),
                          datetime.datetime(2031, 11, 10, 0, 0, 0),
                          datetime.datetime(2028, 12, 31, 23, 59, 59),
                          datetime.datetime(2034, 6, 29, 17, 6, 20)])


# ESP-IDF v5.3's bundle check, on recorded chains. The anchors are RSA keys, so a plain
# PKCS #1 v1.5 check is enough to verify what they signed without a crypto package.

RSA_DIGESTS = {
    "2a864886f70d010105": ("sha1", "3021300906052b0e03021a05000414"),
    "2a864886f70d01010b": ("sha256", "3031300d060960864801650304020105000420"),
    "2a864886f70d01010c": ("sha384", "3041300d060960864801650304020205000430"),
    "2a864886f70d01010d": ("sha512", "3051300d060960864801650304020305000440"),
}


def children(der, start, end):
    out = []
    while start < end:
        tag, value, stop = ca_store._tlv(der, start)
        out.append((tag, value, stop, start))
        start = stop
    return out


def signed_by(child, key):
    """Whether the certificate `child` carries a valid RSA PKCS #1 v1.5 signature by the key
    in `key` (a SubjectPublicKeyInfo DER). False for any other kind of key or signature."""
    _, start, end = ca_store._tlv(child, 0)
    parts = children(child, start, end)
    (_, _, tbs_end, tbs_at), (_, alg, _, _), (_, sig, sig_end, _) = parts
    _, oid, oid_end = ca_store._tlv(child, alg)
    digest = RSA_DIGESTS.get(child[oid:oid_end].hex())
    _, kstart, kend = ca_store._tlv(key, 0)
    (_, kalg, kalg_end, _), (_, bits, _, _) = children(key, kstart, kend)[:2]
    if digest is None or b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" not in key[kalg:kalg_end]:
        return False
    _, rstart, rend = ca_store._tlv(key, bits + 1)
    (_, n, n_end, _), (_, e, e_end, _) = children(key, rstart, rend)
    modulus = int.from_bytes(key[n:n_end], "big")
    exponent = int.from_bytes(key[e:e_end], "big")
    size = (modulus.bit_length() + 7) // 8
    signature = int.from_bytes(child[sig + 1:sig_end], "big")
    name, prefix = digest
    hashed = hashlib.new(name, child[tbs_at:tbs_end]).digest()
    info = bytes.fromhex(prefix) + hashed
    expected = b"\x00\x01" + b"\xff" * (size - len(info) - 3) + b"\x00" + info
    return pow(signature, exponent, modulus).to_bytes(size, "big") == expected


def issuer(der):
    _, start, _ = ca_store._tlv(der, 0)
    _, pos, _ = ca_store._tlv(der, start)
    fields = []
    while len(fields) < 3:
        tag, _, end = ca_store._tlv(der, pos)
        if not (tag == 0xA0 and not fields):
            fields.append(der[pos:end])
        pos = end
    return fields[2]


def accepts(bundle, top):
    """esp_crt_verify_callback @ESP-IDF v5.3.1: find the top certificate's issuer by subject
    in the bundle, and check the top's signature with that root's key."""
    return any(ca_store.subject_and_key(root)[0] == issuer(top)
               and signed_by(top, ca_store.subject_and_key(root)[1]) for root in bundle)


def recorded():
    """[(kind, hosts, top DER)] from test_chains.pem."""
    text = (pathlib.Path(__file__).parent / "test_chains.pem").read_text()
    entries = []
    for block in text.split("\n\n")[1:]:
        kinds, hosts = set(), []
        for line in block.split("\n"):
            for kind in ("needs-anchor", "store"):
                if line.startswith("# %s: " % kind):
                    kinds.add(kind)
                    hosts += line.split(": ", 1)[1].split()
        assert len(kinds) == 1, block[:200]
        entries.append((kinds.pop(), hosts, ca_store.certificates(block.strip() + "\n")[0]))
    return entries


def unneeded(anchors, store, entries, now):
    """The anchors that no recorded, unexpired top needs: those whose loss would break none."""
    live = [top for _, _, top in entries if ca_store.not_after(top) > now]
    return [anchor for anchor in anchors
            if not any(not accepts(store, top) and accepts([anchor], top) for top in live)]


class CrossSignAnchorTest(unittest.TestCase):
    """The anchors, against chains recorded from real servers: each regressed host passes with
    the anchors and fails without, and an anchor that nothing needs any more, or that has
    expired, fails the suite so it is removed."""

    store = ca_store.certificates(COMMITTED)
    anchors = ca_store.certificates(ANCHORS.decode())
    labels = ca_store.names(ANCHORS.decode())
    entries = recorded()

    def anchor(self, label):
        return self.anchors[self.labels.index(label)]

    def test_the_recording_covers_every_host_found_to_need_an_anchor(self):
        hosts = [h for kind, hs, _ in self.entries if kind == "needs-anchor" for h in hs]
        self.assertEqual(len(hosts), 93)
        self.assertEqual(len(set(hosts)), 93)
        for host in ("www.google.com", "archive.org", "gitlab.com", "cdn.jsdelivr.net",
                     "example.com", "www.namecheap.com", "zoom.us", "api.pushover.net"):
            self.assertIn(host, hosts)

    def test_the_four_anchors_are_the_ones_chosen(self):
        self.assertEqual(self.labels, ["GlobalSign Root CA", "DigiCert Global Root CA",
                                       "Comodo AAA Services root", "Go Daddy Class 2 CA"])

    def test_each_anchor_has_a_recorded_host_of_its_own(self):
        for label, anchor in zip(self.labels, self.anchors):
            others = [a for a in self.anchors if a is not anchor]
            self.assertTrue(any(kind == "needs-anchor" and not accepts(self.store + others, top)
                                for kind, _, top in self.entries), label)

    def test_hosts_that_need_an_anchor_fail_without_them_and_pass_with_them(self):
        for kind, hosts, top in self.entries:
            if kind == "needs-anchor":
                self.assertFalse(accepts(self.store, top), hosts)
                self.assertTrue(accepts(self.store + self.anchors, top), hosts)

    def test_hosts_the_store_covers_pass_without_the_anchors(self):
        stores = [top for kind, _, top in self.entries if kind == "store"]
        self.assertTrue(stores)
        for top in stores:
            self.assertTrue(accepts(self.store, top))

    def test_every_anchor_is_still_needed_by_a_recorded_chain(self):
        now = ca_store.utc_now()
        self.assertEqual([ca_store.names(ANCHORS.decode())[self.anchors.index(a)]
                          for a in unneeded(self.anchors, self.store, self.entries, now)], [])

    def test_no_anchor_has_expired(self):
        now = ca_store.utc_now()
        for label, anchor in zip(ca_store.names(ANCHORS.decode()), self.anchors):
            self.assertGreater(ca_store.not_after(anchor), now, label)

    def test_no_anchor_is_in_the_store(self):
        for anchor in self.anchors:
            self.assertNotIn(anchor, self.store)

    def test_an_anchor_retires_when_the_chain_that_needs_it_expires(self):
        # Every cross-sign GlobalSign Root CA made, and the root itself, run out on 2028-01-28;
        # after that nothing recorded needs it, and the suite fails until it is removed. The
        # AAA cross-signs follow on 2028-12-31.
        gone = unneeded(self.anchors, self.store, self.entries, datetime.datetime(2028, 1, 29))
        self.assertEqual(gone, [self.anchor("GlobalSign Root CA")])
        gone = unneeded(self.anchors, self.store, self.entries, datetime.datetime(2029, 1, 1))
        self.assertEqual(gone, [self.anchor("GlobalSign Root CA"),
                                self.anchor("Comodo AAA Services root")])

    def test_an_anchor_retires_when_no_recorded_chain_uses_it(self):
        without_archive = [e for e in self.entries if "archive.org" not in e[1]]
        gone = unneeded(self.anchors, self.store, without_archive, NOW)
        self.assertEqual(gone, [self.anchor("Go Daddy Class 2 CA")])

    def test_an_anchor_the_store_already_covers_counts_as_unneeded(self):
        self.assertEqual(unneeded(self.anchors, self.store + self.anchors, self.entries, NOW),
                         self.anchors)

    def test_the_signature_check_rejects_a_wrong_key(self):
        google = next(top for _, hosts, top in self.entries if "www.google.com" in hosts)
        globalsign = ca_store.subject_and_key(self.anchor("GlobalSign Root CA"))[1]
        digicert = ca_store.subject_and_key(self.anchor("DigiCert Global Root CA"))[1]
        self.assertTrue(signed_by(google, globalsign))
        self.assertFalse(signed_by(google, digicert))
        tampered = bytearray(google)
        tampered[200] ^= 1
        self.assertFalse(signed_by(bytes(tampered), globalsign))


class CommittedStoreTest(unittest.TestCase):
    """The tree as committed."""

    def test_the_committed_store_is_consistent(self):
        errors, _ = ca_store.check(REPO_ROOT)
        self.assertEqual(errors, [])

    def test_the_committed_pins_parse_like_pins_and_as_shell(self):
        path = REPO_ROOT / ca_store.STORE_DIR / ca_store.PINS_NAME
        pins = ca_store.read_pins(path)
        for value in pins.values():
            self.assertNotRegex(value, "[\"' ]")
        shell = subprocess.run(
            ["sh", "-c", '. "$1" && echo "$CA_MOZILLA_DATE $CA_MAX_AGE_DAYS"', "sh", str(path)],
            capture_output=True, text=True, check=True)
        self.assertEqual(shell.stdout.split(),
                         [pins["CA_MOZILLA_DATE"], pins["CA_MAX_AGE_DAYS"]])

    def test_every_esp32_project_builds_its_bundle_from_the_store(self):
        found = sorted(str(p.relative_to(REPO_ROOT)) for p, _ in ca_store.projects(REPO_ROOT))
        self.assertEqual(found, ["software/u64ctrl", "software/wifi/raw_c3",
                                 "software/wifi/raw_u64"])

    def test_every_project_that_uses_the_store_has_a_version_to_bump(self):
        for project, _ in ca_store.projects(REPO_ROOT):
            _, text, version = ca_store.bump_ident(project, "2026-09-25")
            self.assertIn('%s"' % version, text)


if __name__ == "__main__":
    unittest.main()
