#!/usr/bin/env python3
"""Tests for the Mozilla root store refresh and its build gate. Needs no network: the store
is served from file:// URLs built from the committed cacert.pem, and the regeneration from
Mozilla's certdata.txt is replaced by a stand-in. CA_STORE_ONLINE=1 adds a test that runs the
real one against GitHub."""

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


def agree(text):
    """A regeneration that comes out the same as curl's file."""
    return NEW_REF, text.encode()


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


class Tree:
    """A repository with the store, two projects that use it and one that does not."""

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
            % (ca_store.iso(date), hashlib.sha256(text.encode()).hexdigest(), OLD_REF))
        self.project("software/wifi/raw_a", "../ca_store/cacert.pem", 6, max_certs)
        self.project("software/u64ctrl", "../wifi/ca_store/cacert.pem", 14, max_certs)
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


class Served:
    """A cacert.pem and its .sha256 as file:// URLs."""

    def __init__(self, directory, text, sha256=None):
        self.path = pathlib.Path(directory) / "cacert.pem"
        self.path.write_bytes(text.encode())
        digest = sha256 or hashlib.sha256(text.encode()).hexdigest()
        pathlib.Path(str(self.path) + ".sha256").write_text("%s  cacert.pem\n" % digest)
        self.url = self.path.as_uri()


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(pathlib.Path(self.tmp) / "repo")
        self.serve_dir = pathlib.Path(self.tmp) / "served"
        self.serve_dir.mkdir()

    def refresh(self, text, sha256=None, **kwargs):
        kwargs.setdefault("regenerate", agree)
        kwargs.setdefault("now", NOW)
        return ca_store.refresh(self.tree.root, Served(self.serve_dir, text, sha256).url, **kwargs)

    def test_a_new_date_writes_the_store_the_pins_and_bumps_every_project_that_uses_it(self):
        new = pem(NEW_DATE, first=5, count=30)
        summary = pathlib.Path(self.tmp) / "summary.md"

        written = self.refresh(new, summary=summary)

        self.assertEqual(self.tree.pem.read_text(), new)
        pins = ca_store.read_pins(self.tree.pins)
        self.assertEqual(pins["CA_MOZILLA_DATE"], NEW_ISO)
        self.assertEqual(pins["CA_SHA256"], hashlib.sha256(new.encode()).hexdigest())
        self.assertEqual(pins["CA_SOURCE_URL"], "https://curl.se/ca/cacert.pem")
        self.assertEqual(pins["CA_CERTDATA_REF"], NEW_REF)
        self.assertIn("# comment kept\n", self.tree.pins.read_text())
        self.assertIn("\nCA_MOZILLA_DATE=%s\n" % NEW_ISO, self.tree.pins.read_text())
        raw_a = (self.tree.root / "software/wifi/raw_a/main/rpc_dispatch.h").read_text()
        self.assertEqual(raw_a, '#define IDENT_STRING "ESP32 WiFi Bridge V1.7"\n'
                                "#define IDENT_MAJOR   1\n"
                                "// 1.7: the Mozilla root store as of 2026-09-25.\n"
                                "// 1.6: something earlier.\n"
                                "#define IDENT_MINOR   7\n")
        u64ctrl = (self.tree.root / "software/u64ctrl/main/rpc_dispatch.h").read_text()
        self.assertIn('"ESP32 WiFi Bridge V1.15"', u64ctrl)
        self.assertIn("#define IDENT_MINOR   15\n", u64ctrl)
        untouched = (self.tree.root / "software/wifi/raw_none/main/rpc_dispatch.h").read_text()
        self.assertEqual(untouched, HEADER % (3, 3, 3))
        self.assertEqual(len(written), 4)
        report = summary.read_text()
        self.assertIn("as of %s (was %s), 30 certificates" % (NEW_ISO, OLD_ISO), report)
        old_fps = set(ca_store.roots(pem(OLD_DATE)))
        new_fps = set(ca_store.roots(new))
        for fp in new_fps - old_fps:
            self.assertIn("- `%s` " % fp, report.split("## Added")[1].split("## Removed")[0])
        for fp in old_fps - new_fps:
            self.assertIn("- `%s` " % fp, report.split("## Removed")[1])
        self.assertEqual(len(new_fps - old_fps), 15)
        self.assertEqual(len(old_fps - new_fps), 5)
        self.assertNotIn("SAME SUBJECT", report)
        self.assertIn(NEW_REF, report)
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29)), ([], []))

    def test_a_second_run_with_the_same_data_changes_nothing(self):
        new = pem(NEW_DATE, first=5, count=30)
        self.refresh(new)
        before = self.tree.snapshot()

        self.assertEqual(self.refresh(new), [])
        self.assertEqual(self.tree.snapshot(), before)

    def test_the_same_date_changes_nothing(self):
        before = self.tree.snapshot()

        self.assertEqual(self.refresh(pem(OLD_DATE)), [])
        self.assertEqual(self.tree.snapshot(), before)

    def test_the_same_date_with_only_a_different_header_changes_nothing(self):
        before = self.tree.snapshot()

        self.assertEqual(self.refresh(pem(OLD_DATE).replace("version 1.33", "version 1.34")), [])
        self.assertEqual(self.tree.snapshot(), before)

    def assertRefused(self, message, text, sha256=None):
        before = self.tree.snapshot()
        with self.assertRaisesRegex(ca_store.StoreError, message):
            self.refresh(text, sha256)
        self.assertEqual(self.tree.snapshot(), before)

    def test_a_wrong_sha256_writes_nothing(self):
        self.assertRefused("sha256 mismatch", pem(NEW_DATE), sha256="0" * 64)

    def test_a_sum_file_that_is_not_a_sum_writes_nothing(self):
        self.assertRefused("not a sha256 sum", pem(NEW_DATE), sha256="<html>")

    def test_a_truncated_download_fails_its_sum(self):
        new = pem(NEW_DATE)
        good_sum = hashlib.sha256(new.encode()).hexdigest()
        self.assertRefused("sha256 mismatch", new[: len(new) // 2], sha256=good_sum)

    def test_a_truncated_file_is_refused_even_when_its_sum_matches(self):
        new = pem(NEW_DATE)
        self.assertRefused("truncated", new[: new.rindex(ca_store.END)])
        self.assertRefused("truncated", new[: new.rindex(ca_store.END) + 10])
        self.assertRefused("truncated", new[:-1])

    def test_a_certificate_that_is_not_der_is_refused(self):
        new = pem(NEW_DATE).replace("\nMII", "\nXII", 1)
        self.assertRefused("not DER", new)

    def test_a_file_without_the_mozilla_date_is_refused(self):
        self.assertRefused("Certificate data from Mozilla",
                           pem(NEW_DATE).replace("as of: ", "at: "))

    def test_an_older_store_is_refused(self):
        self.assertRefused("older than the committed store", pem("Mon Mar 11 15:25:27 2024 GMT"))

    def test_different_certificates_under_the_same_date_are_refused(self):
        self.assertRefused("certificates changed but the Mozilla date did not",
                           pem(OLD_DATE, first=1))

    def test_more_certificates_than_the_bundle_allows_are_refused(self):
        shutil.rmtree(self.tree.root)
        self.tree = Tree(self.tree.root, max_certs=10)
        self.assertRefused("allows 10", pem(NEW_DATE, count=11))

    def test_a_project_whose_version_does_not_parse_writes_nothing(self):
        (self.tree.root / "software/u64ctrl/main/rpc_dispatch.h").write_text(
            HEADER.replace("V1.%d", "V2.%d") % (14, 14, 14))
        self.assertRefused("IDENT_STRING says 2.14", pem(NEW_DATE, first=1))

    def test_a_network_failure_writes_nothing(self):
        before = self.tree.snapshot()
        for url in ((self.serve_dir / "missing.pem").as_uri(), "http://127.0.0.1:9/cacert.pem"):
            with mock.patch.object(ca_store, "FETCH_TIMEOUT", 5):
                with self.assertRaisesRegex(ca_store.StoreError, "cannot fetch"):
                    ca_store.refresh(self.tree.root, url)
        self.assertEqual(self.tree.snapshot(), before)

    def test_the_command_line_reports_a_failure_with_a_nonzero_status(self):
        served = Served(self.serve_dir, pem(NEW_DATE), sha256="0" * 64)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = ca_store.main(["refresh", "--repo-root", str(self.tree.root),
                                    "--source", served.url])
        self.assertEqual(status, 1)
        self.assertIn("sha256 mismatch", stderr.getvalue())


    def test_a_new_date_with_the_same_certificates_bumps_nothing(self):
        new = pem(NEW_DATE)
        summary = pathlib.Path(self.tmp) / "summary.md"
        headers = {p: p.read_text() for p in self.tree.root.rglob("rpc_dispatch.h")}

        written = self.refresh(new, summary=summary)

        self.assertEqual(written, [self.tree.pem, self.tree.pins])
        self.assertEqual({p: p.read_text() for p in headers}, headers)
        self.assertEqual(ca_store.read_pins(self.tree.pins)["CA_MOZILLA_DATE"], NEW_ISO)
        self.assertIn("did not change", summary.read_text())

    def test_a_file_that_mozillas_data_does_not_give_is_refused(self):
        # A mirror serving its own key under ISRG Root X1's name, with a matching sum: the
        # regeneration from certdata.txt still gives the real one.
        honest = pem(NEW_DATE)
        forged = rekeyed(honest, 3, 7)
        self.assertNotEqual(forged, honest)
        before = self.tree.snapshot()
        with self.assertRaisesRegex(ca_store.StoreError, "is not what .* gives"):
            self.refresh(forged, regenerate=lambda text: (NEW_REF, honest.encode()))
        self.assertEqual(self.tree.snapshot(), before)

    def test_a_different_header_alone_is_refused_too(self):
        honest = pem(NEW_DATE)
        with self.assertRaisesRegex(ca_store.StoreError, "is not what"):
            self.refresh(honest.replace("version 1.33", "version 1.34"),
                         regenerate=lambda text: (NEW_REF, honest.encode()))

    def test_a_key_change_under_the_same_subject_gets_its_own_section(self):
        # When Mozilla itself makes the change, both origins agree and the store is written,
        # but the description puts it apart from ordinary additions and removals.
        new = rekeyed(pem(NEW_DATE), 3, 7)
        summary = pathlib.Path(self.tmp) / "summary.md"

        self.refresh(new, summary=summary)

        report = summary.read_text()
        section = report.split("## SAME SUBJECT, DIFFERENT CERTIFICATE")[1].split("## Added")[0]
        old_fp = hashlib.sha256(ca_store.certificates(pem(OLD_DATE))[3]).hexdigest()
        new_fp = hashlib.sha256(ca_store.certificates(new)[3]).hexdigest()
        self.assertIn("`%s` became `%s`" % (old_fp, new_fp), section)
        self.assertEqual(report.split("## Added")[1].split("## Removed")[0].strip(), "None.")
        self.assertIn("V1.7", (self.tree.root / "software/wifi/raw_a/main/rpc_dispatch.h")
                      .read_text())

    def test_labels_cannot_inject_markup_into_the_description(self):
        new = pem(NEW_DATE, first=5, count=30)
        label = ca_store.names(new)[-1]
        new = new.replace("\n%s\n" % label, "\n[x](https://evil)<b>`\n", 1)
        summary = pathlib.Path(self.tmp) / "summary.md"
        self.refresh(new, summary=summary)
        self.assertNotIn("](https", summary.read_text())
        self.assertNotIn("<b>", summary.read_text())

    def test_a_date_in_the_future_is_refused(self):
        self.assertRefused("in the future", pem("Thu Oct 01 12:00:01 2026 GMT"))

    def test_a_date_within_a_day_of_the_clock_is_accepted(self):
        self.refresh(pem("Wed Sep 30 11:59:59 2026 GMT"))
        self.assertEqual(ca_store.read_pins(self.tree.pins)["CA_MOZILLA_DATE"],
                         "2026-09-30T11:59:59Z")

    def test_an_earlier_time_on_the_same_day_is_a_rollback(self):
        self.assertRefused("older than the committed store", pem("Tue Jul 14 03:12:00 2026 GMT"))

    def test_exactly_as_many_certificates_as_the_bundle_allows_is_accepted(self):
        shutil.rmtree(self.tree.root)
        self.tree = Tree(self.tree.root, max_certs=10)
        self.assertTrue(self.refresh(pem(NEW_DATE, count=10)))

    def test_a_failing_regeneration_writes_nothing(self):
        def broken(text):
            raise ca_store.StoreError("cannot fetch certdata.txt")
        self.assertRefusedWith("cannot fetch certdata", pem(NEW_DATE), broken)

    def assertRefusedWith(self, message, text, regenerate):
        before = self.tree.snapshot()
        with self.assertRaisesRegex(ca_store.StoreError, message):
            self.refresh(text, regenerate=regenerate)
        self.assertEqual(self.tree.snapshot(), before)


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tree = Tree(self.tmp)  # as of 2026-07-14, limit 180 days

    def test_a_fresh_store_passes(self):
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2027, 1, 10)), ([], []))

    def test_a_stale_store_warns(self):
        errors, warnings = ca_store.check(self.tree.root, today=datetime.date(2027, 1, 11))
        self.assertEqual(errors, [])
        self.assertIn("181 days old", warnings[0])

    def test_a_stale_store_fails_a_release(self):
        errors, warnings = ca_store.check(self.tree.root, release=True,
                                          today=datetime.date(2027, 1, 11))
        self.assertEqual(warnings, [])
        self.assertIn("181 days old", errors[0])

    def test_a_fresh_store_passes_a_release(self):
        self.assertEqual(ca_store.check(self.tree.root, release=True,
                                        today=datetime.date(2026, 9, 29)), ([], []))

    def test_the_release_flag_sets_the_exit_status(self):
        arguments = ["check", "--repo-root", str(self.tree.root), "--today", "2027-06-01"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ca_store.main(arguments), 0)
            self.assertEqual(ca_store.main([*arguments, "--release"]), 1)

    def test_a_pins_date_that_disagrees_with_the_store_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_ISO, NEW_ISO))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
        self.assertIn("is from %s, CA_MOZILLA_DATE says %s" % (OLD_ISO, NEW_ISO), errors[0])

    def test_a_pins_date_that_is_not_iso_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_ISO, "2026-07-14"))
        with self.assertRaisesRegex(ca_store.StoreError, "not of the form"):
            ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))

    def test_more_certificates_than_the_bundle_allows_fails(self):
        shutil.rmtree(self.tree.root)
        self.tree = Tree(self.tree.root, max_certs=19)
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
        self.assertEqual(len(errors), 2)
        self.assertIn("MAX_CERTS=19, the store has 20", errors[0])

    def test_a_date_in_the_future_fails(self):
        errors, _ = ca_store.check(self.tree.root, now=datetime.datetime(2026, 7, 13, 3, 12, 0))
        self.assertIn("in the future", errors[0])

    def test_a_certdata_ref_that_is_not_a_commit_fails(self):
        self.tree.pins.write_text(self.tree.pins.read_text().replace(OLD_REF, "firefox@release"))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
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
        (stray / "sdkconfig").write_text(SDKCONFIG % ("../../../ca_store/cacert.pem", 200))
        other = self.tree.root / "software/u64ctrl/build"
        (other / "sdkconfig").parent.mkdir(parents=True)
        (other / "sdkconfig").write_text("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y\n"
                                         "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y\n")
        self.assertEqual(ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29)),
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
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
        self.assertIn("does not match CA_SHA256", errors[0])

    def test_a_project_back_on_the_default_bundle_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y\n"
                             "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y\n"
                             "# CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE is not set\n")
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
        self.assertEqual(len(errors), 2)
        self.assertIn("software/u64ctrl/sdkconfig", errors[0])

    def test_a_project_that_adds_the_default_bundle_to_the_store_fails(self):
        sdkconfig = self.tree.root / "software/u64ctrl/sdkconfig"
        sdkconfig.write_text(sdkconfig.read_text().replace(
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y",
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y"))
        errors, _ = ca_store.check(self.tree.root, today=datetime.date(2026, 9, 29))
        self.assertIn("DEFAULT_NONE", errors[0])


class CommittedStoreTest(unittest.TestCase):
    """The tree as committed."""

    @unittest.skipUnless(os.environ.get("CA_STORE_ONLINE") == "1", "set CA_STORE_ONLINE=1")
    def test_the_committed_store_is_what_mozillas_certdata_gives(self):
        pins = ca_store.read_pins(REPO_ROOT / ca_store.STORE_DIR / ca_store.PINS_NAME)
        ref, again = ca_store.regenerate(COMMITTED)
        self.assertEqual(ref, pins["CA_CERTDATA_REF"])
        self.assertEqual(again, COMMITTED.encode())

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
