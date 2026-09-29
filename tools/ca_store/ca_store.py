#!/usr/bin/env python3
"""Checks the Mozilla root store the ESP32 modules trust for TLS, before every ESP32 build.

    ca_store.py check      fail if the store, its pins and the sdkconfigs disagree; warn when
                           the store is older than CA_MAX_AGE_DAYS, and fail instead with
                           --release. Also makes the next build regenerate a module's bundle
                           when the store changed since that module was last built.
    ca_store.py pin        after a reviewed edit of anchors.pem: update CA_ANCHORS_SHA256 and
                           CA_BUNDLE_SET_SHA256, and bump IDENT_MINOR of every module that
                           attaches the bundle when its certificates changed

The store is the directory software/wifi/ca_store: cacert.pem, the bundle curl extracts from
Mozilla's certdata.txt (the same source ESP-IDF's own cacrt_all.pem comes from); anchors.pem, a
few roots Mozilla dropped that cross-signed chains servers send still need, chosen by hand; and
CA_PINS. Each ESP32 project's sdkconfig selects CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE and
points CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH at the directory, so ESP-IDF's
gen_crt_bundle.py builds the device's bundle from every .pem in it at every build. ESP-IDF
refreshes its own copy only at minor releases, so a patch-release bump never makes it current.

The Ultimate's updater reflashes a module only when the version the module reports differs from
the one it carries. CA_BUNDLE_SET_SHA256 pins the set of certificates the bundle is built from,
so `check` fails when that set changes without the pin, and `pin` moves the pin
together with IDENT_MINOR of every module whose own sources attach the bundle. A module that
does not attach it carries no bundle in its image, and is not reflashed for nothing.

Only the standard library, so it runs in the build image and on a stock runner alike.
"""

import argparse
import base64
import datetime
import hashlib
import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE_DIR = "software/wifi/ca_store"
PEM_NAME = "cacert.pem"
PINS_NAME = "CA_PINS"
ANCHORS_NAME = "anchors.pem"
PIN_KEYS = ("CA_SOURCE_URL", "CA_MOZILLA_DATE", "CA_SHA256", "CA_MAX_AGE_DAYS", "CA_CERTDATA_REF",
            "CA_ANCHORS_SHA256", "CA_BUNDLE_SET_SHA256")

DATE_PREFIX = "## Certificate data from Mozilla as of: "
BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
# How far ahead of this host's clock a Mozilla date may be. A later one would make every real
# update look like a rollback, and the age gate would never fire again.
CLOCK_SLACK = datetime.timedelta(days=1)
# What a module's sources call when they verify servers against the bundle. A module that never
# calls it has no bundle in its image.
ATTACH = "esp_crt_bundle_attach"
# In each project's build directory: which store its bundle was last generated from.
STAMP_NAME = "ca_store.stamp"
BUNDLE_OUTPUT = "esp-idf/mbedtls/x509_crt_bundle"


class StoreError(Exception):
    pass


def store_paths(repo_root):
    store = pathlib.Path(repo_root) / STORE_DIR
    return store / PEM_NAME, store / PINS_NAME


def write_atomically(path, data):
    """Writes through a new file renamed into place. The rename changes the directory's
    modification time, which is what ESP-IDF's build watches when the bundle path is a
    directory, so an incremental build regenerates the bundle."""
    path = pathlib.Path(path)
    temporary = path.with_name(path.name + ".new")
    temporary.write_bytes(data)
    os.replace(str(temporary), str(path))


# CA_PINS: KEY=VALUE lines and # comments, parsed like tests/crypto/PINS and shell-sourceable,
# so no value has quotes or spaces.


# CA_PINS: KEY=VALUE lines and # comments, parsed like tests/crypto/PINS and shell-sourceable,
# so no value has quotes or spaces.


def read_pins(path):
    pins = {}
    for line in pathlib.Path(path).read_text().split("\n"):
        line = line.split("#", 1)[0].strip()
        if line:
            if "=" not in line:
                raise StoreError("%s: %r is not KEY=VALUE" % (path, line))
            key, value = line.split("=", 1)
            pins[key] = value
    missing = [key for key in PIN_KEYS if key not in pins]
    if missing:
        raise StoreError("%s: missing %s" % (path, ", ".join(missing)))
    if not pins["CA_MAX_AGE_DAYS"].isdigit():
        raise StoreError("%s: CA_MAX_AGE_DAYS=%s is not a number of days"
                         % (path, pins["CA_MAX_AGE_DAYS"]))
    return pins


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def write_pins(path, updates):
    """Rewrites the given keys in place, keeping the order and the comments."""
    out = []
    for line in pathlib.Path(path).read_text().split("\n"):
        key = line.split("=", 1)[0]
        if "=" in line and not line.startswith("#") and key in updates:
            line = "%s=%s" % (key, updates[key])
        out.append(line)
    write_atomically(path, "\n".join(out).encode())


# The PEM.


def mozilla_date(text):
    for line in text.split("\n"):
        if line.startswith(DATE_PREFIX):
            return line[len(DATE_PREFIX):].strip()
    raise StoreError("no '%s' line" % DATE_PREFIX.strip("# "))


def parse_date(stamp):
    # "Fri Sep 25 03:12:01 2026 GMT", parsed by hand so the host's locale cannot change it.
    match = re.fullmatch(r"\w{3} (\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\d{4}) GMT", stamp)
    if not match or match.group(1) not in MONTHS:
        raise StoreError("unrecognised Mozilla date %r" % stamp)
    month, day, hour, minute, second, year = match.groups()
    return datetime.datetime(int(year), MONTHS.index(month) + 1, int(day),
                             int(hour), int(minute), int(second))


def iso(stamp):
    """The header's date as CA_PINS holds it: 2026-09-25T03:12:01Z."""
    return parse_date(stamp).strftime(ISO_FORMAT)


def parse_iso(value):
    try:
        return datetime.datetime.strptime(value, ISO_FORMAT)
    except ValueError:
        raise StoreError("CA_MOZILLA_DATE=%s is not of the form 2026-09-25T03:12:01Z" % value)


def certificates(text):
    """The DER of each certificate, after checking the file is whole."""
    ders = []
    inside = None
    for line in text.split("\n"):
        if line == BEGIN:
            if inside is not None:
                raise StoreError("certificate %d is not closed" % (len(ders) + 1))
            inside = []
        elif line == END:
            if inside is None:
                raise StoreError("END without BEGIN after certificate %d" % len(ders))
            try:
                der = base64.b64decode("".join(inside), validate=True)
            except ValueError:
                raise StoreError("certificate %d is not valid base64" % (len(ders) + 1))
            if len(der) < 4 or der[0] != 0x30:
                raise StoreError("certificate %d is not DER" % (len(ders) + 1))
            ders.append(der)
            inside = None
        elif inside is not None:
            inside.append(line)
    if inside is not None:
        raise StoreError("the file ends inside certificate %d (truncated?)" % (len(ders) + 1))
    if not ders:
        raise StoreError("no certificates")
    if not text.endswith(END + "\n"):
        raise StoreError("the file does not end with a whole certificate (truncated?)")
    return ders


def names(text):
    """The label curl writes above each certificate, in file order."""
    lines = text.split("\n")
    return [lines[i - 2] for i, line in enumerate(lines)
            if line == BEGIN and i >= 2 and lines[i - 1].startswith("=")]


def _tlv(der, pos):
    """(tag, start of the value, end of the element) of the DER element at pos."""
    if pos + 2 > len(der):
        raise StoreError("DER ends early")
    tag, length = der[pos], der[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(der):
            raise StoreError("bad DER length")
        length = int.from_bytes(der[pos:pos + count], "big")
        pos += count
    if pos + length > len(der):
        raise StoreError("DER element runs past its end")
    return tag, pos, pos + length


def subject_and_key(der):
    """The subject name and the SubjectPublicKeyInfo of a certificate, each as DER. These are
    the two things ESP-IDF's bundle keeps of a root."""
    _, start, _ = _tlv(der, 0)                  # Certificate
    _, pos, _ = _tlv(der, start)                # tbsCertificate
    fields = []
    while len(fields) < 7:
        tag, _, end = _tlv(der, pos)
        if not (tag == 0xA0 and not fields):    # skip the optional [0] version
            fields.append(der[pos:end])
        pos = end
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    return fields[4], fields[5]


def not_after(der):
    """A certificate's notAfter, as a naive UTC datetime."""
    _, start, _ = _tlv(der, 0)
    _, pos, _ = _tlv(der, start)
    fields = []
    while len(fields) < 4:
        tag, _, end = _tlv(der, pos)
        if not (tag == 0xA0 and not fields):
            fields.append(der[pos:end])
        pos = end
    validity = fields[3]
    _, start, _ = _tlv(validity, 0)
    _, _, end = _tlv(validity, start)
    tag, value, stop = _tlv(validity, end)
    stamp = validity[value:stop].decode("ascii")
    if tag == 0x17:                             # UTCTime, years 1950-2049
        stamp = ("19" if int(stamp[:2]) >= 50 else "20") + stamp
    return datetime.datetime.strptime(stamp, "%Y%m%d%H%M%SZ")


def roots(text):
    """{sha256 fingerprint: (label, subject DER, key DER)} of every certificate in a store."""
    if not text:
        return {}
    ders = certificates(text)
    labels = names(text)
    if len(labels) != len(ders):
        labels = ["(no label)"] * len(ders)
    return {hashlib.sha256(der).hexdigest(): (label, *subject_and_key(der))
            for label, der in zip(labels, ders)}


def bundle_certificates(store_dir):
    """The DER of every certificate the bundle is built from: cacert.pem, then anchors.pem."""
    store_dir = pathlib.Path(store_dir)
    ders = certificates((store_dir / PEM_NAME).read_text())
    anchors = store_dir / ANCHORS_NAME
    return ders + (certificates(anchors.read_text()) if anchors.exists() else [])


def bundle_set_sha256(ders):
    """CA_BUNDLE_SET_SHA256: the sha256 over the DER encodings, sorted and concatenated. DER is
    self-delimiting, so the concatenation is unambiguous, and the order of the files and of the
    certificates in them does not matter, as it does not to gen_crt_bundle.py."""
    return hashlib.sha256(b"".join(sorted(set(ders)))).hexdigest()


# The ESP32 projects that build their bundle from the store.


def has_line(text, line):
    return line in text.split("\n")


def projects(repo_root):
    """(project dir, sdkconfig text) of every ESP32 project whose bundle comes from the store."""
    repo_root = pathlib.Path(repo_root)
    store = (repo_root / STORE_DIR).resolve()
    found = []
    for sdkconfig in sorted(repo_root.glob("software/**/sdkconfig")):
        if "build" in sdkconfig.relative_to(repo_root).parts:
            continue
        text = sdkconfig.read_text()
        if not has_line(text, "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y"):
            continue
        match = re.search(r'^CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH="(.*)"$', text, re.M)
        if match and (sdkconfig.parent / match.group(1)).resolve() == store:
            found.append((sdkconfig.parent, text))
    return found


def attaching(project):
    """Whether a project's own sources (under main/, not ESP-IDF's) attach the bundle."""
    for path in sorted((pathlib.Path(project) / "main").rglob("*")):
        if (path.suffix in (".c", ".cc", ".cpp", ".h")
                and ATTACH in path.read_text(errors="replace")):
            return True
    return False


def bundle_misconfigured(repo_root):
    """Every sdkconfig that builds a bundle must build it from the store and nothing else."""
    repo_root = pathlib.Path(repo_root)
    using = {project for project, _ in projects(repo_root)}
    problems = []
    for sdkconfig in sorted(repo_root.glob("software/**/sdkconfig")):
        if "build" in sdkconfig.relative_to(repo_root).parts:
            continue
        text = sdkconfig.read_text()
        if not has_line(text, "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y"):
            continue
        relative = sdkconfig.relative_to(repo_root)
        if sdkconfig.parent not in using:
            problems.append("%s: CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH does not name the "
                            "directory %s (a path to %s alone leaves out %s)"
                            % (relative, STORE_DIR, PEM_NAME, ANCHORS_NAME))
        elif not has_line(text, "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y"):
            problems.append("%s: names the store but does not set "
                            "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y, so the path is ignored"
                            % relative)
        if not has_line(text, "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE=y"):
            problems.append("%s: also takes ESP-IDF's default bundle; select "
                            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE" % relative)
    return problems


def max_certs(text):
    match = re.search(r"^CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=(\d+)$", text, re.M)
    return int(match.group(1)) if match else None


def bump_ident(project, date):
    """IDENT_MINOR and IDENT_STRING up by one, with a line saying why, as the header keeps them.

    Returns (header, new text, new version) and writes nothing, so refresh can check every
    project before it changes any file."""
    header = project / "main" / "rpc_dispatch.h"
    if not header.exists():
        raise StoreError("%s uses the store but has no %s" % (project, header))
    text = header.read_text()
    major = re.search(r"^#define IDENT_MAJOR\s+(\d+)$", text, re.M)
    minor = re.search(r"^#define IDENT_MINOR\s+(\d+)$", text, re.M)
    string = re.search(r'^#define IDENT_STRING "(.* V)(\d+)\.(\d+)"$', text, re.M)
    if not (major and minor and string):
        raise StoreError("%s: IDENT_MAJOR, IDENT_MINOR or IDENT_STRING not found" % header)
    if (string.group(2), string.group(3)) != (major.group(1), minor.group(1)):
        raise StoreError("%s: IDENT_STRING says %s.%s, IDENT_MAJOR/MINOR say %s.%s" % (
            header, string.group(2), string.group(3), major.group(1), minor.group(1)))
    new = int(minor.group(1)) + 1
    version = "%s.%d" % (major.group(1), new)
    text = (text[:minor.start()] + minor.group(0).replace(minor.group(1), str(new))
            + text[minor.end():])
    text = (text[:string.start()] + '#define IDENT_STRING "%s%s"' % (string.group(1), version)
            + text[string.end():])
    major = re.search(r"^#define IDENT_MAJOR\s+\d+\n", text, re.M)
    note = "// %s: the Mozilla root store as of %s.\n" % (version, date)
    return header, text[:major.end()] + note + text[major.end():], version


def pin_bundle(repo_root, day, pem_updates=None):
    """Moves CA_ANCHORS_SHA256 and CA_BUNDLE_SET_SHA256 to what is in the store (plus any other
    pins given), and when the bundle's certificates changed bumps IDENT_MINOR of every module
    that attaches the bundle. Checks every header before it writes anything. Returns
    (paths written, [(project, new version)])."""
    pem_path, pins_path = store_paths(repo_root)
    pins = read_pins(pins_path)
    ders = bundle_certificates(pem_path.parent)
    new_set = bundle_set_sha256(ders)
    bumps = []
    if new_set != pins["CA_BUNDLE_SET_SHA256"]:
        bumps = [bump_ident(project, day) for project, _ in projects(repo_root)
                 if attaching(project)]
    updates = dict(pem_updates or {})
    updates["CA_ANCHORS_SHA256"] = hashlib.sha256(
        (pem_path.parent / ANCHORS_NAME).read_bytes()).hexdigest()
    updates["CA_BUNDLE_SET_SHA256"] = new_set
    write_pins(pins_path, updates)
    written, bumped = [pins_path], []
    for header, text, version in bumps:
        write_atomically(header, text.encode())
        written.append(header)
        bumped.append((header.parent.parent, version))
    return written, bumped


def store_stamp(store_dir):
    """The sha256 over the name and contents of every file gen_crt_bundle.py reads from the
    store directory."""
    digest = hashlib.sha256()
    for path in sorted(pathlib.Path(store_dir).iterdir()):
        if path.is_file() and path.name.endswith((".pem", ".der")):
            data = path.read_bytes()
            digest.update(b"%s\0%d\0" % (path.name.encode(), len(data)) + data)
    return digest.hexdigest()


def restamp_builds(repo_root):
    """ESP-IDF's build regenerates the bundle only when the store directory's own time changes,
    which an edit in place does not do. So each project's build directory keeps the stamp of the
    store its bundle came from; on a mismatch the generated bundle is deleted, and the next build
    makes it again. Returns the projects whose bundle was dropped."""
    stamp = store_stamp(pathlib.Path(repo_root) / STORE_DIR)
    dropped = []
    for project, _ in projects(repo_root):
        build = project / "build"
        if not build.is_dir():
            continue                            # a first build generates the bundle anyway
        stamp_file = build / STAMP_NAME
        if stamp_file.exists() and stamp_file.read_text().strip() == stamp:
            continue
        bundle = build / BUNDLE_OUTPUT
        if bundle.exists():
            bundle.unlink()
            dropped.append(project)
        stamp_file.write_text(stamp + "\n")
    return dropped


# The check.


def check_anchors(store_dir, pins, store, now):
    """(anchor DERs, errors, warnings). ESP-IDF builds the bundle from every .pem and .der in
    the store directory, so nothing but the two known files may be there."""
    errors, warnings = [], []
    for path in sorted(store_dir.iterdir()):
        if path.suffix in (".pem", ".der") and path.name not in (PEM_NAME, ANCHORS_NAME):
            errors.append("%s would go into every module's bundle: only %s and %s belong in %s"
                          % (path.name, PEM_NAME, ANCHORS_NAME, STORE_DIR))
    path = store_dir / ANCHORS_NAME
    if not path.exists():
        return [], [*errors, "%s is missing" % ANCHORS_NAME], warnings
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pins["CA_ANCHORS_SHA256"]:
        errors.append("%s does not match CA_ANCHORS_SHA256 in %s" % (ANCHORS_NAME, PINS_NAME))
    try:
        anchors = certificates(data.decode("utf-8", "replace"))
    except StoreError as error:
        return [], [*errors, "%s: %s" % (ANCHORS_NAME, error)], warnings
    labels = names(data.decode("utf-8", "replace"))
    for i, der in enumerate(anchors):
        label = labels[i] if len(labels) == len(anchors) else "anchor %d" % (i + 1)
        if der in store:
            errors.append("%s: %s is in %s again; remove it from %s"
                          % (ANCHORS_NAME, label, PEM_NAME, ANCHORS_NAME))
        if not_after(der) < now:
            warnings.append("%s: %s expired on %s; remove it"
                            % (ANCHORS_NAME, label, not_after(der).date()))
    return anchors, errors, warnings


def check(repo_root, release=False, today=None, now=None):
    """Returns (errors, warnings)."""
    pem_path, pins_path = store_paths(repo_root)
    pins = read_pins(pins_path)
    now = now or utc_now()
    errors = []
    if not re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", pins["CA_CERTDATA_REF"]):
        errors.append("CA_CERTDATA_REF=%s is not owner/repo@<full commit SHA>"
                      % pins["CA_CERTDATA_REF"])
    if parse_iso(pins["CA_MOZILLA_DATE"]) > now + CLOCK_SLACK:
        errors.append("CA_MOZILLA_DATE=%s is in the future" % pins["CA_MOZILLA_DATE"])
    data = pem_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pins["CA_SHA256"]:
        errors.append("%s does not match CA_SHA256 in %s" % (pem_path.name, PINS_NAME))
    text = data.decode("utf-8", "replace")
    try:
        if iso(mozilla_date(text)) != pins["CA_MOZILLA_DATE"]:
            errors.append("%s is from %s, CA_MOZILLA_DATE says %s"
                          % (pem_path.name, iso(mozilla_date(text)), pins["CA_MOZILLA_DATE"]))
        store = certificates(text)
    except StoreError as error:
        errors.append("%s: %s" % (pem_path.name, error))
        store = []
    anchors, anchor_errors, anchor_warnings = check_anchors(pem_path.parent, pins, store, now)
    errors += anchor_errors
    count = len(store) + len(anchors)
    subjects = {}
    for der in store + anchors:
        subject = subject_and_key(der)[0]
        if subject in subjects and subjects[subject] != der:
            # ESP-IDF's lookup is a binary search that tries one root per subject, so which of
            # two would be used depends on where they sort.
            errors.append("two roots in the bundle have the same subject: %s and %s"
                          % (hashlib.sha256(subjects[subject]).hexdigest()[:16],
                             hashlib.sha256(der).hexdigest()[:16]))
        subjects[subject] = der
    pinned_set = pins["CA_BUNDLE_SET_SHA256"]
    if not anchor_errors and store and bundle_set_sha256(store + anchors) != pinned_set:
        modules = [os.path.relpath(p, repo_root) for p, _ in projects(repo_root) if attaching(p)]
        errors.append("the bundle's certificates changed but CA_BUNDLE_SET_SHA256 did not: run "
                      "`python3 tools/ca_store/ca_store.py pin`, which bumps IDENT_MINOR of %s"
                      % (", ".join(modules) or "no module (none attaches the bundle)"))
    errors += bundle_misconfigured(repo_root)
    for project, sdkconfig in projects(repo_root):
        limit = max_certs(sdkconfig)
        if limit is not None and count > limit:
            errors.append("%s/sdkconfig: CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=%d, "
                          "the store has %d" % (os.path.relpath(project, repo_root), limit, count))

    warnings = anchor_warnings
    today = today or now.date()
    age = (today - parse_iso(pins["CA_MOZILLA_DATE"]).date()).days
    limit = int(pins["CA_MAX_AGE_DAYS"])
    if age > limit:
        message = ("the Mozilla root store is %d days old (as of %s), over CA_MAX_AGE_DAYS=%d: "
                   "take a newer cacert.pem from CA_SOURCE_URL"
                   % (age, pins["CA_MOZILLA_DATE"], limit))
        (errors if release else warnings).append(message)
    return errors, warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("check", "pin"))
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--release", action="store_true",
                        help="check: a stale store is an error, not a warning")
    parser.add_argument("--today", type=datetime.date.fromisoformat, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    repo_root = pathlib.Path(arguments.repo_root)

    try:
        if arguments.command == "pin":
            written, _ = pin_bundle(repo_root, utc_now().date().isoformat())
            for path in written:
                print("ca_store: wrote %s" % os.path.relpath(path, repo_root))
            return 0
        errors, warnings = check(repo_root, arguments.release, arguments.today)
        for project in ([] if errors else restamp_builds(repo_root)):
            print("ca_store: the store changed since %s was built; its bundle will be made again"
                  % os.path.relpath(project, repo_root))
    except (StoreError, OSError) as error:
        print("ca_store: %s" % error, file=sys.stderr)
        return 1

    for message in warnings:
        print("ca_store: warning: %s" % message, file=sys.stderr)
    for message in errors:
        print("ca_store: %s" % message, file=sys.stderr)
    if errors:
        return 1
    if not warnings:
        date = read_pins(store_paths(repo_root)[1])["CA_MOZILLA_DATE"]
        print("ca_store: the Mozilla root store is as of %s" % date)
    return 0


if __name__ == "__main__":
    sys.exit(main())
