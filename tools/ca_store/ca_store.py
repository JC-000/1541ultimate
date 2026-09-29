#!/usr/bin/env python3
"""Keeps the Mozilla root store the ESP32 modules trust for TLS current.

    ca_store.py refresh    fetch curl's cacert.pem, verify it against its sum and against a
                           copy regenerated from Mozilla's certdata.txt on GitHub, and if
                           Mozilla's data changed write it and CA_PINS, with a version bump of
                           every module that uses it when the certificates changed
    ca_store.py check      fail if the store and the sdkconfigs disagree; warn when the store
                           is older than CA_MAX_AGE_DAYS, and fail instead with --release

The store is software/wifi/ca_store/cacert.pem, the bundle curl extracts from Mozilla's
certdata.txt (the same source ESP-IDF's own cacrt_all.pem comes from), with CA_PINS beside it.
Each ESP32 project's sdkconfig selects CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE and points
CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH at the file, so ESP-IDF's gen_crt_bundle.py builds
the device's bundle from it at every build. ESP-IDF refreshes its own copy only at minor
releases, so a patch-release bump never makes it current.

curl.se publishes the file and its sum from the same server, so the sum alone proves only that
the download is whole. `refresh` also fetches certdata.txt from Firefox's source on GitHub (the
revision whose sha256 is the one curl's header names, recorded as CA_CERTDATA_REF), runs curl's
own mk-ca-bundle.pl on it (pinned by commit and sha256, and run with Perl), and accepts curl's
file only if the result is byte for byte the same. Changing the store then takes both servers.

The Ultimate's updater reflashes a module only when the version the module reports differs
from the one it carries, so a store change that does not bump IDENT_MINOR never reaches a
device. `refresh` therefore bumps every project whose sdkconfig uses the store, in the same
change, whenever the set of certificates changes. A new date with the same certificates
builds the same bundle and bumps nothing.

Only the standard library (and Perl for `refresh`), so it runs in the build image and on a
stock runner alike.
"""

import argparse
import base64
import calendar
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE_DIR = "software/wifi/ca_store"
PEM_NAME = "cacert.pem"
PINS_NAME = "CA_PINS"
PIN_KEYS = ("CA_SOURCE_URL", "CA_MOZILLA_DATE", "CA_SHA256", "CA_MAX_AGE_DAYS", "CA_CERTDATA_REF")

# The second origin: Mozilla's certdata.txt as Firefox's release branch carries it, and the
# script curl converts it with.
CERTDATA_REPO = "mozilla-firefox/firefox"
CERTDATA_BRANCH = "release"
CERTDATA_PATH = "security/nss/lib/ckfw/builtins/certdata.txt"
CERTDATA_COMMITS = 10
MK_CA_BUNDLE_COMMIT = "d48f2f4ec867783e611beeb2ad53fbabcb94aa6f"
MK_CA_BUNDLE_SHA256 = "8e278f4982210b37e4f9a048bd6ed23df41e4a054085bd73f8242628f03d09ca"
MK_CA_BUNDLE_URL = "https://raw.githubusercontent.com/curl/curl/%s/scripts/mk-ca-bundle.pl"
RAW_URL = "https://raw.githubusercontent.com/%s/%s/%s"
API_URL = "https://api.github.com/repos/%s/commits?sha=%s&path=%s&per_page=%d"

DATE_PREFIX = "## Certificate data from Mozilla as of: "
CERTDATA_PREFIX = "## SHA256: "
BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
FETCH_TIMEOUT = 60
# How far ahead of this host's clock a Mozilla date may be. A later one would make every real
# update look like a rollback, and the age gate would never fire again.
CLOCK_SLACK = datetime.timedelta(days=1)


class StoreError(Exception):
    pass


def store_paths(repo_root):
    store = pathlib.Path(repo_root) / STORE_DIR
    return store / PEM_NAME, store / PINS_NAME


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
    pathlib.Path(path).write_text("\n".join(out))


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


def changes(old_text, new_text):
    """(added, removed, rekeyed) as sorted lists: fingerprints for the first two, and
    (label, old fingerprint, new fingerprint) for a subject that stays with a different key or
    certificate, which is the case to look at by hand because ESP-IDF looks roots up by
    subject."""
    old, new = roots(old_text), roots(new_text)
    by_subject = {subject: fp for fp, (_, subject, _) in old.items()}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    rekeyed = []
    for fp in list(added):
        old_fp = by_subject.get(new[fp][1])
        if old_fp in removed:
            rekeyed.append((new[fp][0], old_fp, fp))
            added.remove(fp)
            removed.remove(old_fp)
    return added, removed, sorted(rekeyed)


def plain(label):
    """A label safe to paste into a pull request description."""
    return re.sub(r"[^A-Za-z0-9 .,()&'/:_+-]", "?", label)[:100]


def certdata_sha256(text):
    for line in text.split("\n"):
        if line.startswith(CERTDATA_PREFIX) and re.fullmatch(r"[0-9a-f]{64}",
                                                             line[len(CERTDATA_PREFIX):]):
            return line[len(CERTDATA_PREFIX):]
    raise StoreError("no '%s' line naming the certdata.txt it came from"
                     % CERTDATA_PREFIX.strip("# :"))


def validate(data, expected_sha256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise StoreError("sha256 mismatch: the file is %s, the published sum is %s"
                         % (actual, expected_sha256))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StoreError("not UTF-8")
    date = mozilla_date(text)
    parse_date(date)
    return text, date, certificates(text)


# The ESP32 projects that build their bundle from the store.


def has_line(text, line):
    return line in text.split("\n")


def projects(repo_root):
    """(project dir, sdkconfig text) of every ESP32 project whose bundle comes from the store."""
    repo_root = pathlib.Path(repo_root)
    pem = (repo_root / STORE_DIR / PEM_NAME).resolve()
    found = []
    for sdkconfig in sorted(repo_root.glob("software/**/sdkconfig")):
        if "build" in sdkconfig.relative_to(repo_root).parts:
            continue
        text = sdkconfig.read_text()
        if not has_line(text, "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y"):
            continue
        match = re.search(r'^CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH="(.*)"$', text, re.M)
        if match and (sdkconfig.parent / match.group(1)).resolve() == pem:
            found.append((sdkconfig.parent, text))
    return found


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
            problems.append("%s: CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH does not name %s/%s"
                            % (relative, STORE_DIR, PEM_NAME))
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


# The commands.


def fetch(url, token=False):
    request = urllib.request.Request(url)
    # A token only raises the API's rate limit; nothing here needs its permissions.
    if token and os.environ.get("GITHUB_TOKEN"):
        request.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as error:
        raise StoreError("cannot fetch %s: %s" % (url, error))


def find_certdata(wanted):
    """(CA_CERTDATA_REF, contents) of the latest of the recent certdata.txt revisions on
    Firefox's release branch whose sha256 is the one curl's file names."""
    url = API_URL % (CERTDATA_REPO, CERTDATA_BRANCH, CERTDATA_PATH, CERTDATA_COMMITS)
    try:
        commits = [c["sha"] for c in json.loads(fetch(url, token=True))]
    except (ValueError, KeyError, TypeError):
        raise StoreError("%s did not return a list of commits" % url)
    for commit in commits:
        data = fetch(RAW_URL % (CERTDATA_REPO, commit, CERTDATA_PATH))
        if hashlib.sha256(data).hexdigest() == wanted:
            return "%s@%s" % (CERTDATA_REPO, commit), data
    raise StoreError("none of the last %d revisions of %s in %s is the certdata.txt curl's file "
                     "names (sha256 %s)" % (len(commits), CERTDATA_PATH, CERTDATA_REPO, wanted))


def regenerate(text):
    """(CA_CERTDATA_REF, bytes): curl's file made again from Mozilla's certdata.txt on GitHub
    with curl's own pinned mk-ca-bundle.pl. Its "as of" line comes from the input's modification
    time, which is set to curl's date, so an honest file comes out identical."""
    ref, certdata = find_certdata(certdata_sha256(text))
    script = fetch(MK_CA_BUNDLE_URL % MK_CA_BUNDLE_COMMIT)
    if hashlib.sha256(script).hexdigest() != MK_CA_BUNDLE_SHA256:
        raise StoreError("mk-ca-bundle.pl at %s is not the pinned file" % MK_CA_BUNDLE_COMMIT)
    stamp = calendar.timegm(parse_date(mozilla_date(text)).timetuple())
    with tempfile.TemporaryDirectory() as work:
        work = pathlib.Path(work)
        (work / "mk-ca-bundle.pl").write_bytes(script)
        (work / "certdata.txt").write_bytes(certdata)
        os.utime(work / "certdata.txt", (stamp, stamp))
        try:
            run = subprocess.run(["perl", "mk-ca-bundle.pl", "-n", "-q", "cacert.pem"], cwd=work,
                                 capture_output=True, check=False)
        except OSError as error:
            raise StoreError("cannot run perl: %s" % error)
        if run.returncode != 0:
            raise StoreError("mk-ca-bundle.pl failed: %s"
                             % run.stderr.decode("utf-8", "replace").strip())
        return ref, (work / "cacert.pem").read_bytes()


def published_sha256(data, url):
    match = re.match(r"([0-9a-f]{64})\s", data.decode("ascii", "replace") + "\n")
    if not match:
        raise StoreError("%s is not a sha256 sum" % url)
    return match.group(1)


def refresh(repo_root, source=None, summary=None, now=None, regenerate=regenerate):
    """Returns the paths written, empty when Mozilla's data has not changed."""
    pem_path, pins_path = store_paths(repo_root)
    pins = read_pins(pins_path)
    url = source or pins["CA_SOURCE_URL"]
    data = fetch(url)
    text, date, ders = validate(data, published_sha256(fetch(url + ".sha256"), url + ".sha256"))

    when, old_date = parse_date(date), pins["CA_MOZILLA_DATE"]
    if when > (now or utc_now()) + CLOCK_SLACK:
        raise StoreError("%s is dated %s, in the future" % (url, iso(date)))
    if when < parse_iso(old_date):
        raise StoreError("%s is older than the committed store (%s, committed %s)"
                         % (url, iso(date), old_date))

    # Every run, changed or not, so a weekly job keeps checking curl.se against Mozilla.
    ref, again = regenerate(text)
    if again != data:
        try:
            added, removed, rekeyed = changes(again.decode("utf-8"), text)
            detail = ("; in curl's file only: %s; in Mozilla's only: %s"
                      % (", ".join(added + [new for _, _, new in rekeyed]) or "none",
                         ", ".join(removed + [old for _, old, _ in rekeyed]) or "none"))
        except (StoreError, UnicodeDecodeError):
            detail = ""
        raise StoreError("%s is not what %s gives when converted with mk-ca-bundle.pl %s%s"
                         % (url, ref, MK_CA_BUNDLE_COMMIT, detail))

    old_text = pem_path.read_text() if pem_path.exists() else ""
    if iso(date) == old_date:
        if old_text and set(ders) != set(certificates(old_text)):
            raise StoreError("the certificates changed but the Mozilla date did not (%s)" % date)
        return []

    using = projects(repo_root)
    for project, sdkconfig in using:
        limit = max_certs(sdkconfig)
        if limit is not None and len(ders) > limit:
            raise StoreError("%d certificates, but %s/sdkconfig allows %d "
                             "(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS)"
                             % (len(ders), project, limit))

    # The bundle is built from the certificates alone, so only a change to them needs the
    # modules reflashed.
    certificates_changed = set(ders) != set(certificates(old_text) if old_text else [])
    day = when.date().isoformat()
    bumps = ([(project, *bump_ident(project, day)) for project, _ in using]
             if certificates_changed else [])

    pem_path.write_bytes(data)
    write_pins(pins_path, {"CA_MOZILLA_DATE": iso(date),
                           "CA_SHA256": hashlib.sha256(data).hexdigest(),
                           "CA_CERTDATA_REF": ref})
    written = [pem_path, pins_path]
    bumped = []
    for project, header, text_after, version in bumps:
        header.write_text(text_after)
        written.append(header)
        bumped.append((project, version))

    if summary:
        pathlib.Path(summary).write_text(describe(old_text, text, url, ref, iso(date), old_date,
                                                  len(ders), bumped, repo_root))
    return written


def describe(old_text, text, url, ref, date, old_date, count, bumped, repo_root):
    """The pull request description: what changed, by SHA-256 fingerprint."""
    added, removed, rekeyed = changes(old_text, text)
    new, old = roots(text), roots(old_text)
    lines = ["Mozilla root store as of %s (was %s), %d certificates." % (date, old_date, count),
             "",
             "Fetched from %s. Regenerated from `%s` with curl's mk-ca-bundle.pl at %s, byte "
             "for byte the same." % (url, ref, MK_CA_BUNDLE_COMMIT), ""]
    if rekeyed:
        lines += ["## SAME SUBJECT, DIFFERENT CERTIFICATE: check each of these by hand", "",
                  "ESP-IDF finds a root by its subject name, so a changed key under the same "
                  "subject changes what the modules trust for every server that names it.", ""]
        lines += ["- %s: `%s` became `%s`" % (plain(label), old_fp, new_fp)
                  for label, old_fp, new_fp in rekeyed]
        lines += [""]
    lines += ["## Added", ""] + (["- `%s` %s" % (fp, plain(new[fp][0])) for fp in added]
                                 or ["None."]) + [""]
    lines += ["## Removed", ""] + (["- `%s` %s" % (fp, plain(old[fp][0])) for fp in removed]
                                   or ["None."]) + [""]
    if bumped:
        lines += ["## Module versions", ""]
        lines += ["- %s now reports %s." % (os.path.relpath(p, repo_root), v) for p, v in bumped]
    else:
        lines += ["The certificates did not change, so the bundle and the module versions do "
                  "not either."]
    return "\n".join(lines) + "\n"


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
        count = len(certificates(text))
    except StoreError as error:
        errors.append("%s: %s" % (pem_path.name, error))
        count = 0
    errors += bundle_misconfigured(repo_root)
    for project, sdkconfig in projects(repo_root):
        limit = max_certs(sdkconfig)
        if limit is not None and count > limit:
            errors.append("%s/sdkconfig: CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=%d, "
                          "the store has %d" % (os.path.relpath(project, repo_root), limit, count))

    warnings = []
    today = today or now.date()
    age = (today - parse_iso(pins["CA_MOZILLA_DATE"]).date()).days
    limit = int(pins["CA_MAX_AGE_DAYS"])
    if age > limit:
        message = ("the Mozilla root store is %d days old (as of %s), over CA_MAX_AGE_DAYS=%d: "
                   "run `python3 tools/ca_store/ca_store.py refresh`"
                   % (age, pins["CA_MOZILLA_DATE"], limit))
        (errors if release else warnings).append(message)
    return errors, warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("refresh", "check"))
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--source", help="refresh: fetch from this URL instead of CA_SOURCE_URL "
                                         "(its sum from the same URL + .sha256)")
    parser.add_argument("--summary", help="refresh: write what changed to this file")
    parser.add_argument("--release", action="store_true",
                        help="check: a stale store is an error, not a warning")
    parser.add_argument("--today", type=datetime.date.fromisoformat, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    repo_root = pathlib.Path(arguments.repo_root)

    try:
        if arguments.command == "refresh":
            written = refresh(repo_root, arguments.source, arguments.summary)
            if not written:
                print("ca_store: the Mozilla root store is current, nothing to do")
            for path in written:
                print("ca_store: wrote %s" % os.path.relpath(path, repo_root))
            return 0
        errors, warnings = check(repo_root, arguments.release, arguments.today)
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
