#!/usr/bin/env python3
"""Keeps the Mozilla root store the ESP32 modules trust for TLS current.

    ca_store.py refresh    fetch curl's cacert.pem, verify it, and if Mozilla's data changed
                           write it, CA_PINS and a version bump of every module that uses it
    ca_store.py check      fail if the store and the sdkconfigs disagree; warn when the store
                           is older than CA_MAX_AGE_DAYS, and fail instead with --release

The store is software/wifi/ca_store/cacert.pem, the bundle curl extracts from Mozilla's
certdata.txt (the same source ESP-IDF's own cacrt_all.pem comes from), with CA_PINS beside it.
Each ESP32 project's sdkconfig selects CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE and points
CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH at the file, so ESP-IDF's gen_crt_bundle.py builds
the device's bundle from it at every build. ESP-IDF refreshes its own copy only at minor
releases, so a patch-release bump never makes it current.

The Ultimate's updater reflashes a module only when the version the module reports differs
from the one it carries, so a store change that does not bump IDENT_MINOR never reaches a
device. `refresh` therefore bumps every project whose sdkconfig uses the store, in the same
change.

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
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE_DIR = "software/wifi/ca_store"
PEM_NAME = "cacert.pem"
PINS_NAME = "CA_PINS"
PIN_KEYS = ("CA_SOURCE_URL", "CA_MOZILLA_DATE", "CA_SHA256", "CA_MAX_AGE_DAYS")

DATE_PREFIX = "## Certificate data from Mozilla as of: "
BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
FETCH_TIMEOUT = 60


class StoreError(Exception):
    pass


def store_paths(repo_root):
    store = pathlib.Path(repo_root) / STORE_DIR
    return store / PEM_NAME, store / PINS_NAME


# CA_PINS: KEY=VALUE lines and # comments, shell-sourceable, so a value with spaces is quoted.


def read_pins(path):
    pins = {}
    for line in pathlib.Path(path).read_text().split("\n"):
        line = line.split("#", 1)[0].strip()
        if line:
            key, value = line.split("=", 1)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            pins[key] = value
    missing = [key for key in PIN_KEYS if key not in pins]
    if missing:
        raise StoreError("%s: missing %s" % (path, ", ".join(missing)))
    return pins


def write_pins(path, updates):
    """Rewrites the given keys in place, keeping the order and the comments."""
    out = []
    for line in pathlib.Path(path).read_text().split("\n"):
        key = line.split("=", 1)[0]
        if "=" in line and not line.startswith("#") and key in updates:
            value = updates[key]
            line = '%s="%s"' % (key, value) if " " in value else "%s=%s" % (key, value)
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
    text = text[:minor.start()] + minor.group(0).replace(minor.group(1), str(new)) + text[minor.end():]
    text = (text[:string.start()] + '#define IDENT_STRING "%s%s"' % (string.group(1), version)
            + text[string.end():])
    major = re.search(r"^#define IDENT_MAJOR\s+\d+\n", text, re.M)
    note = "// %s: the Mozilla root store as of %s.\n" % (version, date)
    return header, text[:major.end()] + note + text[major.end():], version


# The commands.


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as error:
        raise StoreError("cannot fetch %s: %s" % (url, error))


def published_sha256(data, url):
    match = re.match(r"([0-9a-f]{64})\s", data.decode("ascii", "replace") + "\n")
    if not match:
        raise StoreError("%s is not a sha256 sum" % url)
    return match.group(1)


def refresh(repo_root, source=None, summary=None):
    """Returns the paths written, empty when Mozilla's data has not changed."""
    pem_path, pins_path = store_paths(repo_root)
    pins = read_pins(pins_path)
    url = source or pins["CA_SOURCE_URL"]
    data = fetch(url)
    text, date, ders = validate(data, published_sha256(fetch(url + ".sha256"), url + ".sha256"))

    old_text = pem_path.read_text() if pem_path.exists() else ""
    old_date = pins["CA_MOZILLA_DATE"]
    if parse_date(date) < parse_date(old_date):
        raise StoreError("%s is older than the committed store (%s, committed %s)"
                         % (url, date, old_date))
    if date == old_date:
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

    day = parse_date(date).date().isoformat()
    bumps = [(project,) + bump_ident(project, day) for project, _ in using]

    pem_path.write_bytes(data)
    write_pins(pins_path, {"CA_MOZILLA_DATE": date,
                           "CA_SHA256": hashlib.sha256(data).hexdigest()})
    written = [pem_path, pins_path]
    bumped = []
    for project, header, text_after, version in bumps:
        header.write_text(text_after)
        written.append(header)
        bumped.append((project, version))

    if summary:
        old_names = set(names(old_text)) if old_text else set()
        new_names = set(names(text))
        lines = ["Mozilla root store from %s as of %s (was %s), %d certificates."
                 % (url, date, old_date, len(ders)), ""]
        lines += ["Added: %s" % name for name in sorted(new_names - old_names)]
        lines += ["Removed: %s" % name for name in sorted(old_names - new_names)]
        lines += [""] + ["%s now reports %s." % (os.path.relpath(p, repo_root), v)
                         for p, v in bumped]
        pathlib.Path(summary).write_text("\n".join(lines) + "\n")
    return written


def check(repo_root, release=False, today=None):
    """Returns (errors, warnings)."""
    pem_path, pins_path = store_paths(repo_root)
    pins = read_pins(pins_path)
    errors = []
    data = pem_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pins["CA_SHA256"]:
        errors.append("%s does not match CA_SHA256 in %s" % (pem_path.name, PINS_NAME))
    text = data.decode("utf-8", "replace")
    try:
        if mozilla_date(text) != pins["CA_MOZILLA_DATE"]:
            errors.append("%s is from %s, CA_MOZILLA_DATE says %s"
                          % (pem_path.name, mozilla_date(text), pins["CA_MOZILLA_DATE"]))
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
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    age = (today - parse_date(pins["CA_MOZILLA_DATE"]).date()).days
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
