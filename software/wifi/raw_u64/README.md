# ESP32 WiFi bridge (raw_u64)

## Building

The bridge builds with ESP-IDF v6.0.3 (for example in the `espressif/idf:v6.0.3` image):
`idf.py build` here, or `make esp32_raw_u64` from the top of the repository. The image is
`build/bridge.bin`; its version is `IDENT_MINOR` in `main/rpc_dispatch.h`, and the Ultimate's
updater reflashes a module only when that differs from what the module reports. The repository's
Docker image (`docker/Dockerfile`) and the CI step `make esp32` still carry ESP-IDF v5.3.1, which
cannot build this project: build it in an ESP-IDF v6.0.3 environment, and the rest of the tree as before.

mbedTLS is ESP-IDF's own, as ESP-IDF imports it: the build carries no patch to it. Known issue:
stock mbedTLS refuses a cookie in a TLS 1.3 HelloRetryRequest (Mbed-TLS/mbedtls#9543), so a
server that sends one, as OpenJDK's JSSE does, fails the handshake. The host test case
`known_issue_hrr_cookie` (`test/`) asserts that behaviour and fails once the library changes.

## The certificate bundle: the Mozilla root store, vendored

The roots the bridge trusts in BUNDLE mode come from `software/wifi/ca_store/cacert.pem`, not
from ESP-IDF's copy. ESP-IDF refreshes its own `cacrt_all.pem` on its release branches only now
and then: v6.0.3 ships Mozilla's data of 2025-12-02, with roots Mozilla has since dropped.

- **Where it comes from.** `cacert.pem` is curl's extract of Mozilla's `certdata.txt`
  (<https://curl.se/ca/cacert.pem>), byte for byte; the data is Mozilla's, under the Mozilla Public
  License 2.0 (<https://mozilla.org/MPL/2.0/>). `CA_PINS` beside it records the source URL,
  the Mozilla date, the file's sha256 (`CA_SHA256`), the `certdata.txt` commit on GitHub it was
  regenerated from as a cross-check (`CA_CERTDATA_REF`), the sha256 of its set of certificates
  (`CA_BUNDLE_SET_SHA256`) and the age limit (`CA_MAX_AGE_DAYS`).
- **How the build uses it.** `sdkconfig` selects `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_NONE`,
  so none of ESP-IDF's roots are merged in, and points `CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH`
  at `../ca_store/cacert.pem`; ESP-IDF's `gen_crt_bundle.py` builds the bundle from that file and
  builds it again whenever the file changes.
- **How the build verifies it.** `CMakeLists.txt` runs `python3 tools/ca_store/ca_store.py check`
  at every configure (an edit to `cacert.pem`, `CA_PINS` or the checker configures again) and
  again at every build, before the bundle is made, so an already-configured tree cannot skip it.
  It checks the configuration the build really uses (its `config/sdkconfig.json`, which
  `idf.py -D SDKCONFIG=...` can point away from this directory's `sdkconfig`). The build fails
  when `cacert.pem` does not match `CA_SHA256`, when its date disagrees with the pins, when its
  certificates changed without `CA_BUNDLE_SET_SHA256`, when another certificate file (such as an
  `anchors.pem`) is in the store, or when the configuration no longer builds the bundle from the
  store alone with `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY=y`. A store older than
  `CA_MAX_AGE_DAYS` is a warning, and an error when the build runs with `RELEASE=1` in its
  environment (`RELEASE=1 idf.py build`, `make RELEASE=1 esp32_raw_u64`). Run the check by hand
  with `python3 tools/ca_store/ca_store.py check`, and its tests with `make ca_store_test`.
- **How to refresh it.** `python3 tools/ca_store/refresh.py --ident-minor N` (needs the network
  and Perl) fetches curl's file and its sum, and takes it only when curl's own `mk-ca-bundle.pl`,
  pinned by commit and sha256, gives the same file from the newest `certdata.txt` on Firefox's
  release branch, which must descend from `CA_CERTDATA_REF`. It writes `cacert.pem` and `CA_PINS`.
  When the certificates changed it also sets `IDENT_MINOR` (and `IDENT_STRING`) in
  `main/rpc_dispatch.h` to N, since the updater reflashes a module only for a new version. N must
  be allocated for this image and above the current minor: the tool refuses a certificate change
  without `--ident-minor`, because on a development line the next number may already belong to
  another image. `--summary FILE` lists what changed by fingerprint, for review. Commit the
  result. Never edit `cacert.pem` by hand: the build refuses it. Moving the pins by hand without
  a new `IDENT_MINOR` is not caught by the check, so review that the two move together.
- **Roots with serial number zero.** Six roots in Mozilla's set as of 2026-09-25 (Go Daddy Root
  CA - G2, Starfield Root CA - G2, Starfield Services Root CA - G2, Security Communication
  RootCA2 and the two HARICA 2015 roots) have serial number 0, which the `cryptography` package
  (48.0) warns is not positive. ESP-IDF's `gen_crt_bundle.py` silences that warning
  today; if a future `cryptography` refuses such certificates, the bundle step fails and the build
  stops (it fails closed, as it would with ESP-IDF's own bundle, which holds the same roots).
- **No anchors.** The ESP-IDF 5.3 line needed four roots Mozilla dropped, kept by hand, for
  cross-signed chains. ESP-IDF 6 verifies cross-signed chains itself
  (`CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY`), so they are retired: `sdkconfig` sets
  it explicitly, `main/tls_engine.c` refuses to build without it, and the check refuses an anchor
  file. Only raw_u64 uses the store; raw_c3 and u64ctrl keep ESP-IDF's bundle.

## The Wi-Fi scan (from the ESP-IDF example this project started as)

This example shows how to use the scan functionality of the Wi-Fi driver of ESP32.

Two scan methods are supported: fast scan and all channel scan.

* fast scan: in this mode, scan finishes right after a matching AP is detected, even if channels are not completely scanned. You can set thresholds for signal strength, as well as select desired authentication modes provided by the AP's. The Wi-Fi driver will ignore AP's that fail to meet mentioned criteria.

* all channel scan: scan will end only after all channels are scanned; the Wi-Fi driver will store 4 of the fully matching AP's. Sort methods for AP's include rssi and authmode. After the scan, the Wi-Fi driver selects the AP that fits best based on the sort.

After the scan, the Wi-Fi driver will try to connect. Because it needs to to allocate precious dynamic memory to store matching AP's, and, most of the cases, connect to the AP with the strongest reception, it does not need to record all the AP's matched. The number of matches stored is limited to 4 in order to limit dynamic memory usage. Among the 4 matches,  AP's are allowed to carry the same SSID name and all possible authentication modes - Open, WEP, WPA and WPA2.
