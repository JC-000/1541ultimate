# tests/crypto: crypto conformance of the ESP32's TLS client

A **host** suite, not a hardware test: it builds mbedTLS on the host with the configuration the
ESP32 image uses, and checks it against independent vectors. It is **opt-in**, not part of the
default gate (`run-tests`): run it when mbedTLS, ESP-IDF or `tls_engine.c` changes.

    tests/crypto/run.sh [outdir]          ESP-IDF v5.3.1 / mbedTLS 3.6.0 (PINS)
    tests/crypto/run_idf6.sh [outdir]     ESP-IDF v6.0.3 / mbedTLS 4.1.1 (PINS.idf6)

The last lines say what matters:

    NOT COVERED: the device uses ESP-IDF hardware code for AES_ALT ... ; this host run tests mbedTLS software paths
    SECURITY DEVIATIONS 3: ...            (accepted by design: ESP-IDF's certificate bundle)
    FAIL-OPEN DEVIATIONS 5: ...           (accepted where x509-limbo refuses, security-relevant)
    KNOWN VULNERABILITIES 1: CVE-2026-49300 (fixed in mbedTLS 3.6.7)
    CRYPTO_CONFORMANCE PASS <n> passed 0 failed <m> suites; insecure outcomes 21 (...), not in passed

"passed" counts three kinds of thing: vectors whose outcome is the one required (by their own
verdict, or by an expectations line, as each suite line splits it), the coverage suite's checks,
and the expectations lines that matched a vector. Vectors that show an insecure outcome as
recorded (known-vulnerable, security-deviation, fail-open, including the same fail-open
behaviour in listed order) and the expectation lines behind them are counted apart, not as passed.

## What it needs

- cc, cmake, python3 (standard library only), git with partial-clone support. The mbedTLS 4
  build also runs mbedTLS's own generators for its test headers, which need Jinja2
  (`scripts/driver.requirements.txt`): a python3 with it first on PATH.
- **Network on the first run.** mbedTLS, ESP-IDF, Wycheproof and x509-limbo are fetched from
  GitHub at the commits in `PINS`; RFC 5869/7748/8439/8448 and the NIST CAVP SHA vectors by URL,
  checked against the sha256 in `conformance.py`. All of it is cached in
  `~/.cache/1541u-build/crypto` (`CRYPTO_CACHE`). After one run, `CRYPTO_OFFLINE=1` uses the
  cache alone and fails on anything missing instead of downloading it.
- About 32 s with a warm cache (offline), mbedTLS build included.

## Files

| File | What |
|---|---|
| `PINS` | the one place the sources come from; a crypto bump is a change here |
| `PINS.idf6`, `sdkconfig.v6.0.3`, `expectations.4`, `esp32_macros.4.txt`, `engine_config.4.txt` | the same for ESP-IDF 6 / mbedTLS 4 (`run_idf6.sh` sets them, and compares engine4's `tls_engine.c` at its `ENGINE4_COMMIT` until the branches meet); the `-nocross` sdkconfig and macro list are the certificate bundle without `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY` |
| `regen_sdkconfig.sh` | regenerates the raw_u64 sdkconfig for another ESP-IDF release with that release's kconfgen, as idf.py does |
| `build_mbedtls.sh` | fetches and builds mbedTLS with the configuration derived from `software/wifi/raw_u64/sdkconfig` and ESP-IDF's `esp_config.h` |
| `esp32_macros.txt` | the derived macro list (one per mbedTLS major); a bump that changes it shows the diff and stops |
| `vectors.c`, `limbo.c` | the harnesses (primitives; X.509 chains, including ESP-IDF's certificate bundle) |
| `conformance.py` | fetches the vectors, runs every suite, prints the summary |
| `expectations` | every outcome that is not the vector's own verdict, with its reason |
| `x509/` | chains made here where x509-limbo has no case (`make_cases.py` makes them; needs `cryptography`) |

## Settings

`CRYPTO_PINS`, `CRYPTO_SDKCONFIG`, `CRYPTO_MACROS` (a candidate release's files),
`CRYPTO_EXPECTATIONS`, `CRYPTO_CONFIG` (an mbedTLS config header instead of the ESP32's),
`CRYPTO_CFLAGS` (e.g. `-fsanitize=address,undefined`), `CRYPTO_CACHE`, `CRYPTO_OFFLINE=1`,
`CRYPTO_STRICT=1` (known vulnerabilities, security deviations and fail-open deviations count as
failures). The two switches take 0 or 1 only. Any other `CRYPTO_` variable is refused, so a
misspelt one cannot be silently ignored.

## What the tls_engine.c check sees

The coverage suite compares `tls_engine.c`'s verification surface with `engine_config.txt` and
fails when it differs or the file is gone: every `#define` naming an `mbedtls_` or `esp_crt_`
symbol, all of `tls_setup()` and `tls_open()` (the argument checks such as "no verify without a
host name", the spike and clock gates, the session configuration with its arguments), all of
`tls_set_clock()` and `tls_build_time()` (the clock floor the clock gate relies on), every other
function that touches the configuration, BIO, verify callback or host name, and the functions
installed as verify callbacks. That keeps `vectors.c`'s ClientHello and `limbo.c`'s two ways to
verify in step with the engine. It is a text comparison: it catches edits, not a determined
evasion, and says nothing about what the engine does at run time. A behavioural test of the
engine (handshakes against it: the interop lane, and M3) is the stronger check.
The run also prints whether the sdkconfig it used sets `CONFIG_TLS_SPIKE` (which builds in
`tls_accept_any`, the verify-nothing callback), so a log shows which engine build it describes.

## What it does not test

The TLS layer itself (the record layer's nonces, the handshake, Finished, CertificateVerify's
content, that the host name and the key-usage checks are applied): only handshakes can show
that. The ESP32's hardware AES/GCM/SHA/bignum code (see the NOT COVERED line). Revocation (the
engine configures no CRL). Name-constraint semantics (mbedTLS 3.6 and 4.1.1 have none; a critical
one is refused at parse time). With mbedTLS 4, the finite-field groups ffdhe2048 to ffdhe8192 the
default configuration offers: no independent vectors, so the coverage suite fails if an engine
offers them (engine4 does not: it sets its groups). The build log (`build_mbedtls.txt`) names
every macro of the derived configuration that the host drops (DROPPED) or replaces (REPLACED).
