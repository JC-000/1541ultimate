# tests/crypto: crypto conformance of the ESP32's TLS client

A **host** suite, not a hardware test: it builds mbedTLS on the host with the configuration the
ESP32 image uses, and checks it against independent vectors. It is **opt-in**, not part of the
default gate (`run-tests`): run it when mbedTLS, ESP-IDF or `tls_engine.c` changes.

    tests/crypto/run.sh [outdir]

The last lines say what matters:

    NOT COVERED: the device uses ESP-IDF hardware code for AES_ALT ... ; this host run tests mbedTLS software paths
    SECURITY DEVIATIONS 3: ...
    KNOWN VULNERABILITIES 1: CVE-2026-49300 (fixed in mbedTLS 3.6.7)
    CRYPTO_CONFORMANCE PASS <n> passed 0 failed <m> suites known-vulnerable 2 security-deviation 4

## What it needs

- cc, cmake, python3 (standard library only), git with partial-clone support.
- **Network on the first run.** mbedTLS, ESP-IDF, Wycheproof and x509-limbo are fetched from
  GitHub at the commits in `PINS`; RFC 5869/7748/8439/8448 and the NIST CAVP SHA vectors by URL,
  checked against the sha256 in `conformance.py`. All of it is cached in
  `~/.cache/1541u-build/crypto` (`CRYPTO_CACHE`). After one run, `CRYPTO_OFFLINE=1` uses the
  cache alone and fails on anything missing instead of downloading it.
- About 15 s with a warm cache.

## Files

| File | What |
|---|---|
| `PINS` | the one place the sources come from; a crypto bump is a change here |
| `build_mbedtls.sh` | fetches and builds mbedTLS with the configuration derived from `software/wifi/raw_u64/sdkconfig` and ESP-IDF's `esp_config.h` |
| `esp32_macros.txt` | the derived macro list; a bump that changes it shows the diff and stops |
| `vectors.c`, `limbo.c` | the harnesses (primitives; X.509 chains, including ESP-IDF's certificate bundle) |
| `conformance.py` | fetches the vectors, runs every suite, prints the summary |
| `expectations` | every outcome that is not the vector's own verdict, with its reason |
| `x509/` | chains made here where x509-limbo has no case (`make_cases.py` makes them; needs `cryptography`) |

## Settings

`CRYPTO_PINS`, `CRYPTO_SDKCONFIG`, `CRYPTO_MACROS` (a candidate release's files),
`CRYPTO_EXPECTATIONS`, `CRYPTO_CONFIG` (an mbedTLS config header instead of the ESP32's),
`CRYPTO_CFLAGS` (e.g. `-fsanitize=address,undefined`), `CRYPTO_CACHE`, `CRYPTO_OFFLINE=1`,
`CRYPTO_STRICT=1` (known vulnerabilities and security deviations count as failures). Any other
`CRYPTO_` variable is refused, so a misspelt one cannot be silently ignored.

## Moving to a new mbedTLS / ESP-IDF

1. Change `ESP_IDF_TAG`, `ESP_IDF_COMMIT` and `MBEDTLS_COMMIT` in `PINS`; the build checks that
   the tag names the commit and that the commit carries that mbedTLS.
2. Regenerate `software/wifi/raw_u64/sdkconfig` at the new ESP-IDF (`idf.py reconfigure`); the
   build refuses an sdkconfig made for another release.
3. Update `esp32_macros.txt` from the diff the build prints, and explain each line in the commit.
4. Remove the `known-vulnerable` lines the run says no longer show.
5. Run until green. The ESP-IDF the firmware builds with (`docker/Dockerfile`) must move with
   `PINS`; that tie is checked by the vendor lane's `check_pins.sh`, not here.

## What it does not test

The TLS layer itself (the record layer's nonces, the handshake, Finished, CertificateVerify's
content, that the host name and the key-usage checks are applied): only handshakes can show
that. The ESP32's hardware AES/GCM/SHA/bignum code (see the NOT COVERED line). Revocation (the
engine configures no CRL). Name-constraint semantics (mbedTLS 3.6 has none; a critical one is
refused at parse time).
