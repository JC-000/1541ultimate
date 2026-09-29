#!/usr/bin/env bash
#
# Crypto conformance suite for the ESP32's TLS 1.3 client (software/wifi/raw_u64/main/tls_engine.c).
#
#   tests/crypto/run.sh [outdir]      (default tests/crypto/output)
#
# CRYPTO_PINS, CRYPTO_SDKCONFIG, CRYPTO_MACROS and CRYPTO_CACHE are passed on to build_mbedtls.sh;
# CRYPTO_EXPECTATIONS names a different expectations file (a candidate's), and
# CRYPTO_KNOWN_VULNERABLE=0 ignores its known-vulnerable lines.
# CRYPTO_CONFIG names an mbedTLS config header to use instead of the ESP32's; CRYPTO_CFLAGS
# builds the library and the harnesses with extra flags, e.g. '-fsanitize=address,undefined'.
#
# Builds mbedTLS as PINS says with the ESP32's configuration (build_mbedtls.sh), builds the two
# harnesses and mbedTLS's own TLS 1.3 key schedule tests against it, fetches the vectors and runs
# every suite (conformance.py). Prints one line per suite and ends with
# "CRYPTO_CONFORMANCE PASS|FAIL <counts>"; the exit status follows it. Moving to a new mbedTLS
# or ESP-IDF release is a change to PINS and nothing else; run this again.
#
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/output}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

echo "tree $(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)$(
    [ -z "$(git -C "$HERE" status --porcelain -- . 2>/dev/null)" ] || echo ' (tests/crypto modified)')"
# The build's own output (with every hardware option it replaced) goes to the log; the summary
# keeps the pins, the sdkconfig and the configuration used
"$HERE/build_mbedtls.sh" "$OUT" ${CRYPTO_CONFIG:+"$CRYPTO_CONFIG"} > "$OUT/build_mbedtls.txt" 2>&1 ||
    { tail -20 "$OUT/build_mbedtls.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }
grep -E '^(pins|mbedTLS|sdkconfig|macros|config:)' "$OUT/build_mbedtls.txt"

LIB=$OUT/build/library
CFLAGS=(${CRYPTO_CFLAGS:-} -std=c11 -O1 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -I"$OUT/config" -I"$OUT/src/include"
        -DMBEDTLS_CONFIG_FILE='"mbedtls_host.h"')
cc "${CFLAGS[@]}" "$HERE/vectors.c" "$LIB/libmbedtls.a" "$LIB/libmbedx509.a" "$LIB/libmbedcrypto.a" -o "$OUT/vectors"
cc "${CFLAGS[@]}" "$HERE/limbo.c" "$LIB/libmbedx509.a" "$LIB/libmbedcrypto.a" -o "$OUT/limbo"
cmake --build "$OUT/build" --target test_suite_ssl -j "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
    > "$OUT/test_suite_ssl_build.txt" 2>&1 ||
    { tail -20 "$OUT/test_suite_ssl_build.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }

python3 "$HERE/conformance.py" --out "$OUT" "${@:2}"
