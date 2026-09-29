#!/usr/bin/env bash
#
# Crypto conformance suite for the ESP32's TLS 1.3 client (software/wifi/raw_u64/main/tls_engine.c).
#
#   tests/crypto/run.sh [outdir]      (default tests/crypto/output)
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

# The build's own output (with every hardware option it replaced) goes to the log; the summary
# keeps the pins and the count
"$HERE/build_mbedtls.sh" "$OUT" > "$OUT/build_mbedtls.txt" 2>&1 ||
    { tail -20 "$OUT/build_mbedtls.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }
grep -E '^(mbedTLS|config:)' "$OUT/build_mbedtls.txt"

LIB=$OUT/build/library
CFLAGS=(-std=c11 -O1 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -I"$OUT/config" -I"$OUT/src/include"
        -DMBEDTLS_CONFIG_FILE='"mbedtls_esp32_host.h"')
cc "${CFLAGS[@]}" "$HERE/vectors.c" "$LIB/libmbedtls.a" "$LIB/libmbedx509.a" "$LIB/libmbedcrypto.a" -o "$OUT/vectors"
cc "${CFLAGS[@]}" "$HERE/limbo.c" "$LIB/libmbedx509.a" "$LIB/libmbedcrypto.a" -o "$OUT/limbo"
cmake --build "$OUT/build" --target test_suite_ssl -j "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
    > "$OUT/test_suite_ssl_build.txt" 2>&1 ||
    { tail -20 "$OUT/test_suite_ssl_build.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }

python3 "$HERE/conformance.py" --out "$OUT" "${@:2}"
