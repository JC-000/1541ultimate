#!/usr/bin/env bash
#
# Crypto conformance suite for the ESP32's TLS 1.3 client (software/wifi/raw_u64/main/tls_engine.c).
#
#   tests/crypto/run.sh [outdir]      (default tests/crypto/output)
#
# CRYPTO_PINS, CRYPTO_SDKCONFIG, CRYPTO_MACROS and CRYPTO_CACHE are passed on to build_mbedtls.sh;
# CRYPTO_EXPECTATIONS names a different expectations file (a candidate's), and
# CRYPTO_STRICT=1 counts known vulnerabilities and security deviations as failures.
# CRYPTO_OFFLINE=1 uses the cache alone (fill it with one run that has the network).
# CRYPTO_ENGINE and CRYPTO_ENGINE_CONFIG name the tls_engine.c the coverage suite compares and its
# recorded surface (run_idf6.sh sets them). CRYPTO_CONFIG names an mbedTLS config header to use
# instead of the ESP32's; CRYPTO_CFLAGS
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
# A misspelt setting would be silently ignored: refuse any CRYPTO_ variable not listed here
KNOWN=" CRYPTO_PINS CRYPTO_SDKCONFIG CRYPTO_MACROS CRYPTO_CACHE CRYPTO_CONFIG CRYPTO_CFLAGS CRYPTO_EXPECTATIONS CRYPTO_STRICT CRYPTO_OFFLINE CRYPTO_ENGINE CRYPTO_ENGINE_CONFIG "
for v in $(env | sed -n 's/^\(CRYPTO_[A-Za-z0-9_]*\)=.*/\1/p'); do
    [[ $KNOWN == *" $v "* ]] || { echo "unknown setting $v (known:$KNOWN)"; echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1; }
done
for v in CRYPTO_STRICT CRYPTO_OFFLINE; do
    case ${!v:-0} in 0|1) ;; *) echo "$v=${!v}: use 0 or 1"; echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1;; esac
done
OUT=${1:-$HERE/output}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# The run reads this directory and software/wifi (the 3.6 engine and sdkconfig): a change to
# either is named, so the tree line never stamps a modified run as the commit
echo "tree $(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)$(
    [ -z "$(git -C "$HERE" status --porcelain -- . ../../software/wifi 2>/dev/null)" ] ||
        echo ' (tests/crypto or software/wifi modified)')"
# The build's own output (with every hardware option it replaced) goes to the log; the summary
# keeps the pins, the sdkconfig and the configuration used
"$HERE/build_mbedtls.sh" "$OUT" ${CRYPTO_CONFIG:+"$CRYPTO_CONFIG"} > "$OUT/build_mbedtls.txt" 2>&1 ||
    { tail -20 "$OUT/build_mbedtls.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }
grep -E '^(pins|mbedTLS|sdkconfig|macros|config:)' "$OUT/build_mbedtls.txt"

# What the build says a program using it needs: include paths, config defines, libraries
BUILD_FLAGS=() BUILD_LIBS=()
while IFS= read -r a; do BUILD_FLAGS+=("$a"); done < "$OUT/harness.flags"
while IFS= read -r a; do BUILD_LIBS+=("$a"); done < "$OUT/harness.libs"
CFLAGS=(${CRYPTO_CFLAGS:-} -std=c11 -O1 -Wall -Wextra -D_POSIX_C_SOURCE=200809L "${BUILD_FLAGS[@]}")
cc "${CFLAGS[@]}" "$HERE/vectors.c" "${BUILD_LIBS[@]}" -o "$OUT/vectors"
# esp_crt_bundle.c is ESP-IDF's, as it is: GNU C (asm labels), its warnings not ours to fix
cc "${CFLAGS[@]}" -std=gnu11 -Wno-unused-parameter -I"$HERE/stub" -I"$OUT/esp_crt_bundle/include" \
    "$HERE/limbo.c" "$OUT/esp_crt_bundle/esp_crt_bundle.c" "${BUILD_LIBS[@]}" -o "$OUT/limbo"
cmake --build "$OUT/build" --target test_suite_ssl -j "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
    > "$OUT/test_suite_ssl_build.txt" 2>&1 ||
    { tail -20 "$OUT/test_suite_ssl_build.txt"; echo "CRYPTO_CONFORMANCE FAIL build"; exit 1; }

python3 "$HERE/conformance.py" --out "$OUT" "${@:2}"
