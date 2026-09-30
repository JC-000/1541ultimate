#!/usr/bin/env bash
#
# The crypto conformance suite with the ESP-IDF 6 / mbedTLS 4 pins: run.sh with PINS.idf6, the
# sdkconfig regenerated for ESP-IDF v6.0.3 (sdkconfig.v6.0.3) and the expectations checked
# against mbedTLS 4.1.1 (expectations.4). Any of the three can still be set, e.g.
# CRYPTO_SDKCONFIG=sdkconfig.v6.0.3-nocross CRYPTO_MACROS=esp32_macros.4-nocross.txt for the
# certificate bundle without CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY.
#
#   tests/crypto/run_idf6.sh [outdir]      (default tests/crypto/output-idf6)
#
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export CRYPTO_PINS=${CRYPTO_PINS:-$HERE/PINS.idf6}
export CRYPTO_SDKCONFIG=${CRYPTO_SDKCONFIG:-$HERE/sdkconfig.v6.0.3}
export CRYPTO_EXPECTATIONS=${CRYPTO_EXPECTATIONS:-$HERE/expectations.4}
# The engine an ESP-IDF 6 image builds is engine4's (esp-tls/engine4), not this tree's 3.6 one,
# until the branches meet: the coverage suite compares that one, at this commit, with
# engine_config.4.txt, and vectors.c's ClientHello copies its calls
ENGINE4_COMMIT=f0ae8ed2fd113a53ee1e02caf809282ab585fcb5
OUT=${1:-$HERE/output-idf6}
mkdir -p "$OUT"
if [ -z "${CRYPTO_ENGINE:-}" ]; then
    git -C "$HERE" show "$ENGINE4_COMMIT:software/wifi/raw_u64/main/tls_engine.c" > "$OUT/tls_engine.4.c" ||
        { echo "engine4's tls_engine.c at $ENGINE4_COMMIT is not in this repository"; echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1; }
    export CRYPTO_ENGINE=$OUT/tls_engine.4.c
fi
export CRYPTO_ENGINE_CONFIG=${CRYPTO_ENGINE_CONFIG:-$HERE/engine_config.4.txt}
echo "engine: $CRYPTO_ENGINE (engine4 $ENGINE4_COMMIT) against $CRYPTO_ENGINE_CONFIG"
exec "$HERE/run.sh" "$OUT" "${@:2}"
