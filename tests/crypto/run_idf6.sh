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
# The ESP-IDF 6 image the pins describe: esp-tls/idf6 at the commit accepted as ESP32 1.304.
# Its tls_engine.c is engine4's (esp-tls/engine4), not this tree's 3.6 one, until the branches
# meet: the coverage suite compares that one, at this commit, with engine_config.4.txt, and
# vectors.c's ClientHello copies its calls
IMAGE_COMMIT=a846369fb02ec96a14fc58f85345336ef9eb2ec5
OUT=${1:-$HERE/output-idf6}
mkdir -p "$OUT"
# The committed sdkconfigs must be the image's for every option the mbedTLS configuration and the
# certificate bundle read (CONFIG_MBEDTLS_*, and the target), whatever CRYPTO_SDKCONFIG names:
# sdkconfig.v6.0.3 as the image has it, sdkconfig.v6.0.3-nocross the same with only
# CROSS_SIGNED_VERIFY and the trusted-certificate callback it selects turned off
mbedtls_keys() { grep -E '^(# )?CONFIG_(MBEDTLS_[A-Z0-9_]*|IDF_TARGET)( is not set|=)' | grep -Ev "^(# )?CONFIG_(${1:-NONE})( is not set|=)" | sort; }
NOCROSS='MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY|MBEDTLS_X509_TRUSTED_CERT_CALLBACK'
git -C "$HERE" show "$IMAGE_COMMIT:software/wifi/raw_u64/sdkconfig" > "$OUT/sdkconfig.image" ||
    { echo "the image's sdkconfig at $IMAGE_COMMIT is not in this repository"; echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1; }
if ! diff -u --label "image $IMAGE_COMMIT" --label sdkconfig.v6.0.3 <(mbedtls_keys < "$OUT/sdkconfig.image") <(mbedtls_keys < "$HERE/sdkconfig.v6.0.3") > "$OUT/sdkconfig.drift" ||
   ! diff -u --label sdkconfig.v6.0.3 --label sdkconfig.v6.0.3-nocross <(mbedtls_keys "$NOCROSS" < "$HERE/sdkconfig.v6.0.3") <(mbedtls_keys "$NOCROSS" < "$HERE/sdkconfig.v6.0.3-nocross") >> "$OUT/sdkconfig.drift" ||
   grep -Eq "^CONFIG_($NOCROSS)=" "$HERE/sdkconfig.v6.0.3-nocross"; then
    cat "$OUT/sdkconfig.drift"
    echo "sdkconfig.v6.0.3 or its -nocross twin is not the image's ($IMAGE_COMMIT) for the mbedTLS options:"
    echo "regenerate them from it with regen_sdkconfig.sh"
    echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1
fi
echo "sdkconfig.v6.0.3: the mbedTLS options of the image at $IMAGE_COMMIT"
if [ -z "${CRYPTO_ENGINE:-}" ]; then
    git -C "$HERE" show "$IMAGE_COMMIT:software/wifi/raw_u64/main/tls_engine.c" > "$OUT/tls_engine.4.c" ||
        { echo "the image's tls_engine.c at $IMAGE_COMMIT is not in this repository"; echo "CRYPTO_CONFORMANCE FAIL setup"; exit 1; }
    export CRYPTO_ENGINE=$OUT/tls_engine.4.c
fi
export CRYPTO_ENGINE_CONFIG=${CRYPTO_ENGINE_CONFIG:-$HERE/engine_config.4.txt}
echo "engine: $CRYPTO_ENGINE (image $IMAGE_COMMIT) against $CRYPTO_ENGINE_CONFIG"
exec "$HERE/run.sh" "$OUT" "${@:2}"
