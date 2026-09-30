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
exec "$HERE/run.sh" "${1:-$HERE/output-idf6}" "${@:2}"
