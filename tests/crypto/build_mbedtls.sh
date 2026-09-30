#!/usr/bin/env bash
#
# Builds mbedTLS for the host, by default with the configuration the ESP32 image uses.
#
#   build_mbedtls.sh <outdir> [<mbedtls config header>]
#
# Takes everything from PINS: mbedTLS at MBEDTLS_COMMIT, and ESP-IDF at ESP_IDF_COMMIT, which
# ESP_IDF_TAG must name and which must carry MBEDTLS_COMMIT as its mbedtls submodule.
#
# Without a config header the configuration is derived, not maintained: the sdkconfig becomes
# sdkconfig.h the way ESP-IDF writes it, ESP-IDF's own esp_config.h is run through the
# preprocessor with it, and every MBEDTLS_ macro that comes out is the configuration. Hardware
# acceleration (the _ALT options) and the ESP-IDF platform hooks are then replaced with
# mbedTLS's software implementations, and each replacement is printed. The sdkconfig must have
# been generated for ESP_IDF_TAG: one from another release lacks that release's new options, and
# esp_config.h would quietly drop what they enable, so the build stops and names them.
# With a config header (a configuration for another CPU, say) that header is used as it is.
# Nothing in the fetched sources is changed.
#
# Leaves in <outdir>: config/mbedtls_host.h (includes the configuration used; the derived one is
# config/mbedtls_esp32_host.h), build/ (a CMake build tree whose library/ holds libmbedx509.a,
# libmbedtls.a and the crypto library: libmbedcrypto.a in 3.x, libtfpsacrypto.a in 4.x), src ->
# the sources, and harness.flags / harness.libs (one compiler argument per line: what a program
# using the build needs). The last line printed is "MBEDTLS_BUILD_OK <outdir> <commit>".
#
# The derived list of MBEDTLS_ macros, before any replacement, must equal esp32_macros.txt (3.x)
# or esp32_macros.<major>.txt: each major has its own baseline.
#
# mbedTLS 4 (ESP-IDF 6) splits the configuration: TF-PSA-Crypto's psa/crypto_config.h holds the
# crypto defaults, and ESP-IDF names esp_config.h both as MBEDTLS_CONFIG_FILE and as
# TF_PSA_CRYPTO_USER_CONFIG_FILE (components/mbedtls/CMakeLists.txt), so every translation unit
# reads crypto_config.h, then esp_config.h. The derived list is what that leaves defined: the
# MBEDTLS_, PSA_WANT_ and TF_PSA_CRYPTO_ macros. Espressif's mbedTLS 4 tree does not build on its
# own: it leaves out the test framework submodule (TF-PSA-Crypto carries the same one) and the
# generated test headers, and includes "mbedtls/bignum.h" and "mbedtls/ecp.h", which ESP-IDF's
# port/include provides. src is then a directory of links to the fetched tree plus a copy of
# tf-psa-crypto/framework at framework/ (where upstream has it), the two headers come from
# ESP-IDF at ESP_IDF_COMMIT, and the test headers are generated with the framework's own scripts
# (they need Jinja2, as mbedTLS's scripts/driver.requirements.txt says).
#
# CRYPTO_PINS names a different pin file, CRYPTO_SDKCONFIG a different sdkconfig (a candidate
# release's, regenerated with its kconfgen), CRYPTO_MACROS a different macro list to match,
# CRYPTO_CACHE a different cache directory, CRYPTO_CFLAGS extra compiler flags (a sanitizer);
# CRYPTO_OFFLINE=1 builds from the cache alone.
#
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SDKCONFIG=${CRYPTO_SDKCONFIG:-$REPO/software/wifi/raw_u64/sdkconfig}
PINS=${CRYPTO_PINS:-$HERE/PINS}
CACHE=${CRYPTO_CACHE:-$HOME/.cache/1541u-build/crypto}

[ $# -eq 1 ] || [ $# -eq 2 ] || { echo "usage: $0 <outdir> [<mbedtls config header>]" >&2; exit 2; }
GIVEN=
if [ $# -eq 2 ]; then
    [ -f "$2" ] || { echo "$2: no such config header" >&2; exit 2; }
    GIVEN=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
fi
# shellcheck source=PINS
. "$PINS"
for key in MBEDTLS_COMMIT ESP_IDF_COMMIT; do
    [[ ${!key} =~ ^[0-9a-f]{40}$ ]] || { echo "PINS: $key is not a full SHA: ${!key}" >&2; exit 1; }
done
mkdir -p "$1" "$CACHE"
OUT=$(cd "$1" && pwd)
echo "pins $PINS sha256 $(shasum -a 256 < "$PINS" | cut -d' ' -f1)"

# CRYPTO_OFFLINE=1: build from the cache only; anything not cached yet is an error, not a download
offline_check() {
    if [ "${CRYPTO_OFFLINE:-0}" = 1 ]; then
        echo "offline, and $1 is not in the cache: run once with the network" >&2
        exit 1
    fi
}
case ${CRYPTO_OFFLINE:-0} in 0|1) ;; *) echo "CRYPTO_OFFLINE=$CRYPTO_OFFLINE: use 0 or 1" >&2; exit 2;; esac
[ "${CRYPTO_OFFLINE:-0}" = 1 ] && export GIT_NO_LAZY_FETCH=1

# fetch <repo> <commit> <dir>: a clean checkout of exactly <commit> and its submodules, fetched
# once and cached. A checkout that is not at <commit> or has local changes is refused, never used.
fetch() {
    local repo=$1 commit=$2 dir=$3
    if [ ! -d "$dir/.git" ]; then
        offline_check "$dir"
        rm -rf "$dir.tmp"
        git init -q "$dir.tmp"
        git -C "$dir.tmp" fetch -q --depth 1 "$repo" "$commit"
        git -C "$dir.tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD
        # Later 3.6.x releases keep their test framework in a submodule, pinned by the commit
        git -C "$dir.tmp" submodule -q update --init --depth 1
        mv "$dir.tmp" "$dir"
    fi
    local head
    head=$(git -C "$dir" rev-parse HEAD)
    [ "$head" = "$commit" ] || { echo "$dir is at $head, not $commit" >&2; exit 1; }
    [ -z "$(git -C "$dir" status --porcelain)" ] || { echo "$dir has local changes" >&2; exit 1; }
}

# idf_tree <dir> <ref>...: ESP-IDF's trees at these refs, without their blobs; only the files
# read below are downloaded.
idf_tree() {
    local dir=$1
    shift
    if [ ! -d "$dir/.git" ]; then
        offline_check "$dir"
        rm -rf "$dir.tmp"
        git init -q "$dir.tmp"
        git -C "$dir.tmp" fetch -q --depth 1 --filter=blob:none https://github.com/espressif/esp-idf "$@"
        mv "$dir.tmp" "$dir"
    fi
}
IDF=$CACHE/esp-idf-$ESP_IDF_COMMIT
idf_tree "$IDF" "$ESP_IDF_COMMIT" "refs/tags/$ESP_IDF_TAG:refs/tags/$ESP_IDF_TAG"
IDF_COMMIT=$(git -C "$IDF" rev-parse "refs/tags/$ESP_IDF_TAG^{commit}")
if [ "$IDF_COMMIT" != "$ESP_IDF_COMMIT" ]; then
    echo "PINS: ESP-IDF $ESP_IDF_TAG is $IDF_COMMIT, but ESP_IDF_COMMIT is $ESP_IDF_COMMIT" >&2
    exit 1
fi
idf_file() { git -C "$IDF" cat-file -p "$ESP_IDF_COMMIT:$1"; }
SUBMODULE=$(git -C "$IDF" rev-parse "$IDF_COMMIT:components/mbedtls/mbedtls")
if [ "$SUBMODULE" != "$MBEDTLS_COMMIT" ]; then
    echo "PINS: ESP-IDF $ESP_IDF_TAG carries mbedtls $SUBMODULE, but MBEDTLS_COMMIT is $MBEDTLS_COMMIT" >&2
    exit 1
fi

SRC=$CACHE/mbedtls-$MBEDTLS_COMMIT
fetch "$MBEDTLS_REPO" "$MBEDTLS_COMMIT" "$SRC"
MAJOR=$(sed -n 's/^#define MBEDTLS_VERSION_MAJOR *\([0-9]*\)$/\1/p' "$SRC/include/mbedtls/build_info.h")
case $MAJOR in
    3) MACROS=${CRYPTO_MACROS:-$HERE/esp32_macros.txt};;
    4) MACROS=${CRYPTO_MACROS:-$HERE/esp32_macros.4.txt};;
    *) echo "mbedTLS major version '$MAJOR' is not supported" >&2; exit 1;;
esac
rm -rf "$OUT/src"
if [ "$MAJOR" = 3 ]; then
    ln -s "$SRC" "$OUT/src"
else
    # The tree as upstream lays it out: framework/ at the top (the same tree as TF-PSA-Crypto's,
    # which upstream pins to the same framework commit), everything else linked, nothing changed.
    # A copy, not a link: the framework's scripts find the project from where they are.
    mkdir "$OUT/src"
    for e in "$SRC"/* "$SRC"/.[!.]*; do
        ln -s "$e" "$OUT/src/"
    done
    cp -R "$SRC/tf-psa-crypto/framework" "$OUT/src/framework"
fi

# derive_esp32_config: writes $CFG/mbedtls_esp32_host.h from the sdkconfig, and sets HDR.
derive_esp32_config() {
    # The sdkconfig must come from ESP_IDF_TAG's kconfgen. An older one lacks the options that
    # release added (they would read as "not set"), so name those and stop. An option missing from
    # a matching sdkconfig is one whose dependencies are not met, which kconfgen leaves out.
    MADE_FOR=v$(sed -n 's/^# Espressif IoT Development Framework (ESP-IDF) \(.*\) Project Configuration$/\1/p' "$SDKCONFIG")
    echo "sdkconfig $SDKCONFIG ($MADE_FOR) sha256 $(shasum -a 256 < "$SDKCONFIG" | cut -d' ' -f1)"
    if [ "$MADE_FOR" != "$ESP_IDF_TAG" ]; then
        kconfig_symbols() { sed -n 's/^[[:space:]]*\(menu\)\{0,1\}config \(MBEDTLS_[A-Z0-9_]*\).*/\2/p' | sort -u; }
        idf_tree "$CACHE/esp-idf-$MADE_FOR" "refs/tags/$MADE_FOR:refs/tags/$MADE_FOR"
        git -C "$CACHE/esp-idf-$MADE_FOR" cat-file -p "refs/tags/$MADE_FOR^{commit}:components/mbedtls/Kconfig" |
            kconfig_symbols > "$CFG/kconfig_made_for.txt"
        idf_file components/mbedtls/Kconfig | kconfig_symbols > "$CFG/kconfig_target.txt"
        missing=$(comm -23 "$CFG/kconfig_target.txt" "$CFG/kconfig_made_for.txt" | while read -r sym; do
            grep -Eq "^(# )?CONFIG_$sym( is not set|=)" "$SDKCONFIG" || echo "CONFIG_$sym"
        done)
        echo "the sdkconfig was generated for ESP-IDF $MADE_FOR, not $ESP_IDF_TAG" >&2
        [ -z "$missing" ] || echo "options new in $ESP_IDF_TAG that it does not set:" $missing >&2
        echo "regenerate it with $ESP_IDF_TAG's kconfgen and pass it as CRYPTO_SDKCONFIG" >&2
        exit 1
    fi

    # sdkconfig.h as ESP-IDF's kconfgen writes it: "y" is 1, "not set" is absent, the rest as is.
    awk -F= '/^CONFIG_[A-Za-z0-9_]+=/ { v = substr($0, length($1) + 2); if (v == "y") v = 1;
             print "#define " $1 " " v }' "$SDKCONFIG" > "$CFG/sdkconfig.h"
    TARGET=$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"$/\1/p' "$SDKCONFIG")
    idf_file "components/soc/$TARGET/include/soc/soc_caps.h" > "$CFG/soc/soc_caps.h"
    idf_file components/mbedtls/port/include/mbedtls/esp_config.h > "$CFG/mbedtls/esp_config.h"
    # esp_config.h includes esp_mem.h for the declarations of the allocator it names; only its
    # macros are wanted here, and that allocator is replaced below.
    : > "$CFG/esp_mem.h"

    if [ "$MAJOR" = 3 ]; then
        # Every MBEDTLS_ macro esp_config.h defines for this sdkconfig, include guards aside.
        cc -E -dM -I "$CFG" -I "$SRC/include" "$CFG/mbedtls/esp_config.h" |
            awk '$1 == "#define" && $2 ~ /^MBEDTLS_/ && $2 !~ /_H$/' | sort > "$CFG/esp_macros.txt"
    else
        # crypto_config.h, then esp_config.h, as tf-psa-crypto/build_info.h reads them; ESP-IDF
        # defines MBEDTLS_MAJOR_VERSION=4 for every mbedTLS target, which esp_config.h tests
        printf '#include "psa/crypto_config.h"\n#include "mbedtls/esp_config.h"\n' > "$CFG/raw_config.c"
        cc -E -dM -DMBEDTLS_MAJOR_VERSION="$MAJOR" -I "$CFG" -I "$SRC/tf-psa-crypto/include" -I "$SRC/include" \
            "$CFG/raw_config.c" |
            awk '$1 == "#define" && $2 ~ /^(MBEDTLS_|PSA_WANT_|TF_PSA_CRYPTO_)/ && $2 != "MBEDTLS_MAJOR_VERSION" &&
                 $2 !~ /_H$/' | sort > "$CFG/esp_macros.txt"
    fi
    # The whole list must match the committed one, so an option that appears or disappears (a
    # new Kconfig default, a renamed macro) is seen and explained in the commit that updates it
    if ! diff -u "$MACROS" "$CFG/esp_macros.txt" > "$CFG/esp_macros.diff"; then
        cat "$CFG/esp_macros.diff" >&2
        echo "the derived macro list differs from $MACROS: review the diff above and update that file" >&2
        exit 1
    fi
    echo "macros: $(wc -l < "$CFG/esp_macros.txt" | tr -d ' ') match $MACROS"

    # What stays on the device and what the host replaces. An _ALT option names a platform
    # implementation (ESP32 AES/SHA/MPI hardware, ROM MD5, the hardware RNG); its _FALLBACK
    # companions only exist with it. The allocator is ESP-IDF's heap_caps one. Without the hardware
    # RNG the host takes its entropy from the OS. AES-NI and VIA Padlock are x86 host instructions
    # the ESP32 does not have: the host runs the same portable C code the fallback paths use. In
    # 4.x the ESP32's hardware is reached through PSA drivers (MBEDTLS_PSA_ACCEL_), and its RNG as
    # the PSA entropy driver; the host takes crypto_config.h's built-in code and OS entropy.
    replace() {
        case $1 in
            *_ALT|*_ALT_FALLBACK|*_ALT_SOFT_FALLBACK|MBEDTLS_GCM_NON_AES_CIPHER_SOFT_FALLBACK)
                echo "ESP32 platform implementation -> mbedTLS software implementation";;
            MBEDTLS_PSA_ACCEL_*)
                echo "ESP32 PSA driver -> mbedTLS built-in implementation";;
            MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG|MBEDTLS_PSA_DRIVER_GET_ENTROPY)
                echo "ESP32 hardware RNG (PSA entropy driver) -> host OS entropy source (MBEDTLS_PSA_BUILTIN_GET_ENTROPY)";;
            MBEDTLS_PLATFORM_STD_CALLOC|MBEDTLS_PLATFORM_STD_FREE)
                echo "ESP-IDF allocator ($2) -> libc calloc/free";;
            MBEDTLS_NO_PLATFORM_ENTROPY)
                echo "ESP32 hardware RNG only -> host OS entropy source";;
            MBEDTLS_AESNI_C|MBEDTLS_PADLOCK_C)
                echo "host CPU AES instructions -> mbedTLS software AES";;
            *) return 1;;
        esac
    }

    HDR=$CFG/mbedtls_esp32_host.h
    {
        echo "/* Generated by tests/crypto/build_mbedtls.sh from $SDKCONFIG and"
        echo " * ESP-IDF $ESP_IDF_TAG ($ESP_IDF_COMMIT) components/mbedtls/port/include/mbedtls/esp_config.h."
        echo " * Do not edit: re-run the script. Values may name sdkconfig options, hence the include. */"
        echo "#include \"sdkconfig.h\""
    } > "$HDR"
    echo "target $TARGET, esp_config.h sha256 $(shasum -a 256 < "$CFG/mbedtls/esp_config.h" | cut -d' ' -f1)"
    kept=0
    replaced=0
    entropy=0
    : > "$CFG/replaced.txt"
    while read -r _ name value; do
        if why=$(replace "$name" "$value"); then
            echo "REPLACED $name${value:+ $value}: $why"
            replaced=$((replaced + 1))
            # the device's own implementations, which no host run tests
            case $name in
                *_ALT|*_ALT_FALLBACK|*_ALT_SOFT_FALLBACK|MBEDTLS_PSA_ACCEL_*) echo "${name#MBEDTLS_}" >> "$CFG/replaced.txt";;
                MBEDTLS_PSA_DRIVER_GET_ENTROPY) entropy=1; echo "${name#MBEDTLS_}" >> "$CFG/replaced.txt";;
            esac
        else
            echo "#define $name${value:+ $value}" >> "$HDR"
            kept=$((kept + 1))
        fi
    done < "$CFG/esp_macros.txt"
    if [ "$entropy" = 1 ]; then
        # crypto_config.h's default, which esp_config.h undefines for its entropy driver
        echo "#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY" >> "$HDR"
    fi
    echo "config: $kept options kept, $replaced replaced -> $HDR"
    # Nothing ESP-IDF may be left for the host build to trip over
    if grep -Eq '^#define .*(esp_|ESP_)' "$HDR"; then
        grep -E '^#define .*(esp_|ESP_)' "$HDR" >&2
        echo "an ESP-IDF name is left in the derived configuration" >&2
        exit 1
    fi
}

CFG=$OUT/config
rm -rf "$CFG"
mkdir -p "$CFG/soc" "$CFG/mbedtls"
echo "mbedTLS $MBEDTLS_COMMIT, ESP-IDF $ESP_IDF_TAG ($ESP_IDF_COMMIT)"
if [ -n "$GIVEN" ]; then
    echo "config: $GIVEN (given, used as it is) sha256 $(shasum -a 256 < "$GIVEN" | cut -d' ' -f1)"
    HDR=$GIVEN
else
    derive_esp32_config
fi
if [ "$MAJOR" = 3 ]; then
    echo "#include \"$HDR\"" > "$CFG/mbedtls_host.h"
else
    # Read twice in 4.x: as TF-PSA-Crypto's configuration and as mbedTLS's
    printf '#ifndef MBEDTLS_HOST_H\n#define MBEDTLS_HOST_H\n#include "%s"\n#endif\n' "$HDR" > "$CFG/mbedtls_host.h"
    # What ESP-IDF's port/include adds to Espressif's tree (see the top)
    mkdir -p "$CFG/port/mbedtls"
    for h in bignum.h ecp.h; do
        idf_file "components/mbedtls/port/include/mbedtls/$h" > "$CFG/port/mbedtls/$h"
    done
fi

# The engine's other way to verify: ESP-IDF's certificate bundle, with the certificates the
# image's bundle is made from (CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL) and the bundle
# generator's own test fixture
B=$OUT/esp_crt_bundle
rm -rf "$B"
mkdir -p "$B/include"
for f in esp_crt_bundle.c include/esp_crt_bundle.h cacrt_all.pem cacrt_local.pem \
         test_gen_crt_bundle/baltimore.der test_gen_crt_bundle/baltimore_crt_bundle; do
    idf_file "components/mbedtls/esp_crt_bundle/$f" > "$B/$(echo "$f" | sed 's|^test_gen_crt_bundle/||')"
done

BUILD=$OUT/build
# Later 3.6.x releases link framework/data_files into the build tree without creating its parent
mkdir -p "$BUILD/framework" "$BUILD/tf-psa-crypto/framework"
{
    echo "-I$CFG"
    echo "-I$OUT/src/include"
    echo "-DMBEDTLS_CONFIG_FILE=\"mbedtls_host.h\""
} > "$OUT/harness.flags"
if [ "$MAJOR" = 3 ]; then
    cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DMBEDTLS_CONFIG_FILE="$CFG/mbedtls_host.h" \
          -DCMAKE_C_FLAGS="${CRYPTO_CFLAGS:-}" \
          -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=ON -DGEN_FILES=OFF \
          -DMBEDTLS_FATAL_WARNINGS=OFF -Wno-dev > "$OUT/cmake.log" 2>&1 ||
        { cat "$OUT/cmake.log" >&2; exit 1; }
    LIBS="mbedtls mbedx509 mbedcrypto"
else
    python3 -c 'import jinja2' 2> /dev/null ||
        { echo "mbedTLS $MAJOR's test headers need python3 with Jinja2 (scripts/driver.requirements.txt)" >&2; exit 1; }
    cmake -S "$OUT/src" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DMBEDTLS_FRAMEWORK_DIR="$OUT/src/framework" \
          -DMBEDTLS_CONFIG_FILE="$CFG/mbedtls_host.h" -DTF_PSA_CRYPTO_CONFIG_FILE="$CFG/mbedtls_host.h" \
          -DCMAKE_C_FLAGS="${CRYPTO_CFLAGS:-} -iquote $CFG/port -iquote $CFG" \
          -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=ON -DGEN_FILES=OFF \
          -DMBEDTLS_FATAL_WARNINGS=OFF -Wno-dev > "$OUT/cmake.log" 2>&1 ||
        { cat "$OUT/cmake.log" >&2; exit 1; }
    # The generated files a release archive carries and Espressif's tree does not, made by the
    # framework's own scripts (tests/CMakeLists.txt runs the same ones with GEN_FILES=ON)
    mkdir -p "$BUILD/tests/include/test" "$BUILD/tests/suites"
    (cd "$OUT/src" &&
        python3 framework/scripts/generate_test_keys.py --output "$BUILD/tests/include/test/test_keys.h" &&
        python3 framework/scripts/generate_test_cert_macros.py --output "$BUILD/tests/include/test/test_certs.h" &&
        python3 framework/scripts/generate_config_tests.py --directory "$BUILD/tests/suites") > "$OUT/gen.log" 2>&1 ||
        { cat "$OUT/gen.log" >&2; exit 1; }
    {
        echo "-I$OUT/src/tf-psa-crypto/include"
        echo "-I$OUT/src/tf-psa-crypto/drivers/builtin/include"
        echo "-iquote"
        echo "$CFG/port"
        echo "-DTF_PSA_CRYPTO_CONFIG_FILE=\"mbedtls_host.h\""
    } >> "$OUT/harness.flags"
    LIBS="mbedtls mbedx509 tfpsacrypto"
fi
# shellcheck disable=SC2086
cmake --build "$BUILD" $(for lib in $LIBS; do echo --target "$lib"; done) -j "$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
    > "$OUT/build.log" 2>&1 || { tail -40 "$OUT/build.log" >&2; exit 1; }
: > "$OUT/harness.libs"
for lib in $LIBS; do
    [ -f "$BUILD/library/lib$lib.a" ] || { echo "lib$lib.a was not built" >&2; exit 1; }
    echo "$BUILD/library/lib$lib.a" >> "$OUT/harness.libs"
done
echo "mbedTLS major $MAJOR"
echo "MBEDTLS_BUILD_OK $OUT $MBEDTLS_COMMIT"
