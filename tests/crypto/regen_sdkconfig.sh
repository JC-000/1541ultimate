#!/usr/bin/env bash
# Regenerates an ESP-IDF project sdkconfig for another ESP-IDF release on the host, the way
# idf.py does (tools/cmake/kconfig.cmake __kconfig_generate_config), without CMake or a
# toolchain: kconfgen from esp-idf-kconfig, every component's Kconfig and sdkconfig.rename at
# the given commit, and the project's own main/Kconfig.projbuild.
#
#   regen_sdkconfig.sh <idf commit> <idf version, e.g. 5.3.6> <project dir> <sdkconfig in> <sdkconfig out>
#
# KCONFGEN names the python that has esp_idf_kconfig installed: the release's constraints file
# (https://dl.espressif.com/dl/esp-idf/espidf.constraints.v<major.minor>.txt) gives the range, and
# the version used is printed last. ESP-IDF 5.3 takes esp-idf-kconfig 2.x, 6.0 takes 3.x.
# Components that live outside the ESP-IDF tree (managed components, submodules such as
# esp-mqtt) are not read: their options keep the values the input sdkconfig gives them.
set -euo pipefail
COMMIT=$1 VERSION=$2 PROJECT=$(cd "$3" && pwd) IN=$4 OUT=$5
PY=${KCONFGEN:?set KCONFGEN to a python with esp-idf-kconfig}
CACHE=${CRYPTO_CACHE:-$HOME/.cache/1541u-build/crypto}
IDF=$CACHE/esp-idf-kconfig-$COMMIT
if [ ! -d "$IDF/.git" ]; then
    rm -rf "$IDF.tmp"
    git init -q "$IDF.tmp"
    git -C "$IDF.tmp" fetch -q --depth 1 --filter=blob:none https://github.com/espressif/esp-idf "$COMMIT"
    git -C "$IDF.tmp" sparse-checkout set --no-cone '/Kconfig' '/sdkconfig.rename' 'Kconfig*' 'sdkconfig.rename*' \
        '/components/*/CMakeLists.txt'
    git -C "$IDF.tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD
    mv "$IDF.tmp" "$IDF"
fi
[ "$(git -C "$IDF" rev-parse HEAD)" = "$COMMIT" ] || { echo "$IDF is not at $COMMIT" >&2; exit 1; }
TARGET=$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"$/\1/p' "$IN")
INIT=$(sed -n 's/^CONFIG_IDF_INIT_VERSION="\(.*\)"$/\1/p' "$IN")
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# The build's components: every directory under components/ with a CMakeLists.txt, and main
kconfigs=() projbuilds=() renames=()
for c in "$IDF"/components/*/; do
    c=${c%/}
    [ -f "$c/CMakeLists.txt" ] || continue
    [ -f "$c/Kconfig" ] && kconfigs+=("$c/Kconfig")
    [ -f "$c/Kconfig.projbuild" ] && projbuilds+=("$c/Kconfig.projbuild")
    [ -f "$c/sdkconfig.rename" ] && renames+=("$c/sdkconfig.rename")
    [ -f "$c/sdkconfig.rename.$TARGET" ] && renames+=("$c/sdkconfig.rename.$TARGET")
done
[ -f "$PROJECT/main/Kconfig.projbuild" ] && projbuilds+=("$PROJECT/main/Kconfig.projbuild")
join() { local IFS=';'; echo "$*"; }
cat > "$W/config.env" <<EOF
{
    "COMPONENT_KCONFIGS": "$(join "${kconfigs[@]}")",
    "COMPONENT_KCONFIGS_PROJBUILD": "$(join "${projbuilds[@]}")",
    "COMPONENT_SDKCONFIG_RENAMES": "$(join "${renames[@]}")",
    "IDF_TARGET": "$TARGET",
    "IDF_TOOLCHAIN": "gcc",
    "IDF_VERSION": "$VERSION",
    "IDF_ENV_FPGA": "",
    "IDF_PATH": "$IDF",
    "COMPONENT_KCONFIGS_SOURCE_FILE": "$W/kconfigs.in",
    "COMPONENT_KCONFIGS_PROJBUILD_SOURCE_FILE": "$W/kconfigs_projbuild.in",
    "KCONFIG_PROMPTLESS_NO_WARN": "IDF_TARGET"
}
EOF
"$PY" "$IDF/tools/kconfig_new/prepare_kconfig_files.py" --list-separator=semicolon --env-file "$W/config.env" 2>/dev/null ||
    { git -C "$IDF" sparse-checkout add /tools/kconfig_new/ && \
      "$PY" "$IDF/tools/kconfig_new/prepare_kconfig_files.py" --list-separator=semicolon --env-file "$W/config.env"; }
cp "$IN" "$W/sdkconfig"
IDF_INIT_VERSION=${INIT:-$VERSION} "$PY" -m kconfgen --list-separator=semicolon --kconfig "$IDF/Kconfig" \
    --sdkconfig-rename "$IDF/sdkconfig.rename" --config "$W/sdkconfig" --env "IDF_MINIMAL_BUILD=n" --env-file "$W/config.env" \
    --env "IDF_TARGET=$TARGET" --env "IDF_TOOLCHAIN=gcc" --env "IDF_ENV_FPGA=" --env "IDF_INIT_VERSION=${INIT:-$VERSION}" \
    --output config "$OUT"
echo "regenerated $OUT for ESP-IDF $VERSION ($COMMIT), target $TARGET, $(shasum -a 256 < "$OUT" | cut -d' ' -f1)"
echo "kconfgen: $("$PY" -c 'import importlib.metadata as m; print("esp-idf-kconfig", m.version("esp-idf-kconfig"))')"
