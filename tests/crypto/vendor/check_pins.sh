#!/usr/bin/env bash
# Checks that every place the ESP32's ESP-IDF / mbedTLS version is written down agrees with
# tests/crypto/PINS, and prints the PINS lines for a new ESP-IDF release.
#
#   check_pins.sh [--offline] [--image] [PINS]   check the tree against PINS (default tests/crypto/PINS)
#   check_pins.sh --suggest <idf-tag>            print the PINS lines for that tag
#
# Offline checks: PINS shape, docker/Dockerfile's esp-idf clone tag, the version header of every
# ESP32 project's sdkconfig. Online (GitHub API, read-only): ESP_IDF_COMMIT (if set) is the
# commit of ESP_IDF_TAG, and MBEDTLS_COMMIT is the mbedtls submodule of ESP_IDF_TAG.
# --image also reads the published build image's history
# (ghcr.io/gideonz/riscv:latest) and checks that it cloned ESP_IDF_TAG.
# Last line: CHECK_PINS_OK or CHECK_PINS_FAIL <n>.
set -u

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IDF_REPO=espressif/esp-idf
IMAGE=gideonz/riscv
PROJECTS="software/wifi/raw_u64 software/wifi/raw_c3 software/u64ctrl"

api() { # api <path> : GitHub REST GET, JSON on stdout
    if command -v gh >/dev/null 2>&1; then
        gh api "$1"
    else
        curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} "https://api.github.com/$1"
    fi
}
json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

submodule_of() { # submodule_of <idf-tag> : SHA of components/mbedtls/mbedtls at that tag
    api "repos/$IDF_REPO/contents/components/mbedtls/mbedtls?ref=$1" | json 'd["sha"] if d.get("type")=="submodule" else ""'
}
tag_commit() { # tag_commit <idf-tag> : the commit an ESP-IDF tag points at (annotated or not)
    local o
    o=$(api "repos/$IDF_REPO/git/refs/tags/$1" | json 'd["object"]["type"]+" "+d["object"]["sha"]')
    case $o in
        tag\ *) api "repos/$IDF_REPO/git/tags/${o#tag }" | json 'd["object"]["sha"]' ;;
        *) echo "${o#* }" ;;
    esac
}
mbedtls_version() { # mbedtls_version <commit> : MBEDTLS_VERSION_STRING at that espressif/mbedtls commit
    api "repos/espressif/mbedtls/contents/include/mbedtls/build_info.h?ref=$1" | json 'd["content"]' |
        python3 -c 'import sys,base64,re; m=re.search(r"#define MBEDTLS_VERSION_STRING\s+\"([^\"]+)\"", base64.b64decode(sys.stdin.read()).decode()); print(m.group(1) if m else "?")'
}

if [ "${1:-}" = "--suggest" ]; then
    tag=${2:?usage: check_pins.sh --suggest <idf-tag>}
    sha=$(submodule_of "$tag")
    [ -n "$sha" ] || { echo "no mbedtls submodule at $IDF_REPO $tag"; exit 1; }
    echo "# mbedTLS $(mbedtls_version "$sha") (espressif/mbedtls), the submodule of ESP-IDF $tag"
    echo "ESP_IDF_TAG=$tag"
    echo "ESP_IDF_COMMIT=$(tag_commit "$tag")"
    echo "MBEDTLS_COMMIT=$sha"
    echo "# Also change: docker/Dockerfile (--branch $tag), then regenerate the sdkconfig of: $PROJECTS"
    exit 0
fi

offline=0
image=0
pins=$ROOT/tests/crypto/PINS
for a in "$@"; do
    case $a in
        --offline) offline=1 ;;
        --image) image=1 ;;
        *) pins=$a ;;
    esac
done

fails=0
ok()   { echo "ok   $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

[ -f "$pins" ] || { echo "FAIL no pin file at $pins"; echo "CHECK_PINS_FAIL 1"; exit 1; }
# shellcheck disable=SC1090
. "$pins"
for k in ESP_IDF_TAG MBEDTLS_REPO MBEDTLS_COMMIT; do
    [ -n "${!k:-}" ] || fail "PINS has no $k"
done
for k in ESP_IDF_COMMIT MBEDTLS_COMMIT WYCHEPROOF_COMMIT X509_LIMBO_COMMIT; do
    v=${!k:-}
    if [ -n "$v" ] && ! [[ $v =~ ^[0-9a-f]{40}$ ]]; then
        fail "PINS $k is not a full commit SHA: $v"
    fi
done
tag=${ESP_IDF_TAG:-}
ver=${tag#v}
[[ $ver =~ ^[0-9]+\.[0-9]+$ ]] && ver=$ver.0 # tag v5.4 writes 5.4.0 into sdkconfig

d=$(sed -n 's/.*git clone .*--branch \([^ ]*\) .*esp-idf.*/\1/p' "$ROOT/docker/Dockerfile" 2>/dev/null | head -1)
if [ "$d" = "$tag" ]; then ok "docker/Dockerfile clones esp-idf $d"; else fail "docker/Dockerfile clones esp-idf '${d:-?}', PINS says $tag"; fi

for p in $PROJECTS; do
    h=$(sed -n 's/^# Espressif IoT Development Framework (ESP-IDF) \([^ ]*\) Project Configuration$/\1/p' "$ROOT/$p/sdkconfig" 2>/dev/null)
    if [ "$h" = "$ver" ]; then ok "$p/sdkconfig was written by ESP-IDF $h"; else fail "$p/sdkconfig was written by ESP-IDF '${h:-?}', PINS says $tag"; fi
done

if [ $offline -eq 0 ]; then
    if [ -n "${ESP_IDF_COMMIT:-}" ]; then
        c=$(tag_commit "$tag")
        if [ "$c" = "$ESP_IDF_COMMIT" ]; then ok "ESP_IDF_COMMIT is the commit of ESP-IDF $tag"; else fail "ESP-IDF $tag is commit ${c:-?}, PINS says $ESP_IDF_COMMIT"; fi
    fi
    s=$(submodule_of "$tag")
    if [ "$s" = "${MBEDTLS_COMMIT:-}" ]; then
        ok "MBEDTLS_COMMIT is the mbedtls submodule of ESP-IDF $tag (mbedTLS $(mbedtls_version "$s"))"
    else
        fail "ESP-IDF $tag has mbedtls ${s:-?}, PINS says ${MBEDTLS_COMMIT:-?}"
    fi
fi

if [ $image -eq 1 ]; then
    tok=$(curl -fsSL "https://ghcr.io/token?scope=repository:$IMAGE:pull" | json 'd["token"]')
    acc='application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
    dig=$(curl -fsSI -H "Authorization: Bearer $tok" -H "Accept: $acc" "https://ghcr.io/v2/$IMAGE/manifests/latest" |
          tr -d '\r' | sed -n 's/^docker-content-digest: //Ip')
    cfg=$(curl -fsSL -H "Authorization: Bearer $tok" -H "Accept: $acc" "https://ghcr.io/v2/$IMAGE/manifests/latest" |
          json 'd["config"]["digest"]')
    if curl -fsSL -H "Authorization: Bearer $tok" "https://ghcr.io/v2/$IMAGE/blobs/$cfg" |
       json '"\n".join(h.get("created_by","") for h in d.get("history",[]))' | grep -q -- "--branch $tag "; then
        ok "ghcr.io/$IMAGE:latest ($dig) cloned esp-idf $tag"
    else
        fail "ghcr.io/$IMAGE:latest ($dig) did not clone esp-idf $tag"
    fi
fi

if [ $fails -eq 0 ]; then echo "CHECK_PINS_OK"; else echo "CHECK_PINS_FAIL $fails"; exit 1; fi
