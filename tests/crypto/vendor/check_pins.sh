#!/usr/bin/env bash
# Checks that every place the ESP32's ESP-IDF / mbedTLS version is written down agrees with
# tests/crypto/PINS, and prints the PINS lines for a new ESP-IDF release.
#
#   check_pins.sh [--offline] [--image] [PINS]   check the tree against PINS
#   check_pins.sh --pins-only [PINS]             check only that PINS is self-consistent (online)
#   check_pins.sh --suggest <idf-tag>            print the PINS lines for that tag
#
# The pin file is the argument, else $CRYPTO_PINS, else tests/crypto/PINS; the one used is printed.
# The file is parsed, never sourced: every line is blank, a comment, or KEY=VALUE with an optional
# trailing "# comment"; anything else (export, quotes, $, spaces in a value, a repeated key) fails.
# A C1 key already set in the environment also fails. ESP_IDF_TAG, ESP_IDF_COMMIT, MBEDTLS_REPO and
# MBEDTLS_COMMIT are required (C1 + amendment 2), and a key C1 does not name is a failure.
# Tree checks (skipped by --pins-only): the version header of every ESP32 project's sdkconfig, and
# docker/Dockerfile, whose live (uncommented) lines must hold exactly one esp-idf clone, from
# https://github.com/espressif/esp-idf at --branch ESP_IDF_TAG, and no command that could move or
# patch a tree after a clone (git checkout/switch/reset/am/apply/fetch/pull/-C, patch). What a
# script the Dockerfile runs does is not seen.
# Online (GitHub API, read-only; skipped by --offline): ESP_IDF_TAG resolves to ESP_IDF_COMMIT; at
# ESP_IDF_COMMIT the mbedtls submodule is MBEDTLS_COMMIT and its URL is MBEDTLS_REPO.
# --image also reads the published build image's history (ghcr.io/gideonz/riscv:latest) and
# checks that it cloned ESP_IDF_TAG. That is the registry, not the local image a build used, and it
# fails for a candidate release until upstream publishes an image for it: it is advisory.
# Last line: CHECK_PINS_OK (every check ran and passed), CHECK_PINS_PARTIAL offline|pins-only (the
# checks that ran passed, some were skipped: not a full pass) or CHECK_PINS_FAIL <n>.
set -u

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
IDF_REPO=espressif/esp-idf
IMAGE=gideonz/riscv
PROJECTS="software/wifi/raw_u64 software/wifi/raw_c3 software/u64ctrl"
C1_KEYS="ESP_IDF_TAG ESP_IDF_COMMIT MBEDTLS_REPO MBEDTLS_COMMIT WYCHEPROOF_REPO WYCHEPROOF_COMMIT X509_LIMBO_REPO X509_LIMBO_COMMIT"
REQUIRED_KEYS="ESP_IDF_TAG ESP_IDF_COMMIT MBEDTLS_REPO MBEDTLS_COMMIT"

api() { # api <path> : GitHub REST GET, JSON on stdout, nothing on failure
    if command -v gh >/dev/null 2>&1; then
        gh api "$1" 2>/dev/null
    else
        curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} "https://api.github.com/$1" 2>/dev/null
    fi
}
json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

submodule_of() { # submodule_of <ref> : SHA of components/mbedtls/mbedtls at that esp-idf ref
    api "repos/$IDF_REPO/contents/components/mbedtls/mbedtls?ref=$1" | json 'd["sha"] if d.get("type")=="submodule" else ""'
}
submodule_url() { # submodule_url <ref> : absolute URL of components/mbedtls/mbedtls, without .git
    api "repos/$IDF_REPO/contents/.gitmodules?ref=$1" | json 'd["content"]' | python3 -c '
import sys, base64, re, posixpath
text = base64.b64decode(sys.stdin.read()).decode()
for block in re.split(r"\n(?=\[submodule)", text):
    if re.search(r"^\s*path\s*=\s*components/mbedtls/mbedtls\s*$", block, re.M):
        url = re.search(r"^\s*url\s*=\s*(\S+)", block, re.M).group(1)
        if url.startswith("../"):
            url = "https://github.com/" + posixpath.normpath(posixpath.join("espressif/esp-idf", url))
        print(re.sub(r"(\.git)?/?$", "", url))
' 2>/dev/null
}
tag_commit() { # tag_commit <idf-tag> : the commit an ESP-IDF tag points at (annotated or not)
    local o
    o=$(api "repos/$IDF_REPO/git/refs/tags/$1" | json 'd["object"]["type"]+" "+d["object"]["sha"]')
    case $o in
        tag\ *) api "repos/$IDF_REPO/git/tags/${o#tag }" | json 'd["object"]["sha"]' ;;
        *) echo "${o#* }" ;;
    esac
}
mbedtls_version() { # mbedtls_version <owner/repo> <commit> : MBEDTLS_VERSION_STRING at that commit
    api "repos/$1/contents/include/mbedtls/build_info.h?ref=$2" | json 'd["content"]' |
        python3 -c 'import sys,base64,re; m=re.search(r"#define MBEDTLS_VERSION_STRING\s+\"([^\"]+)\"", base64.b64decode(sys.stdin.read()).decode()); print(m.group(1) if m else "?")' 2>/dev/null
}

if [ "${1:-}" = "--suggest" ]; then
    tag=${2:?usage: check_pins.sh --suggest <idf-tag>}
    commit=$(tag_commit "$tag")
    [ -n "$commit" ] || { echo "cannot resolve $IDF_REPO $tag (no such tag, or no network)"; exit 1; }
    sha=$(submodule_of "$commit")
    url=$(submodule_url "$commit")
    [ -n "$sha" ] && [ -n "$url" ] || { echo "no mbedtls submodule at $IDF_REPO $tag"; exit 1; }
    echo "# mbedTLS $(mbedtls_version "${url#https://github.com/}" "$sha"), the mbedtls submodule of ESP-IDF $tag"
    echo "ESP_IDF_TAG=$tag"
    echo "ESP_IDF_COMMIT=$commit"
    echo "MBEDTLS_REPO=$url"
    echo "MBEDTLS_COMMIT=$sha"
    echo "# Also change: docker/Dockerfile (--branch $tag), then regenerate the sdkconfig of: $PROJECTS"
    exit 0
fi

offline=0
image=0
pinsonly=0
pins=${CRYPTO_PINS:-$ROOT/tests/crypto/PINS}
for a in "$@"; do
    case $a in
        --offline) offline=1 ;;
        --image) image=1 ;;
        --pins-only) pinsonly=1 ;;
        *) pins=$a ;;
    esac
done

fails=0
ok()   { echo "ok   $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

echo "PINS file: $pins"
[ -f "$pins" ] || { echo "FAIL no pin file at $pins"; echo "CHECK_PINS_FAIL 1"; exit 1; }
for k in $C1_KEYS; do
    if [ -n "${!k+x}" ]; then
        fail "the environment sets $k=${!k}: keys come from the PINS file only"
    fi
    unset "$k"
done
PINS_LINE='^([A-Z][A-Z0-9_]*)=([A-Za-z0-9._:/+@-]+)([[:space:]]+#.*)?$'
n=0
seen=" "
while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case $line in
        ''|[[:space:]]*'#'*|'#'*) continue ;;
    esac
    [[ $line =~ ^[[:space:]]*$ ]] && continue
    if [[ $line =~ $PINS_LINE ]]; then
        k=${BASH_REMATCH[1]}
        v=${BASH_REMATCH[2]}
        case " $C1_KEYS " in
            *" $k "*) ;;
            *) fail "PINS line $n: $k is not a C1 key"; continue ;;
        esac
        case $seen in
            *" $k "*) fail "PINS line $n: $k is set twice"; continue ;;
        esac
        seen="$seen$k "
        printf -v "$k" '%s' "$v"
    else
        fail "PINS line $n is not KEY=VALUE: $line"
    fi
done < "$pins"
for k in $REQUIRED_KEYS; do
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

if [ $pinsonly -eq 0 ]; then
    # Live Dockerfile text with continuation lines joined, one RUN (or other instruction) per line
    live=$(grep -v '^[[:space:]]*#' "$ROOT/docker/Dockerfile" 2>/dev/null | sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta')
    clones=$(printf '%s\n' "$live" | grep -o 'git clone [^&;]*esp-idf[^[:space:]&;]*' || true)
    n=0
    while IFS= read -r l; do
        [ -n "$l" ] && n=$((n + 1))
    done <<< "$clones"
    if [ "$n" -ne 1 ]; then
        fail "docker/Dockerfile has $n live esp-idf clones, expected 1"
    else
        url=$(printf '%s' "$clones" | grep -o 'https\?://[^[:space:]]*' | head -1)
        branch=$(printf '%s' "$clones" | sed -n 's/.*--branch[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p')
        if [ "${url%.git}" != "https://github.com/espressif/esp-idf" ]; then
            fail "docker/Dockerfile clones esp-idf from '$url', not https://github.com/espressif/esp-idf"
        elif [ "$branch" != "$tag" ]; then
            fail "docker/Dockerfile clones esp-idf '${branch:-?}', PINS says $tag"
        else
            ok "docker/Dockerfile clones espressif/esp-idf $branch"
        fi
    fi
    moves=$(printf '%s\n' "$live" | grep -o -E 'git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?(checkout|switch|reset|am|apply|fetch|pull)\b|git[[:space:]]+-C\b|(^|[[:space:];&|])patch[[:space:]]' | sort -u | tr '\n' ' ' || true)
    if [ -n "$moves" ]; then
        fail "docker/Dockerfile runs commands that can move or patch a checkout: $moves"
    fi

    for p in $PROJECTS; do
        h=$(sed -n 's/^# Espressif IoT Development Framework (ESP-IDF) \([^ ]*\) Project Configuration$/\1/p' "$ROOT/$p/sdkconfig" 2>/dev/null)
        if [ "$h" = "$ver" ]; then ok "$p/sdkconfig was written by ESP-IDF $h"; else fail "$p/sdkconfig was written by ESP-IDF '${h:-?}', PINS says $tag"; fi
    done
fi
if [ $offline -eq 0 ]; then
    c=$(tag_commit "$tag")
    if [ -z "$c" ]; then
        fail "cannot resolve ESP-IDF tag $tag (GitHub API or network error)"
    elif [ "$c" = "${ESP_IDF_COMMIT:-}" ]; then
        ok "ESP_IDF_COMMIT is the commit of ESP-IDF $tag"
    else
        fail "ESP-IDF $tag is commit $c, PINS says ${ESP_IDF_COMMIT:-?}"
    fi
    ref=${ESP_IDF_COMMIT:-$tag}
    s=$(submodule_of "$ref")
    u=$(submodule_url "$ref")
    if [ -z "$s" ] || [ -z "$u" ]; then
        fail "cannot read the mbedtls submodule at ESP-IDF $ref (GitHub API or network error)"
    else
        if [ "$s" = "${MBEDTLS_COMMIT:-}" ]; then
            ok "MBEDTLS_COMMIT is the mbedtls submodule of ESP-IDF $tag (mbedTLS $(mbedtls_version "${u#https://github.com/}" "$s"))"
        else
            fail "ESP-IDF $tag has mbedtls $s, PINS says ${MBEDTLS_COMMIT:-?}"
        fi
        r=${MBEDTLS_REPO:-}
        r=${r%/}
        r=${r%.git}
        if [ "$u" = "$r" ]; then ok "MBEDTLS_REPO is the mbedtls submodule URL of ESP-IDF $tag"; else fail "ESP-IDF $tag takes mbedtls from $u, PINS says ${MBEDTLS_REPO:-?}"; fi
    fi
fi

if [ $image -eq 1 ]; then
    tok=$(curl -fsSL "https://ghcr.io/token?scope=repository:$IMAGE:pull" 2>/dev/null | json 'd["token"]')
    acc='application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
    dig=$(curl -fsSI -H "Authorization: Bearer $tok" -H "Accept: $acc" "https://ghcr.io/v2/$IMAGE/manifests/latest" 2>/dev/null |
          tr -d '\r' | sed -n 's/^docker-content-digest: //Ip')
    cfg=$(curl -fsSL -H "Authorization: Bearer $tok" -H "Accept: $acc" "https://ghcr.io/v2/$IMAGE/manifests/latest" 2>/dev/null |
          json 'd["config"]["digest"]')
    hist=$(curl -fsSL -H "Authorization: Bearer $tok" "https://ghcr.io/v2/$IMAGE/blobs/$cfg" 2>/dev/null |
           json '"\n".join(h.get("created_by","") for h in d.get("history",[]))')
    if [ -z "$hist" ]; then
        fail "cannot read ghcr.io/$IMAGE:latest (registry or network error)"
    elif printf '%s\n' "$hist" | grep -q -- "--branch $tag "; then
        ok "ghcr.io/$IMAGE:latest ($dig) cloned esp-idf $tag"
    else
        fail "ghcr.io/$IMAGE:latest ($dig) did not clone esp-idf $tag"
    fi
fi

if [ $fails -ne 0 ]; then echo "CHECK_PINS_FAIL $fails"; exit 1; fi
if [ $offline -eq 1 ] && [ $pinsonly -eq 1 ]; then echo "CHECK_PINS_PARTIAL offline pins-only"
elif [ $offline -eq 1 ]; then echo "CHECK_PINS_PARTIAL offline"
elif [ $pinsonly -eq 1 ]; then echo "CHECK_PINS_PARTIAL pins-only"
else echo "CHECK_PINS_OK"; fi
