#!/usr/bin/env bash
# Regression cases for check_pins.sh, offline. Each case builds a scratch tree from this checkout's
# docker/Dockerfile and ESP32 sdkconfigs, changes one thing, runs check_pins.sh --offline and
# compares the last line with the expected one ("pass" = CHECK_PINS_PARTIAL offline, "fail" =
# CHECK_PINS_FAIL). The pins are the v5.3.1 set, so the tree needs no network and no tests/crypto.
# Last line: TEST_CHECK_PINS PASS <n> or TEST_CHECK_PINS FAIL <failed>/<n>.
set -u

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CHECK=$ROOT/tests/crypto/vendor/check_pins.sh
WORK=$(mktemp -d "${TMPDIR:-/tmp}/test_check_pins.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
PROJECTS="software/wifi/raw_u64 software/wifi/raw_c3 software/u64ctrl"

cat > "$WORK/PINS" <<'EOF'
# v5.3.1 pins, as in tests/crypto/PINS
ESP_IDF_TAG=v5.3.1
ESP_IDF_COMMIT=c8fc5f643b7a7b0d3b182d3df610844e3dc9bd74
MBEDTLS_REPO=https://github.com/espressif/mbedtls
MBEDTLS_COMMIT=72aa687352a469044cbb946f3fdb261430e41ce1   # esp-idf v5.3.1 submodule
WYCHEPROOF_REPO=https://github.com/C2SP/wycheproof
WYCHEPROOF_COMMIT=3fa63dd0344abb611f1fb1d77e119938603ea230
X509_LIMBO_REPO=https://github.com/C2SP/x509-limbo
X509_LIMBO_COMMIT=554528a9b0c0d95e071f55de018326f0b65a8364
EOF

tree() { # tree <name>: a scratch copy of the files check_pins.sh reads
    local t=$WORK/$1
    mkdir -p "$t/tests/crypto/vendor" "$t/docker"
    cp "$CHECK" "$t/tests/crypto/vendor/"
    cp "$ROOT/docker/Dockerfile" "$t/docker/"
    for p in $PROJECTS; do
        mkdir -p "$t/$p"
        cp "$ROOT/$p/sdkconfig" "$t/$p/"
    done
    echo "$t"
}

n=0
failed=0
expect() { # expect <pass|fail> <name> <tree> <pins> [env assignments...]; MSG=<text> also requires that FAIL text
    local want=$1 name=$2 t=$3 pins=$4
    shift 4
    local out last
    out=$(env "$@" "$t/tests/crypto/vendor/check_pins.sh" --offline "$pins" 2>&1)
    last=$(printf '%s\n' "$out" | tail -1)
    local got=fail
    [ "$last" = "CHECK_PINS_PARTIAL offline" ] && got=pass
    if [ -n "${MSG:-}" ] && ! printf '%s\n' "$out" | grep '^FAIL' | grep -qF -- "$MSG"; then
        got="fail without \"$MSG\""
    fi
    n=$((n + 1))
    if [ "$got" = "$want" ]; then
        echo "ok   $name ($last)"
    else
        echo "FAIL $name: expected $want, got: $last"
        failed=$((failed + 1))
    fi
}
pins_plus() { # pins_plus <name> <line...>: the good PINS with lines appended
    local f=$WORK/PINS.$1
    shift
    cp "$WORK/PINS" "$f"
    printf '%s\n' "$@" >> "$f"
    echo "$f"
}
dockerfile() { # dockerfile <name> <sed expression>: a tree whose Dockerfile is edited
    local t
    t=$(tree "$1")
    sed -i.bak -e "$2" "$t/docker/Dockerfile" && rm -f "$t/docker/Dockerfile.bak"
    echo "$t"
}

T=$(tree base)
expect pass "unchanged tree and pins" "$T" "$WORK/PINS"
expect pass "indented comment" "$T" "$(pins_plus c1 '   # an indented comment')"

# PINS lines the consumers would read differently (vendor-adversarial3 M4, adversarial2 L1)
expect fail "indented key after the real ones" "$T" "$(pins_plus i1 ' ESP_IDF_TAG=v5.3.6 # candidate')"
expect fail "tab-indented key" "$T" "$(pins_plus i2 $'\tESP_IDF_COMMIT=79e3454c68248bd7d881721c9b2e94561378a8ce # candidate')"
expect fail "indented key with a bare #" "$T" "$(pins_plus i3 ' MBEDTLS_COMMIT=2b96dd8eebe880f304c69976b3c2fa0c5100cbb6 #')"
expect fail "repeated key" "$T" "$(pins_plus d1 'ESP_IDF_TAG=v5.3.1')"
expect fail "export" "$T" "$(pins_plus e1 'export FOO_BAR=1')"
expect fail "declare" "$T" "$(pins_plus e2 'declare fails=-5')"
expect fail "command substitution" "$T" "$(pins_plus e3 'X=$(touch '"$WORK"'/pwned)')"
expect fail "unknown key" "$T" "$(pins_plus u1 'EXTRA_KEY=1')"
grep -v '^ESP_IDF_COMMIT=' "$WORK/PINS" > "$WORK/PINS.nocommit"
expect fail "missing ESP_IDF_COMMIT" "$T" "$WORK/PINS.nocommit"
sed 's|^MBEDTLS_REPO=.*|MBEDTLS_REPO="https://github.com/espressif/mbedtls"|' "$WORK/PINS" > "$WORK/PINS.quoted"
expect fail "quoted value" "$T" "$WORK/PINS.quoted"
expect fail "environment sets a key" "$T" "$WORK/PINS" ESP_IDF_TAG=v5.3.1

# Dockerfile edits (vendor-adversarial2 L2, adversarial3 M7)
CL='git clone --recursive --branch v5.3.1 https:\/\/github.com\/espressif\/esp-idf'
expect fail "clone from a fork" "$(dockerfile fork 's|github.com/espressif/esp-idf|github.com/GideonZ/esp-idf|')" "$WORK/PINS"
MSG="can move or patch a checkout"
expect fail "git -c ... checkout" "$(dockerfile gc "s|$CL|& \&\& git -C esp-idf -c advice.detachedHead=false checkout v5.3.6|")" "$WORK/PINS"
expect fail "git --git-dir checkout" "$(dockerfile gd "s|$CL|& \&\& git --git-dir=esp-idf/.git --work-tree=esp-idf checkout v5.3.6|")" "$WORK/PINS"
expect fail "git -c checkout, no -C" "$(dockerfile gc2 "s|$CL|& \&\& cd esp-idf \&\& git -c advice.detachedHead=false checkout v5.3.6 \&\& cd ..|")" "$WORK/PINS"
expect fail "submodule update --remote" "$(dockerfile sub "s|$CL|& \&\& cd esp-idf \&\& git submodule update --remote components/mbedtls/mbedtls \&\& cd ..|")" "$WORK/PINS"
MSG="can move or patch a checkout"
expect fail "plain git checkout" "$(dockerfile pl "s|$CL|& \&\& cd esp-idf \&\& git checkout v5.3.6 \&\& cd ..|")" "$WORK/PINS"
expect fail "cherry-pick" "$(dockerfile cp "s|$CL|& \&\& cd esp-idf \&\& git cherry-pick abc \&\& cd ..|")" "$WORK/PINS"
expect fail "merge" "$(dockerfile mg "s|$CL|& \&\& cd esp-idf \&\& git merge origin/release/v5.3 \&\& cd ..|")" "$WORK/PINS"
expect fail "restore" "$(dockerfile rs "s|$CL|& \&\& cd esp-idf \&\& git restore --source=v5.3.6 . \&\& cd ..|")" "$WORK/PINS"
expect fail "am" "$(dockerfile am "s|$CL|& \&\& git -C esp-idf am /p/x.patch|")" "$WORK/PINS"
expect fail "patch" "$(dockerfile pt '$a\
RUN cd /opt/esp/esp-idf \&\& patch -p1 < /x.diff')" "$WORK/PINS"
MSG=
expect fail "ADD a git URL into the tree" "$(dockerfile ad '$a\
ADD https://github.com/espressif/esp-idf.git#v5.3.6 /opt/esp/esp-idf')" "$WORK/PINS"
expect fail "COPY into the mbedtls submodule" "$(dockerfile co '$a\
COPY mbedtls/ /opt/esp/esp-idf/components/mbedtls/mbedtls/')" "$WORK/PINS"
expect fail "second ENV IDF_PATH" "$(dockerfile ev '$a\
ENV IDF_PATH=/opt/other/esp-idf')" "$WORK/PINS"
expect fail "two live clones" "$(dockerfile two '$a\
RUN git clone --branch v5.5.5 https://github.com/espressif/esp-idf /x')" "$WORK/PINS"
# vendor-adversarial4 L1: five Dockerfile spellings the round-3 checker passed
MSG="clones esp-idf 'v5.3.6'"
expect fail "last --branch= wins" "$(dockerfile b2 "s|--branch v5.3.1 https|--branch v5.3.1 --branch=v5.3.6 https|")" "$WORK/PINS"
expect fail "last -b wins" "$(dockerfile b3 "s|--branch v5.3.1 https|--branch v5.3.1 -b v5.3.6 https|")" "$WORK/PINS"
expect fail "trailing shell comment names the old tag" "$(dockerfile tc "s|--branch v5.3.1 https://github.com/espressif/esp-idf |--branch v5.3.6 https://github.com/espressif/esp-idf  # was: git clone --branch v5.3.1 of esp-idf |")" "$WORK/PINS"
MSG="WORKDIR inside the ESP-IDF tree"
expect fail "WORKDIR into the tree, relative COPY" "$(dockerfile wd '$a\
WORKDIR /opt/esp/esp-idf/components/mbedtls\
COPY mbedtls/ mbedtls/')" "$WORK/PINS"
MSG="sets IDF_PATH 2 times"
expect fail "IDF_PATH in a multi-variable ENV" "$(dockerfile e2 '$a\
ENV IDF_TOOLS_PATH=/root/.espressif IDF_PATH=/opt/other/esp-idf')" "$WORK/PINS"
MSG="only the one esp-idf clone is allowed"
expect fail "second git clone of mbedtls into the tree" "$(dockerfile mc '$a\
RUN rm -rf $IDF_PATH/components/mbedtls/mbedtls \&\& git clone --branch mbedtls-3.6.7 https://github.com/Mbed-TLS/mbedtls $IDF_PATH/components/mbedtls/mbedtls')" "$WORK/PINS"
MSG=
expect pass "commented clone with checkout" "$(dockerfile cm '1i\
# RUN git clone --branch v5.2.0 https://github.com/espressif/esp-idf \&\& git checkout x')" "$WORK/PINS"

[ ! -e "$WORK/pwned" ] || { echo "FAIL the command substitution in PINS was executed"; failed=$((failed + 1)); }
if [ $failed -eq 0 ]; then echo "TEST_CHECK_PINS PASS $n"; else echo "TEST_CHECK_PINS FAIL $failed/$n"; exit 1; fi
