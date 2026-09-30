#!/bin/zsh
# Builds the engine host test (engine_test.c) and its server (m3srv.c).
#   build.sh [VARIANT...]     VARIANT = head (this tree, the default) | base (the M2 engine at a846369f, for RED runs)
#                             | mut-NAME (this tree with mutants/NAME.patch applied)
#                             | at-SHA[+NAME] (the engine at commit SHA, optionally with mutant NAME applied)
# Inputs, all read-only (override with the environment):
#   MB4   mbedTLS 4.1.1 (espressif ce3f3485) built by build_mb4.sh with this bridge's sdkconfig, ASan+UBSan
#   S4    its source tree; IDF: ESP-IDF v6.0.3 (76f5dedd), for esp_crt_bundle.c and gen_crt_bundle.py
#   SRV   mbedTLS 3.6.0 with its default configuration (the server side), and S36 its source
# Output: build/<variant>/engine_test, build/m3srv, build/pki (mkpki.sh).
set -e
T=${0:A:h}; RAW=${T:h}; SW=${RAW:h:h}; REPO=${SW:h}
AR=${AR_ROOT:-/Users/someone/Documents/1541u-esp-tls-archive}
MB4=${MB4:-$AR/session-0930/m3esp-work/mb4}
S4=${S4:-$AR/session-0929/engine4-work/mbedtls-4.1.1}
IDF=${IDF:-$AR/session-0929/engine4-work/idf-v6.0.3}
SRV=${SRV:-$AR/session-0930/m3esp-work/srv36}
S36=${S36:-$AR/session-0928/fixreview-work/mbedtls-3.6.0}
BD=$T/build; mkdir -p $BD $T/stub/x # stub/x: "../lwip/..." includes resolve from it (an empty dir git does not keep)
$T/mkpki.sh $BD/pki

# The certificate bundle the BUNDLE cases verify against: the test root only, in ESP-IDF 6's own format
if [ ! -f $BD/x509_crt_bundle ]; then
  (cd $BD && python3 $IDF/components/mbedtls/esp_crt_bundle/gen_crt_bundle.py -q --input $BD/pki/ca.pem)
fi
# The server and the embedded files (only when missing or changed: mutrun.sh builds in parallel)
if [ ! -f $BD/m3srv -o $T/m3srv.c -nt $BD/m3srv ]; then
  printf '    .section __TEXT,__const\n    .globl _binary_x509_crt_bundle_start\n    .globl _binary_x509_crt_bundle_end\n_binary_x509_crt_bundle_start:\n    .incbin "%s"\n_binary_x509_crt_bundle_end:\n' $BD/x509_crt_bundle > $BD/bundle.s
  printf '    .section __TEXT,__const\n    .globl _binary_tls_test_ca_pem_start\n    .globl _binary_tls_test_ca_pem_end\n_binary_tls_test_ca_pem_start:\n    .incbin "%s"\n    .byte 0\n_binary_tls_test_ca_pem_end:\n' $BD/pki/ca.pem > $BD/testca.s

  cc -std=gnu17 -g -O1 -w -I$S36/include -I$S36/library -I$SRV/include $T/m3srv.c \
     $SRV/library/libmbedtls.a $SRV/library/libmbedx509.a $SRV/library/libmbedcrypto.a -o $BD/m3srv
fi

MI=(-I$MB4/config -I$S4/include -I$S4/tf-psa-crypto/include -I$S4/tf-psa-crypto/drivers/builtin/include
    -I$MB4/build/library -I$MB4/build/tf-psa-crypto/include
    -I$S4/library -I$S4/tf-psa-crypto/core -I$S4/tf-psa-crypto/drivers/builtin/src -I$S4/tf-psa-crypto/extras
    -DMBEDTLS_MAJOR_VERSION=4 "-DMBEDTLS_CONFIG_FILE=\"mbedtls/esp_config.h\"" "-DTF_PSA_CRYPTO_USER_CONFIG_FILE=\"$MB4/config/mbedtls/esp_config.h\"")
L=($MB4/build/library/libmbedtls.a $MB4/build/library/libmbedx509.a $MB4/build/library/libtfpsacrypto.a
   $MB4/build/tf-psa-crypto/drivers/builtin/libbuiltin.a $MB4/build/tf-psa-crypto/drivers/everest/libeverest.a
   $MB4/build/tf-psa-crypto/drivers/p256-m/libp256-m.a $MB4/build/tf-psa-crypto/drivers/pqcp/libpqcp.a
   $MB4/build/tf-psa-crypto/extras/libextras.a $MB4/build/tf-psa-crypto/platform/libplatform.a
   $MB4/build/tf-psa-crypto/utilities/libutilities.a)
# The mbedTLS patches the ESP32 build applies (../mbedtls_patches.cmake, --fuzz=0), compiled as MB4 compiled the
# original and linked ahead of libmbedtls.a, which then leaves its own copy out. NOCOOKIE=1 links the unpatched
# library (the RED run of case hrr_cookie).
MP=$BD/mbedtls_patched
if [ ! -f $MP/ssl_tls13_generic.o -o $RAW/patches/mbedtls-tls13-hrr-cookie.patch -nt $MP/ssl_tls13_generic.o ]; then
  rm -rf $MP; mkdir -p $MP/library; cp $S4/library/ssl_tls13_generic.c $MP/library/
  patch -s -d $MP -p1 --forward --batch --fuzz=0 -i $RAW/patches/mbedtls-tls13-hrr-cookie.patch
  cc -g -O2 -DNDEBUG -fsanitize=address,undefined -fno-omit-frame-pointer -w -iquote $S4/library $MI \
     -I$S4/tf-psa-crypto/dispatch -I$S4/tf-psa-crypto/platform -I$S4/tf-psa-crypto/utilities \
     -I$S4/tf-psa-crypto/drivers/everest/include -I$S4/tf-psa-crypto/drivers/p256-m/p256-m -I$S4/tf-psa-crypto/drivers/pqcp/include \
     -c $MP/library/ssl_tls13_generic.c -o $MP/ssl_tls13_generic.o
fi
MPO=($MP/ssl_tls13_generic.o); [ -n "${NOCOOKIE:-}" ] && MPO=()
HOSTOFF="CONFIG_MBEDTLS_HARDWARE_AES CONFIG_MBEDTLS_HARDWARE_SHA CONFIG_MBEDTLS_HARDWARE_MPI CONFIG_MBEDTLS_HARDWARE_ECC CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY CONFIG_MBEDTLS_ROM_MD5 CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL CONFIG_MBEDTLS_HARDWARE_RSA_DS_PERIPHERAL"

for v in ${@:-head}; do
  O=$BD/$v; rm -rf $O; mkdir -p $O/src
  case $v in
    base) git -C $REPO archive a846369f software/wifi/raw_u64/main software/wifi/raw_u64/sdkconfig | tar -x -C $O/src
          M=$O/src/software/wifi/raw_u64/main; SDK=$O/src/software/wifi/raw_u64/sdkconfig; EXTRA=(-DBASE_ENGINE); CA=($BD/testca.s);;
    head) M=$RAW/main; SDK=$RAW/sdkconfig; EXTRA=(); CA=();;
    at-*) sha=${${v#at-}%%+*}; git -C $REPO archive $sha software/wifi/raw_u64/main | tar -x -C $O/src   # at-SHA[+MUTANT]
          [[ $v == *+* ]] && patch -s -d $O/src/software/wifi/raw_u64 -p1 < $T/mutants/${v#*+}.patch
          M=$O/src/software/wifi/raw_u64/main; SDK=$RAW/sdkconfig; EXTRA=(); CA=();;
    mut-*) mkdir -p $O/src/main; cp -R $RAW/main/. $O/src/main/; patch -s -d $O/src -p1 < $T/mutants/${v#mut-}.patch
          M=$O/src/main; SDK=$RAW/sdkconfig; EXTRA=(); CA=();;
  esac
  awk -F= -v off="$HOSTOFF" 'BEGIN { n = split(off, o, " "); for (i = 1; i <= n; i++) skip[o[i]] = 1 }
       /^CONFIG_[A-Za-z0-9_]+=/ { if ($1 in skip) next; v = substr($0, length($1) + 2); if (v == "y") v = 1; print "#define " $1 " " v }' \
      $SDK > $O/sdkconfig.h
  CF=(-std=gnu17 -g -O1 -Wall -Wextra -Wno-unused-parameter -D_FORTIFY_SOURCE=0 -fsanitize=address,undefined -fno-omit-frame-pointer
      -Wno-macro-redefined -I$O -I$T/stub -I$T/stub/x -I$M -I$SW/io/uart -I$IDF/components/mbedtls/esp_crt_bundle/include $MI $EXTRA)
  cc $CF -c $M/tls_engine.c -o $O/tls_engine.o 2> $O/warnings.txt || { cat $O/warnings.txt; exit 1; }
  cc $CF -Wno-unused-variable -Wno-unused-but-set-variable -Wno-sign-compare -Wno-missing-field-initializers -Wno-pointer-sign \
     -c $M/rpc_dispatch.c -o $O/rpc_dispatch.o 2>> $O/warnings.txt || { cat $O/warnings.txt; exit 1; }
  cc $CF -Wno-unused-function -c $T/engine_test.c -o $O/engine_test.o
  cc $CF -fno-sanitize=alignment -w -c $IDF/components/mbedtls/esp_crt_bundle/esp_crt_bundle.c -o $O/esp_crt_bundle.o
  cc -fsanitize=address,undefined -Wl,-undefined,dynamic_lookup $O/{tls_engine,rpc_dispatch,engine_test,esp_crt_bundle}.o $BD/bundle.s $CA $MPO $L -o $O/engine_test
  echo "built $v ($(grep -c warning: $O/warnings.txt || true) warnings in the bridge sources)${NOCOOKIE:+ WITHOUT the mbedTLS patches}"
done
