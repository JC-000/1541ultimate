#!/bin/zsh
# Builds the engine host test and its server: build.sh [head|base|mut-NAME|at-SHA[+NAME]...] (default head).
# Variants and the required inputs MB4, S4, IDF, SRV, S36: README.md. Output: build/<variant>/engine_test,
# build/tls_server, build/pki (mkpki.sh).
set -e
T=${0:A:h}; RAW=${T:h}; SW=${RAW:h:h}; REPO=${SW:h}
for e in MB4 S4 IDF SRV S36; do [ -n "${(P)e}" ] || { echo "build.sh: set $e (see the header)" >&2; exit 2; }; done
BD=$T/build; mkdir -p $BD $T/stub/x # stub/x: "../lwip/..." includes resolve from it (an empty dir git does not keep)
$T/mkpki.sh $BD/pki

# The certificate bundle the BUNDLE cases verify against: the test root only, in ESP-IDF 6's own format
if [ ! -f $BD/x509_crt_bundle ]; then
  (cd $BD && python3 $IDF/components/mbedtls/esp_crt_bundle/gen_crt_bundle.py -q --input $BD/pki/ca.pem)
fi
# The server and the embedded files (only when missing or changed: mutrun.sh builds in parallel)
if [ ! -f $BD/tls_server -o $T/tls_server.c -nt $BD/tls_server ]; then
  printf '    .section __TEXT,__const\n    .globl _binary_x509_crt_bundle_start\n    .globl _binary_x509_crt_bundle_end\n_binary_x509_crt_bundle_start:\n    .incbin "%s"\n_binary_x509_crt_bundle_end:\n' $BD/x509_crt_bundle > $BD/bundle.s
  printf '    .section __TEXT,__const\n    .globl _binary_tls_test_ca_pem_start\n    .globl _binary_tls_test_ca_pem_end\n_binary_tls_test_ca_pem_start:\n    .incbin "%s"\n    .byte 0\n_binary_tls_test_ca_pem_end:\n' $BD/pki/ca.pem > $BD/testca.s

  cc -std=gnu17 -g -O1 -w -I$S36/include -I$S36/library -I$SRV/include $T/tls_server.c \
     $SRV/library/libmbedtls.a $SRV/library/libmbedx509.a $SRV/library/libmbedcrypto.a -o $BD/tls_server
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
HOSTOFF="CONFIG_MBEDTLS_HARDWARE_AES CONFIG_MBEDTLS_HARDWARE_SHA CONFIG_MBEDTLS_HARDWARE_MPI CONFIG_MBEDTLS_HARDWARE_ECC CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY CONFIG_MBEDTLS_ROM_MD5 CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL CONFIG_MBEDTLS_HARDWARE_RSA_DS_PERIPHERAL"

for v in ${@:-head}; do
  O=$BD/$v; rm -rf $O; mkdir -p $O/src
  case $v in
    base) [ -n "$BASE_REF" ] || { echo "build.sh: base needs BASE_REF, a commit with the previous engine (README.md)" >&2; exit 2; }
          git -C $REPO archive $BASE_REF software/wifi/raw_u64/main software/wifi/raw_u64/sdkconfig | tar -x -C $O/src
          M=$O/src/software/wifi/raw_u64/main; SDK=$O/src/software/wifi/raw_u64/sdkconfig; EXTRA=(-DBASE_ENGINE); CA=($BD/testca.s)
          [ -f $M/tls_engine.c ] && ! grep -q CMD_TLS_CLOSE_ALL $M/rpc_calls.h && ! diff -rq $M $RAW/main > /dev/null ||
            { echo "build.sh: BASE_REF=$BASE_REF is not the previous engine (README.md: base)" >&2; exit 2; };;
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
  cc -fsanitize=address,undefined -Wl,-undefined,dynamic_lookup $O/{tls_engine,rpc_dispatch,engine_test,esp_crt_bundle}.o $BD/bundle.s $CA $L -o $O/engine_test
  echo "built $v ($(grep -c warning: $O/warnings.txt || true) warnings in the bridge sources)"
done
