#
# Host build of the ESP32's TLS engine (tls_engine.c and the CMD_TLS_* handlers
# in rpc_dispatch.c) against mbedTLS built for the host, driven the way the
# Ultimate drives it, against independent TLS 1.3 servers: OpenSSL s_server and
# a GnuTLS echo server. ASan and UBSan are on.
#
#   make                      build
#   make interop              build and run the matrix: one line per case, then
#                             TLS_INTEROP PASS|FAIL n/m
#   make interop ENGINE_REV=<commit>
#                             the same against tls_engine.c as it was at <commit>
#   make interop ONLY=<regex> only the cases whose name matches
#   make interop BAUD=0       without the serial link's delay per step (nios_pump.c --baud)
#
# Needs: cc, python3, git, cmake, openssl (OPENSSL=, default brew's openssl@3),
# and GnuTLS with pkg-config. mbedTLS is built by tests/crypto/build_mbedtls.sh:
# the commit tests/crypto/PINS names, with the ESP32 image's configuration.
#
RESULT  = result
OUTPUT  = output

PATH_SW = ../../../../software
TEST    = $(PATH_SW)/test/wifi_tls_interop
MAIN    = $(PATH_SW)/wifi/raw_u64/main
STUB    = $(TEST)/stub

MBEDTLS     = $(OUTPUT)/mbedtls
MBEDTLS_LIB = $(MBEDTLS)/build/library
OPENSSL     ?= $(shell brew --prefix openssl@3 2>/dev/null)/bin/openssl
PYTHON      ?= python3

# tls_engine.c from another commit, for red/green runs
ENGINE_REV ?=
ifeq ($(ENGINE_REV),)
ENGINE_SRC = $(MAIN)/tls_engine.c
ENGINE_TAG = tree
else
ENGINE_TAG = $(ENGINE_REV)
ENGINE_SRC = $(OUTPUT)/$(ENGINE_TAG)/tls_engine.c
endif
PUMP = $(RESULT)/nios_pump_$(ENGINE_TAG)

# rpc_dispatch.c includes "../lwip/esp_netif_lwip_internal.h": from stub/driver that is stub/lwip.
# sdkconfig.h is the one build_mbedtls.sh derives from software/wifi/raw_u64/sdkconfig.
CFLAGS = -std=gnu17 -g -O1 -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined -fno-omit-frame-pointer \
         -I$(STUB) -I$(STUB)/driver -I$(MAIN) -I$(PATH_SW)/io/uart -I$(MBEDTLS)/config -I$(MBEDTLS)/src/include \
         -DMBEDTLS_CONFIG_FILE='"mbedtls_esp32_host.h"'
LIBS   = $(MBEDTLS_LIB)/libmbedtls.a $(MBEDTLS_LIB)/libmbedx509.a $(MBEDTLS_LIB)/libmbedcrypto.a

# The rest of rpc_dispatch.c (Wi-Fi, UART) is never called here and stays unresolved
ifeq ($(shell uname -s),Darwin)
UNRESOLVED = -Wl,-undefined,dynamic_lookup
CONST_SECTION = __TEXT,__const
else
UNRESOLVED = -Wl,--unresolved-symbols=ignore-all
CONST_SECTION = .rodata
endif

PKI = $(OUTPUT)/pki

.PHONY: all interop clean

all: $(PUMP) $(RESULT)/gnutls_echo

$(MBEDTLS_LIB)/libmbedtls.a: ../../../../tests/crypto/PINS ../../../../tests/crypto/build_mbedtls.sh \
                                       $(PATH_SW)/wifi/raw_u64/sdkconfig
	../../../../tests/crypto/build_mbedtls.sh $(MBEDTLS) | tee $(OUTPUT)/mbedtls.log | tail -1
	@tail -1 $(OUTPUT)/mbedtls.log | grep -q '^MBEDTLS_BUILD_OK '

$(OUTPUT)/$(ENGINE_TAG)/tls_engine.c:
	@mkdir -p $(dir $@)
	git -C $(PATH_SW) show $(ENGINE_REV):software/wifi/raw_u64/main/tls_engine.c > $@

# The throwaway PKI; the engine's compiled-in test CA is its two roots
$(PKI)/trust.pem: $(TEST)/interop.py
	$(PYTHON) $(TEST)/interop.py pki --openssl $(OPENSSL) --pki $(PKI)

$(OUTPUT)/test_ca.S: $(PKI)/trust.pem
	printf '    .section $(CONST_SECTION)\n    .globl _binary_tls_test_ca_pem_start\n    .globl _binary_tls_test_ca_pem_end\n_binary_tls_test_ca_pem_start:\n    .incbin "$(abspath $<)"\n    .byte 0\n_binary_tls_test_ca_pem_end:\n' > $@

$(OUTPUT)/$(ENGINE_TAG)/tls_engine.o: $(ENGINE_SRC) $(MAIN)/tls_engine.h $(MAIN)/rpc_calls.h $(MBEDTLS_LIB)/libmbedtls.a
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Dsettimeofday=harness_settimeofday -c -o $@ $<

$(OUTPUT)/%.o: $(MAIN)/%.c $(MBEDTLS_LIB)/libmbedtls.a
	@mkdir -p $(OUTPUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTPUT)/nios_pump.o: $(TEST)/nios_pump.c $(MAIN)/rpc_calls.h $(MBEDTLS_LIB)/libmbedtls.a
	@mkdir -p $(OUTPUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(PUMP): $(OUTPUT)/$(ENGINE_TAG)/tls_engine.o $(OUTPUT)/rpc_dispatch.o $(OUTPUT)/nios_pump.o $(OUTPUT)/test_ca.S
	@mkdir -p $(RESULT)
	$(CC) -fsanitize=address,undefined $(UNRESOLVED) -o $@ $^ $(LIBS)

$(RESULT)/gnutls_echo: $(TEST)/gnutls_echo.c
	@mkdir -p $(RESULT)
	$(CC) -std=gnu17 -O1 -Wall $(shell pkg-config --cflags gnutls) -o $@ $< $(shell pkg-config --libs gnutls)

interop: all
	$(PYTHON) $(TEST)/interop.py run --pump $(PUMP) --gnutls $(RESULT)/gnutls_echo --openssl $(OPENSSL) \
	    --pki $(PKI) --out $(OUTPUT)/run_$(ENGINE_TAG)$(if $(BAUD),_baud$(BAUD)) $(if $(ONLY),--only '$(ONLY)') $(if $(BAUD),--baud $(BAUD))

clean:
	@rm -rf $(OUTPUT) $(RESULT)
