#
# The ESP32's TLS engine (tls_engine.c and the CMD_TLS_* handlers in
# rpc_dispatch.c), built for the host with ASan and UBSan and driven the way the
# Ultimate drives it (software/test/wifi_tls_interop/nios_pump.c), against the
# client-independent interop matrix in software/test/tls_interop: OpenSSL
# s_server, a GnuTLS echo server and a raw HelloRetryRequest peer.
#
#   make                      build
#   make interop              build and run the matrix: one line per case, then
#                             TLS_INTEROP PASS|FAIL n/m (mbedTLS commit, sdkconfig sha256)
#   make interop ENGINE_REV=<commit>
#                             the same against tls_engine.c as it was at <commit>
#   make interop ONLY=<regex> only the cases whose name matches
#   make interop BAUD=0       without the serial link's delay per step (nios_pump.c --baud)
#   make interop CRYPTO_PINS=<file> CRYPTO_SDKCONFIG=<file> CRYPTO_MACROS=<file>
#                             another mbedTLS: build_mbedtls.sh's overrides, passed on
#
# Needs: cc, python3, git, cmake, openssl (OPENSSL=, default brew's openssl@3),
# GnuTLS with pkg-config, and pip access for tlslite-ng (pinned by hash in
# software/test/tls_interop/requirements-tlslite.txt, installed in output/venv). mbedTLS is built by tests/crypto/build_mbedtls.sh
# (cached, so it runs every time) into a directory named after the hash of its
# effective inputs; the engine, the pump and the run are named after it too.
#
RESULT  = result
OUTPUT  = output

REPO    = $(abspath ../../../..)
PATH_SW = ../../../../software
PEERS   = $(PATH_SW)/test/tls_interop
TEST    = $(PATH_SW)/test/wifi_tls_interop
MAIN    = $(PATH_SW)/wifi/raw_u64/main
STUB    = $(TEST)/stub

OPENSSL ?= $(shell brew --prefix openssl@3 2>/dev/null)/bin/openssl
PYTHON  ?= python3

# build_mbedtls.sh's inputs, with its own defaults
BUILD_MBEDTLS = $(REPO)/tests/crypto/build_mbedtls.sh
EFF_PINS      = $(abspath $(or $(CRYPTO_PINS),$(REPO)/tests/crypto/PINS))
EFF_SDKCONFIG = $(abspath $(or $(CRYPTO_SDKCONFIG),$(REPO)/software/wifi/raw_u64/sdkconfig))
EFF_MACROS    = $(abspath $(or $(CRYPTO_MACROS),$(REPO)/tests/crypto/esp32_macros.txt))
MBEDTLS_KEY  := $(shell cat $(EFF_PINS) $(EFF_SDKCONFIG) $(EFF_MACROS) $(BUILD_MBEDTLS) | shasum -a 256 | cut -c1-12)
MBEDTLS       = $(OUTPUT)/mbedtls-$(MBEDTLS_KEY)
MBEDTLS_LIB   = $(MBEDTLS)/build/library
SDKCONFIG_SHA := $(shell shasum -a 256 < $(EFF_SDKCONFIG) | cut -c1-16)

# tls_engine.c from another commit, for red/green runs
ENGINE_REV ?=
ifeq ($(ENGINE_REV),)
ENGINE_SRC = $(MAIN)/tls_engine.c
ENGINE_TAG = tree
else
ENGINE_TAG = $(ENGINE_REV)
ENGINE_SRC = $(OUTPUT)/$(ENGINE_TAG)/tls_engine.c
endif
OBJ  = $(OUTPUT)/$(MBEDTLS_KEY)
PUMP = $(RESULT)/nios_pump_$(ENGINE_TAG)_$(MBEDTLS_KEY)

# rpc_dispatch.c includes "../lwip/esp_netif_lwip_internal.h": from stub/driver that is stub/lwip.
# sdkconfig.h is the one build_mbedtls.sh derives from the sdkconfig.
CFLAGS = -std=gnu17 -g -O1 -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined -fno-omit-frame-pointer \
         -I$(STUB) -I$(STUB)/driver -I$(MAIN) -I$(PATH_SW)/io/uart -I$(MBEDTLS)/config -I$(MBEDTLS)/src/include \
         -DMBEDTLS_CONFIG_FILE='"mbedtls_host.h"'
LIBS   = $(MBEDTLS_LIB)/libmbedtls.a $(MBEDTLS_LIB)/libmbedx509.a $(MBEDTLS_LIB)/libmbedcrypto.a

# The rest of rpc_dispatch.c (Wi-Fi, UART) is never called here and stays unresolved
ifeq ($(shell uname -s),Darwin)
UNRESOLVED = -Wl,-undefined,dynamic_lookup
CONST_SECTION = __TEXT,__const
else
UNRESOLVED = -Wl,--unresolved-symbols=ignore-all
CONST_SECTION = .rodata
endif

PKI  = $(OUTPUT)/pki
VENV = $(OUTPUT)/venv

.PHONY: all interop clean FORCE

all: $(PUMP) $(RESULT)/gnutls_echo $(VENV)/installed

$(VENV)/installed: $(PEERS)/requirements-tlslite.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q --require-hashes -r $<
	@touch $@

# Always run: build_mbedtls.sh checks its inputs and is cached. The stamp only changes with the build.
$(MBEDTLS)/stamp: FORCE
	@mkdir -p $(MBEDTLS)
	@CRYPTO_PINS=$(EFF_PINS) CRYPTO_SDKCONFIG=$(EFF_SDKCONFIG) CRYPTO_MACROS=$(EFF_MACROS) \
	    $(BUILD_MBEDTLS) $(MBEDTLS) > $(MBEDTLS)/build_mbedtls.log 2>&1 || { tail -20 $(MBEDTLS)/build_mbedtls.log; exit 1; }
	@tail -1 $(MBEDTLS)/build_mbedtls.log | grep '^MBEDTLS_BUILD_OK '
	@cmp -s $(MBEDTLS)/build_mbedtls.log $(MBEDTLS)/stamp || cp $(MBEDTLS)/build_mbedtls.log $(MBEDTLS)/stamp

$(OUTPUT)/$(ENGINE_TAG)/tls_engine.c:
	@mkdir -p $(dir $@)
	git -C $(PATH_SW) show $(ENGINE_REV):software/wifi/raw_u64/main/tls_engine.c > $@

# The engine's compiled-in test CA is the PKI's two roots
# The throwaway PKI: made once, and only extended (interop.py pki keeps what exists)
$(PKI)/trust.pem: FORCE
	@$(PYTHON) $(PEERS)/interop.py pki --openssl $(OPENSSL) --pki $(PKI) > /dev/null

$(OUTPUT)/test_ca.S: $(PKI)/trust.pem
	@mkdir -p $(OUTPUT)
	printf '    .section $(CONST_SECTION)\n    .globl _binary_tls_test_ca_pem_start\n    .globl _binary_tls_test_ca_pem_end\n_binary_tls_test_ca_pem_start:\n    .incbin "$(abspath $<)"\n    .byte 0\n_binary_tls_test_ca_pem_end:\n' > $@

$(OBJ)/$(ENGINE_TAG)/tls_engine.o: $(ENGINE_SRC) $(MAIN)/tls_engine.h $(MAIN)/rpc_calls.h $(MBEDTLS)/stamp Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Dsettimeofday=harness_settimeofday -Dmbedtls_ssl_read=harness_ssl_read \
	    -Dmbedtls_ssl_write=harness_ssl_write -c -o $@ $<

$(OBJ)/rpc_dispatch.o: $(MAIN)/rpc_dispatch.c $(MAIN)/rpc_calls.h $(MBEDTLS)/stamp
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/nios_pump.o: $(TEST)/nios_pump.c $(MAIN)/rpc_calls.h $(MBEDTLS)/stamp
	@mkdir -p $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ $<

$(PUMP): $(OBJ)/$(ENGINE_TAG)/tls_engine.o $(OBJ)/rpc_dispatch.o $(OBJ)/nios_pump.o $(OUTPUT)/test_ca.S
	@mkdir -p $(RESULT)
	$(CC) -fsanitize=address,undefined $(UNRESOLVED) -o $@ $^ $(LIBS)

$(RESULT)/gnutls_echo: $(PEERS)/gnutls_echo.c
	@mkdir -p $(RESULT)
	$(CC) -std=gnu17 -O1 -Wall $(shell pkg-config --cflags gnutls) -o $@ $< $(shell pkg-config --libs gnutls)

interop: all
	$(PYTHON) $(PEERS)/interop.py run --client $(PUMP) --gnutls $(RESULT)/gnutls_echo --openssl $(OPENSSL) \
	    --tlslite-python $(VENV)/bin/python \
	    --pki $(PKI) --out $(OUTPUT)/run_$(ENGINE_TAG)_$(MBEDTLS_KEY)$(if $(BAUD),_baud$(BAUD)) \
	    --label "engine $(ENGINE_TAG), mbedTLS $$(tail -1 $(MBEDTLS)/stamp | cut -d' ' -f3), sdkconfig sha256 $(SDKCONFIG_SHA)" \
	    $(if $(ONLY),--only '$(ONLY)') $(if $(BAUD),--client-arg=--baud --client-arg=$(BAUD))

clean:
	@rm -rf $(OUTPUT) $(RESULT)
