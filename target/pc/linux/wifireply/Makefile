#
# Host build of the reply table of the WiFi command channel, and of
# wifi_cmd.cc against stubs of the UART and the RTOS, and of what wifi_connect.h
# tells the user after a connect from the access point list.
#
#   make          build
#   make test     build and run
#   make legacy   build and run the model of the table before the fix; it fails
#
PRJ     = wifireply
RESULT  = result
OUTPUT  = output

PATH_SW = ../../../../software

VPATH   = $(PATH_SW)/io/wifi $(PATH_SW)/test/wifi_reply
STUBS   = $(PATH_SW)/test/wifi_reply/stubs

CC      = gcc
COPTIONS = -std=c99 -g -O0 -Wall -Wextra -Wno-unused-parameter \
           $(addprefix -I, $(VPATH))

CXX     = g++
CXXOPTIONS = -std=c++11 -g -O0 -w -DRISCV=1 -DU64=2 -I$(STUBS) $(addprefix -I, $(VPATH)) \
             -I$(PATH_SW)/io/uart -I$(PATH_SW)/u64ctrl/main -I$(PATH_SW)/system

SRCS_C  = wifi_reply_test.c
OBJS    = $(addprefix $(OUTPUT)/, $(SRCS_C:%.c=%.o))
CMD_SRC = $(PATH_SW)/io/wifi/wifi_cmd.cc $(PATH_SW)/test/wifi_reply/wifi_cmd_test.cc
CMD_DEP = $(wildcard $(PATH_SW)/io/wifi/*.h $(STUBS)/*.h)
CONN_SRC = $(PATH_SW)/test/wifi_reply/wifi_connect_test.cc

.PHONY: all test legacy clean bench-hold-red

all: $(RESULT)/$(PRJ) $(RESULT)/wifi_cmd $(RESULT)/wifi_connect

$(OUTPUT)/%.o: %.c wifi_reply.h
	@mkdir -p $(OUTPUT)
	$(CC) $(COPTIONS) -c -o $@ $<

$(RESULT)/$(PRJ): $(OBJS)
	@mkdir -p $(RESULT)
	$(CC) -o $@ $(OBJS)

$(RESULT)/wifi_cmd: $(CMD_SRC) $(CMD_DEP)
	@mkdir -p $(RESULT)
	$(CXX) $(CXXOPTIONS) -o $@ $(CMD_SRC)

$(RESULT)/wifi_connect: $(CONN_SRC) $(CMD_DEP)
	@mkdir -p $(RESULT)
	$(CXX) $(CXXOPTIONS) -o $@ $(CONN_SRC)

test: all
	@$(RESULT)/$(PRJ)
	@mkdir -p $(OUTPUT)
	@$(RESULT)/wifi_cmd > $(OUTPUT)/wifi_cmd.log || { grep '^FAIL' $(OUTPUT)/wifi_cmd.log; tail -n 1 $(OUTPUT)/wifi_cmd.log; exit 1; }
	@tail -n 1 $(OUTPUT)/wifi_cmd.log
	@$(RESULT)/wifi_connect

legacy:
	@mkdir -p $(OUTPUT)
	$(CC) $(COPTIONS) -DWIFI_REPLY_LEGACY -o $(OUTPUT)/legacy $(PATH_SW)/test/wifi_reply/wifi_reply_test.c
	@$(OUTPUT)/legacy

# BENCH ONLY: CMD_BENCH_HOLD_RX (wifi_bench_hold.h, wifi_bench_hold_rx in wifi_cmd.cc). Each model changes one rule of the
# RPC or of the reply parser in a copy; wifi_cmd_test has to fail against it.
#   clamp-removed   the request carries ms as asked (no 10000 limit)      clamp-zero    a release (0) is sent as 1
#   long-timeout    waits the 10 s default instead of 1 s                  no-uart-check no module: dereferences a missing uart
#   size-ignored    parses 12 bytes whatever came                          short-ok      a 6 byte reply is parsed
#   bare-success-ok an 8 byte reply with esp_err 0 is an answer            held-from-short held_ms read from an 8 byte reply
BENCH_HOLD_MUTANTS := clamp-removed clamp-zero long-timeout no-uart-check size-ignored short-ok bare-success-ok held-from-short no-buf-lumped no-slot-lumped rts-flag-dropped flag-in-wait
mutfile_clamp-removed := wifi_bench_hold.h
mut_clamp-removed := s/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : ms;/return ms;/
mutfile_clamp-zero := wifi_bench_hold.h
mut_clamp-zero := s/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : ms;/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : (ms ? ms : 1);/
mutfile_long-timeout := wifi_cmd.cc
mut_long-timeout := s/(int)clamped + BENCH_HOLD_RPC_SLACK_MS/WIFI_REPLY_TIMEOUT_MS/
mutfile_no-uart-check := wifi_cmd.cc
mut_no-uart-check := s/if (!esp32.uart) {/if (0) {/
mutfile_no-buf-lumped := wifi_cmd.cc
mut_no-buf-lumped := s/return BENCH_HOLD_RC_NO_BUF;/return BENCH_HOLD_RC_NONE;/
mutfile_no-slot-lumped := wifi_cmd.cc
mut_no-slot-lumped := s/return BENCH_HOLD_RC_NO_SLOT;/return BENCH_HOLD_RC_NONE;/
mutfile_size-ignored := wifi_cmd.cc
mut_size-ignored := s/bench_hold_rx_parse(buf->data, buf->size, esp_err, held_ms)/bench_hold_rx_parse(buf->data, 12, esp_err, held_ms)/
mutfile_short-ok := wifi_bench_hold.h
mut_short-ok := s/if (size < (int)(sizeof(rpc_header_t) + sizeof(int))) {/if (0) {/
mutfile_bare-success-ok := wifi_bench_hold.h
mut_bare-success-ok := s/} else if (err == 0) {/} else if (0) {/
mutfile_held-from-short := wifi_bench_hold.h
mut_held-from-short := s/if (size >= (int)sizeof(rpc_bench_hold_rx_resp)) {/if (1) {/
mutfile_rts-flag-dropped := wifi_cmd.cc
mut_rts-flag-dropped := s/args->ms = clamped | (ms \& BENCH_HOLD_RTS_OFF);/args->ms = clamped;/
mutfile_flag-in-wait := wifi_cmd.cc
mut_flag-in-wait := s/bench_hold_clamp(ms \& ~BENCH_HOLD_RTS_OFF)/bench_hold_clamp(ms)/

define BENCH_HOLD_MUTANT
bench-hold-red-$(1):
	@mkdir -p $(OUTPUT)/mut_$(1)
	cp $(PATH_SW)/io/wifi/wifi_cmd.cc $(PATH_SW)/io/wifi/wifi_bench_hold.h $(OUTPUT)/mut_$(1)/
	sed '$(mut_$(1))' $(PATH_SW)/io/wifi/$(mutfile_$(1)) > $(OUTPUT)/mut_$(1)/$(mutfile_$(1)).new
	@if cmp -s $(PATH_SW)/io/wifi/$(mutfile_$(1)) $(OUTPUT)/mut_$(1)/$(mutfile_$(1)).new; then echo "bench-hold-red-$(1): the model changes nothing"; exit 1; fi
	mv $(OUTPUT)/mut_$(1)/$(mutfile_$(1)).new $(OUTPUT)/mut_$(1)/$(mutfile_$(1))
	$(CXX) $(CXXOPTIONS) -I$(OUTPUT)/mut_$(1) -o $(OUTPUT)/mut_$(1)/wifi_cmd $(OUTPUT)/mut_$(1)/wifi_cmd.cc $(PATH_SW)/test/wifi_reply/wifi_cmd_test.cc
	@if $(OUTPUT)/mut_$(1)/wifi_cmd > $(OUTPUT)/mut_$(1)/run.log 2>&1; then \
		echo "bench-hold-red-$(1): the suite passed against the model"; exit 1; \
	else \
		echo "bench-hold-red-$(1): killed ($$$$(grep -c '^FAIL' $(OUTPUT)/mut_$(1)/run.log) checks failed), as required"; \
	fi
endef
$(foreach m,$(BENCH_HOLD_MUTANTS),$(eval $(call BENCH_HOLD_MUTANT,$(m))))
bench-hold-red: $(addprefix bench-hold-red-,$(BENCH_HOLD_MUTANTS))

clean:
	@rm -rf $(OUTPUT) $(RESULT)
