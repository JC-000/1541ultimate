# BENCH ONLY, never upstream. Run it on top of the normal Makefile, so that it needs no edit of it:
#   make -f Makefile -f bench_hold.mk bench-hold bench-hold-red
# BENCH ONLY: CMD_BENCH_HOLD_RX for the X15 leg. The UCI command 0xE5 (bench_hold_ctrl.h), the wire format and the reply parser
# (wifi_bench_hold.h) against a fake RPC; the RPC itself is tested in target/pc/linux/wifireply (make test, make bench-hold-red).
BENCH_HOLD_TEST := $(OUTPUT_DIR)/benchHoldTest
BENCH_HOLD_DIR := ../../wifi

bench-hold:
	mkdir -p $(OUTPUT_DIR)
	$(CXX) $(CXXFLAGS) -I$(BENCH_HOLD_DIR) bench_hold_test.cpp ../../usb/tests/host_test_main.cpp -lpthread -o $(BENCH_HOLD_TEST) && $(BENCH_HOLD_TEST)

# One rule of the headers changed per model (in a copy placed first on the include path); each has to fail the suite.
BENCH_HOLD_MUTANTS := len-unchecked len-at-least ms-offset short-as-noreply none-as-ok not-supported-as-data not-supported-any-error \
	swapped-words outlen-12 outlen-kept not-supported-code ok-text clamp-removed clamp-zero parse-short-ok parse-bare-success-ok \
	parse-held-from-short parse-err-offset parse-held-offset
mutfile_len-unchecked := bench_hold_ctrl.h
mut_len-unchecked := s/if (len != BENCH_HOLD_UCI_LEN) {/if (0) {/
mutfile_len-at-least := bench_hold_ctrl.h
mut_len-at-least := s/if (len != BENCH_HOLD_UCI_LEN) {/if (len < BENCH_HOLD_UCI_LEN) {/
mutfile_ms-offset := bench_hold_ctrl.h
mut_ms-offset := s/memcpy(\&ms, msg + 2, sizeof(ms));/memcpy(\&ms, msg + 1, sizeof(ms));/
mutfile_short-as-noreply := bench_hold_ctrl.h
mut_short-as-noreply := s/if (rc == BENCH_HOLD_RC_SHORT) {/if (0) {/
mutfile_none-as-ok := bench_hold_ctrl.h
mut_none-as-ok := s/if (rc != BENCH_HOLD_RC_OK) {/if (0) {/
mutfile_not-supported-as-data := bench_hold_ctrl.h
mut_not-supported-as-data := s/if (esp_err == BENCH_HOLD_NOT_SUPPORTED) {/if (0) {/
mutfile_not-supported-any-error := bench_hold_ctrl.h
mut_not-supported-any-error := s/if (esp_err == BENCH_HOLD_NOT_SUPPORTED) {/if (esp_err != 0) {/
mutfile_swapped-words := bench_hold_ctrl.h
mut_swapped-words := s/memcpy(out, \&esp_err, sizeof(esp_err));/memcpy(out + 4, \&esp_err, sizeof(esp_err));/
mutfile_outlen-12 := bench_hold_ctrl.h
mut_outlen-12 := s/\*outlen = (int)(sizeof(esp_err) + sizeof(held_word));/*outlen = 12;/
mutfile_outlen-kept := bench_hold_ctrl.h
mut_outlen-kept := s/^    \*outlen = 0;$$//
mutfile_not-supported-code := bench_hold_ctrl.h
mut_not-supported-code := s/define BENCH_HOLD_NOT_SUPPORTED   0x106/define BENCH_HOLD_NOT_SUPPORTED   0x105/
mutfile_ok-text := bench_hold_ctrl.h
mut_ok-text := s/"00,OK"/"00,OKAY"/
mutfile_clamp-removed := wifi_bench_hold.h
mut_clamp-removed := s/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : ms;/return ms;/
mutfile_clamp-zero := wifi_bench_hold.h
mut_clamp-zero := s/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : ms;/return (ms > BENCH_HOLD_MS_MAX) ? (uint32_t)BENCH_HOLD_MS_MAX : (ms ? ms : 1);/
mutfile_parse-short-ok := wifi_bench_hold.h
mut_parse-short-ok := s/if (size < (int)(sizeof(rpc_header_t) + sizeof(int))) {/if (size < 4) {/
mutfile_parse-bare-success-ok := wifi_bench_hold.h
mut_parse-bare-success-ok := s/} else if (err == 0) {/} else if (0) {/
mutfile_parse-held-from-short := wifi_bench_hold.h
mut_parse-held-from-short := s/if (size >= (int)sizeof(rpc_bench_hold_rx_resp)) {/if (size >= 8) {/
mutfile_parse-err-offset := wifi_bench_hold.h
mut_parse-err-offset := s/memcpy(\&err, data + sizeof(rpc_header_t), sizeof(err));/memcpy(\&err, data + 8, sizeof(err));/
mutfile_parse-held-offset := wifi_bench_hold.h
mut_parse-held-offset := s/memcpy(\&held, data + sizeof(rpc_header_t) + sizeof(int), sizeof(held));/memcpy(\&held, data + 4, sizeof(held));/

define BENCH_HOLD_MUTANT
bench-hold-red-$(1):
	mkdir -p $$(OUTPUT_DIR)/bh_$(1)
	cp $$(BENCH_HOLD_DIR)/bench_hold_ctrl.h $$(BENCH_HOLD_DIR)/wifi_bench_hold.h $$(OUTPUT_DIR)/bh_$(1)/
	sed '$$(mut_$(1))' $$(BENCH_HOLD_DIR)/$$(mutfile_$(1)) > $$(OUTPUT_DIR)/bh_$(1)/$$(mutfile_$(1)).new
	@if cmp -s $$(BENCH_HOLD_DIR)/$$(mutfile_$(1)) $$(OUTPUT_DIR)/bh_$(1)/$$(mutfile_$(1)).new; then echo "bench-hold-red-$(1): the model changes nothing"; exit 1; fi
	mv $$(OUTPUT_DIR)/bh_$(1)/$$(mutfile_$(1)).new $$(OUTPUT_DIR)/bh_$(1)/$$(mutfile_$(1))
	$$(CXX) $$(CXXFLAGS) -I$$(OUTPUT_DIR)/bh_$(1) bench_hold_test.cpp ../../usb/tests/host_test_main.cpp -lpthread -o $$(OUTPUT_DIR)/bh_$(1)/test
	@if $$(OUTPUT_DIR)/bh_$(1)/test > $$(OUTPUT_DIR)/bh_$(1)/run.log 2>&1; then \
		echo "bench-hold-red-$(1): the suite passed against the model"; exit 1; \
	else \
		echo "bench-hold-red-$(1): killed ($$$$(grep -c FAIL $$(OUTPUT_DIR)/bh_$(1)/run.log) checks failed), as required"; \
	fi
endef
$(foreach m,$(BENCH_HOLD_MUTANTS),$(eval $(call BENCH_HOLD_MUTANT,$(m))))
bench-hold-red: $(addprefix bench-hold-red-,$(BENCH_HOLD_MUTANTS))
.PHONY: bench-hold bench-hold-red $(addprefix bench-hold-red-,$(BENCH_HOLD_MUTANTS))
