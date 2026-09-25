#
# Host build of the checks on the TLS calls to the WiFi module, of the channel
# they share with GET_RANDOM (against M1's code), and of the exit paths of the
# TLS spike. FreeRTOS, the UART and lwIP are stand-ins.
#
#   make          build
#   make test     build and run
#
RESULT  = result
OUTPUT  = output

PATH_SW = ../../../../software
TEST    = $(PATH_SW)/test/wifi_tls

VPATH   = $(TEST)/stub $(TEST) $(PATH_SW)/io/wifi $(PATH_SW)/io/uart $(PATH_SW)/wifi/raw_u64/main

CXX     = g++
CPPOPTIONS = -std=gnu++11 -g -O0 -Wall -Wextra -Wno-unused-parameter -DNIOS=1 -DU64=1 \
           $(addprefix -I, $(VPATH))

TLS_SRCS   = wifi_tls_test.cc wifi_dedicated_test.cc m1_oracle.cc world.cc \
             wifi_tls.cc wifi_dedicated.cc wifi_random.cc
SPIKE_SRCS = spike_test.cc wifi_tls_spike.cc

TLS_OBJS   = $(addprefix $(OUTPUT)/tls/, $(TLS_SRCS:%.cc=%.o))
SPIKE_OBJS = $(addprefix $(OUTPUT)/spike/, $(SPIKE_SRCS:%.cc=%.o))

.PHONY: all test clean

all: $(RESULT)/wifitls $(RESULT)/tlsspike

$(OUTPUT)/tls/%.o: %.cc
	@mkdir -p $(OUTPUT)/tls
	$(CXX) $(CPPOPTIONS) -c -o $@ $<

# wifi_dedicated.cc includes "wifi_cmd.h", which the compiler looks for next to
# the source before anywhere else. A copy compiled from here finds the
# stand-in instead; it is the same file, byte for byte.
$(OUTPUT)/tls/wifi_dedicated.o: $(PATH_SW)/io/wifi/wifi_dedicated.cc
	@mkdir -p $(OUTPUT)/tls
	cp $< $(OUTPUT)/tls/wifi_dedicated.cc
	$(CXX) $(CPPOPTIONS) -c -o $@ $(OUTPUT)/tls/wifi_dedicated.cc

$(OUTPUT)/spike/%.o: %.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DTLS_SPIKE -c -o $@ $<

# The spike's allocation goes to spike_test.cc, which can then make it fail.
$(OUTPUT)/spike/wifi_tls_spike.o: wifi_tls_spike.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DTLS_SPIKE -Dmalloc=spike_malloc -Dfree=spike_free -c -o $@ $<

$(RESULT)/wifitls: $(TLS_OBJS)
	@mkdir -p $(RESULT)
	$(CXX) -o $@ $(TLS_OBJS)

$(RESULT)/tlsspike: $(SPIKE_OBJS)
	@mkdir -p $(RESULT)
	$(CXX) -o $@ $(SPIKE_OBJS)

test: all
	@$(RESULT)/wifitls
	@$(RESULT)/tlsspike

clean:
	@rm -rf $(OUTPUT) $(RESULT)
