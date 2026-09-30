#
# Host build of the checks on the TLS calls to the WiFi module, of the channel
# they share with GET_RANDOM (against M1's code), and of the TLS commands of
# the network target (M3). FreeRTOS, the UART, lwIP and, for the network
# target, the module are stand-ins. The M2 spike's test is no longer built:
# the spike speaks M2's wire, which M3 replaced.
#
#   make          build
#   make test     build and run
#
RESULT  = result
OUTPUT  = output

PATH_SW = ../../../../software
TEST    = $(PATH_SW)/test/wifi_tls

VPATH   = $(TEST)/stub $(TEST) $(PATH_SW)/io/wifi $(PATH_SW)/io/uart $(PATH_SW)/wifi/raw_u64/main
# The route's JSON, rendered by the firmware's own classes for the golden files.
JSON_PATH = $(PATH_SW)/api $(PATH_SW)/components $(PATH_SW)/io/stream $(PATH_SW)/system

CXX     = g++
CPPOPTIONS = -std=gnu++11 -g -O0 -Wall -Wextra -Wno-unused-parameter -DNIOS=1 -DU64=1 \
           $(addprefix -I, $(VPATH))

TLS_SRCS   = wifi_tls_test.cc wifi_dedicated_test.cc m1_oracle.cc world.cc \
             wifi_tls.cc wifi_dedicated.cc wifi_random.cc
SPIKE_SRCS = spike_test.cc wifi_tls_spike.cc wifi_tls_json.cc json.cc mystring.cc small_printf.cc
GOLDEN     = ../../../../tests/e2e/io/wifi/golden

TLS_OBJS   = $(addprefix $(OUTPUT)/tls/, $(TLS_SRCS:%.cc=%.o))
SPIKE_OBJS = $(addprefix $(OUTPUT)/spike/, $(SPIKE_SRCS:%.cc=%.o))

.PHONY: all test golden clean

# The network target's sources, which a red run can point at another tree.
NET_DIR  = $(PATH_SW)/io/network
NET_PATH = $(TEST)/netstub $(TEST)/stub $(NET_DIR) $(PATH_SW)/io/wifi $(PATH_SW)/io/command_interface
NET_OPTIONS = -std=gnu++11 -g -O0 -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -DNIOS=1 -DU64=1 $(addprefix -I, $(NET_PATH))
NET_SRCS = net_tls_test.cc net_world.cc ip4addr_aton.cc
NET_OBJS = $(addprefix $(OUTPUT)/net/, $(NET_SRCS:%.cc=%.o)) $(OUTPUT)/net/network_target.o

all: $(RESULT)/wifitls $(RESULT)/nettls

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

$(OUTPUT)/net/%.o: $(TEST)/%.cc
	@mkdir -p $(OUTPUT)/net
	$(CXX) $(NET_OPTIONS) -c -o $@ $<

# Compiled from a copy, so that its includes find the stand-ins rather than
# the headers next to it (network_interface.h).
$(OUTPUT)/net/network_target.o: $(NET_DIR)/network_target.cc $(NET_DIR)/network_target.h
	@mkdir -p $(OUTPUT)/net
	cp $< $(OUTPUT)/net/network_target.cc
	$(CXX) $(NET_OPTIONS) -c -o $@ $(OUTPUT)/net/network_target.cc

$(RESULT)/nettls: $(NET_OBJS)
	@mkdir -p $(RESULT)
	$(CXX) -o $@ $(NET_OBJS)

$(OUTPUT)/spike/%.o: %.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DTLS_SPIKE -DRUNS_ON_PC $(addprefix -idirafter , $(JSON_PATH)) -c -o $@ $<

# The spike's allocation goes to spike_test.cc, which can then make it fail.
$(OUTPUT)/spike/wifi_tls_spike.o: wifi_tls_spike.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DTLS_SPIKE -Dmalloc=spike_malloc -Dfree=spike_free -c -o $@ $<

$(OUTPUT)/spike/%.o: $(PATH_SW)/api/%.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DRUNS_ON_PC $(addprefix -I, $(JSON_PATH)) -c -o $@ $<

$(OUTPUT)/spike/%.o: $(PATH_SW)/components/%.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DRUNS_ON_PC $(addprefix -I, $(JSON_PATH)) -c -o $@ $<

# The firmware's formatter, which StreamRamFile renders the JSON with. The rest
# of that file would replace the host's printf family, so it is renamed away.
FW_STDIO = printf puts putchar sprintf snprintf vsprintf vsnprintf sscanf
$(OUTPUT)/spike/%.o: $(PATH_SW)/system/%.cc
	@mkdir -p $(OUTPUT)/spike
	$(CXX) $(CPPOPTIONS) -DRUNS_ON_PC $(foreach f,$(FW_STDIO),-D$(f)=fw_$(f)) $(addprefix -I, $(JSON_PATH)) -c -o $@ $<

$(RESULT)/wifitls: $(TLS_OBJS)
	@mkdir -p $(RESULT)
	$(CXX) -o $@ $(TLS_OBJS)

$(RESULT)/tlsspike: $(SPIKE_OBJS)
	@mkdir -p $(RESULT)
	$(CXX) -o $@ $(SPIKE_OBJS)

# The spike test also renders the route's JSON for each exit path into
# $(OUTPUT)/golden and checks it against the files in $(GOLDEN), which
# `make golden` rewrites.
test: all
	@$(RESULT)/wifitls
	@$(RESULT)/nettls

golden: all
	@mkdir -p $(GOLDEN)
	@$(RESULT)/tlsspike $(GOLDEN) $(GOLDEN)

clean:
	@rm -rf $(OUTPUT) $(RESULT)
