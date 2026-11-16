# Target 6 (UCI HTTP) over the WiFi module's TLS sessions, on the host: the real HttpTarget and
# ModuleTlsHttpProvider against a fake module and a fake TCP peer. Needs the patched HTTP parser:
#   python3 tools/prepare_http_parser.py     (never commit that submodule change)
#   make test
SW  = ../../../../software
CXX ?= g++
INC = -I$(SW)/network -I$(SW)/network/tests -I$(SW)/api -I$(SW)/infra -I$(SW)/components -I$(SW)/io/stream \
      -I$(SW)/system -I$(SW)/io/wifi -I$(SW)/io/command_interface -I$(SW)/httpd/c-version/lib
DEFS = -DRUNS_ON_PC -DMHS_PORT=8001 -D_DEFAULT_SOURCE
CXXFLAGS = -std=gnu++11 -g -O0 -Wall -Wextra -Wno-format -Wno-format-extra-args -Wno-unused-parameter $(INC) $(DEFS)
OUT = output
CXX_SRCS = $(SW)/network/tests/test_module_tls_http.cc $(SW)/network/tests/http_target_test_support.cc \
           $(SW)/network/module_tls_http.cc $(SW)/network/http_request.cc \
           $(SW)/api/json.cc $(SW)/components/mystring.cc $(SW)/components/pattern.cc $(SW)/system/small_printf.cc
C_SRCS = $(SW)/httpd/c-version/lib/http_protocol.c $(SW)/httpd/c-version/lib/multipart.c $(SW)/httpd/c-version/lib/url.c
OBJS = $(patsubst %,$(OUT)/%.o,$(notdir $(CXX_SRCS) $(C_SRCS)))
VPATH = $(dir $(CXX_SRCS) $(C_SRCS))

.PHONY: all test clean
all: $(OUT)/test_module_tls_http
test: all
	$(OUT)/test_module_tls_http
$(OUT)/http_target.cc.o: $(SW)/io/command_interface/http_target.cc
	@mkdir -p $(OUT)
	$(CXX) $(CXXFLAGS) -I$(SW)/io/command_interface/tests/host_rtos -c -o $@ $<
$(OUT)/%.cc.o: %.cc
	@mkdir -p $(OUT)
	$(CXX) $(CXXFLAGS) -c -o $@ $<
$(OUT)/%.c.o: %.c
	@mkdir -p $(OUT)
	$(CC) -g -O0 -Wall -Wno-unused-parameter $(INC) $(DEFS) -c -o $@ $<
$(OUT)/test_module_tls_http: $(OBJS) $(OUT)/http_target.cc.o
	$(CXX) -o $@ $^ -lpthread
clean:
	rm -rf $(OUT)
