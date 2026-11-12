# Builds lockstep.prg, the 6502 test client, with cc65's ca65 and ld65.
#
#     make            build/lockstep.prg (+ .map, .labels)
#     make check      rebuild and compare with the committed lockstep.prg
#
# The relay address in the PRG is 0.0.0.0: run_pair.py writes the real one into
# the CONFIG block before it starts the program.

CA65    ?= ca65
LD65    ?= ld65
CAFLAGS ?= -g --cpu 6502
BUILD   ?= build

OBJS := $(BUILD)/main.o $(BUILD)/uci.o $(BUILD)/session.o \
	$(BUILD)/digest.o $(BUILD)/rng.o $(BUILD)/tick.o
INC  := $(wildcard *.inc)

.PHONY: all check clean
all: $(BUILD)/lockstep.prg

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: %.s $(INC) | $(BUILD)
	$(CA65) $(CAFLAGS) -I . -o $@ $<

$(BUILD)/lockstep.prg: $(OBJS) lockstep.cfg
	$(LD65) -C lockstep.cfg -o $@ -m $(BUILD)/lockstep.map -Ln $(BUILD)/lockstep.labels $(OBJS)

check: $(BUILD)/lockstep.prg
	cmp $(BUILD)/lockstep.prg lockstep.prg && echo "lockstep.prg matches the sources"

clean:
	rm -rf $(BUILD)
