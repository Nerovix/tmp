OUT_DIR = build
CC      = aarch64-linux-gnu-gcc
RM      = rm -f

TOOLS = dump_violations start_test sync_test
BINARIES = $(addprefix $(OUT_DIR)/,$(TOOLS))

all: $(BINARIES)

$(OUT_DIR)/%: %.c | $(OUT_DIR)
	$(CC) $< -o $@ -static

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	$(RM) $(BINARIES)

.PHONY: all clean
