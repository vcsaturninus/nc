CFLAGS += -Wall -Wpedantic -std=c99 -Werror -O3
ifdef DEBUG_MODE
 CFLAGS += -g
endif

CPPFLAGS += -Isrc 
CPPFLAGS += -D_POSIX_C_SOURCE=200112L   # struct addrinfo, getopt

ifdef USE_TLS
CPPFLAGS += -DUSE_TLS
LDFLAGS  += -lssl -lcrypto
endif

$(info LDFLAGS is $(LDFLAGS))

SRC:=$(wildcard src/*.c)
OUT:=nc
OUT_DIR:=out

VALGRIND_REPORT:=valgrind.txt

.PHONY: all clean

all: clean compile

clean:
	rm -rf $(OUT_DIR) $(VALGRIND_REPORT)
	mkdir -p $(OUT_DIR)

$(OUT_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

compile: $(addprefix $(OUT_DIR)/, $(notdir $(SRC:.c=.o)))
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ $(LDFLAGS) -o $(OUT_DIR)/$(OUT)


