CFLAGS:= -Wall -Wpedantic -std=c99 -Werror -O3
ifdef DEBUG_MODE
 CFLAGS += -g
endif

SRC:= src/nc.c
CPPFLAGS:=-Isrc 
CPPFLAGS += -D_POSIX_C_SOURCE=200112L   # struct addrinfo, getopt
OUT:=nc

VALGRIND_REPORT:= valgrind.txt
OUT_DIR:=out

# tests
TESTS_DIR:=tests/
C_TESTS_SRC:=tests.c
C_TESTS_OUT:=tests

.PHONY: all clean

all: clean paths compile

paths:
	mkdir -p $(OUT_DIR)

clean:
	rm -rf $(OUT_DIR) $(VALGRIND_REPORT)

compile:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SRC) -o $(OUT_DIR)/$(OUT)

grind: clean paths compile
	valgrind --leak-check=full --show-leak-kinds=all \
        --track-origins=yes --verbose \
        --log-file=$(VALGRIND_REPORT) \
        ./$(OUT_DIR)/$(C_TESTS_OUT)


