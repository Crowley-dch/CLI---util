CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector
LIBS = -lcrypto

SRC_DIR = src
MODES_DIR = src/modes
HASH_DIR = src/hash

OBJS = \
    $(SRC_DIR)/cli_parser.o \
    $(SRC_DIR)/file_io.o \
    $(SRC_DIR)/ecb.o \
    $(SRC_DIR)/main.o \
    $(SRC_DIR)/csprng.o \
    $(MODES_DIR)/cbc.o \
    $(MODES_DIR)/cfb.o \
    $(MODES_DIR)/ofb.o \
    $(MODES_DIR)/ctr.o \
    $(HASH_DIR)/sha256.o \
    $(HASH_DIR)/blake2b.o \
    $(MAC_DIR)/hmac.o

BIN = cryptocore

MAC_DIR = src/mac

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/%.o: $(MODES_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(HASH_DIR)/%.o: $(HASH_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(MAC_DIR)/%.o: $(MAC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/main.o: $(SRC_DIR)/main.c \
                   $(SRC_DIR)/cli_parser.h \
                   $(SRC_DIR)/file_io.h \
                   $(HASH_DIR)/sha256.h \
                   $(HASH_DIR)/blake2b.h

$(SRC_DIR)/cli_parser.o: $(SRC_DIR)/cli_parser.c $(SRC_DIR)/cli_parser.h

$(SRC_DIR)/file_io.o: $(SRC_DIR)/file_io.c $(SRC_DIR)/file_io.h

$(HASH_DIR)/sha256.o: $(HASH_DIR)/sha256.c $(HASH_DIR)/sha256.h
$(HASH_DIR)/blake2b.o: $(HASH_DIR)/blake2b.c $(HASH_DIR)/blake2b.h

clean:
	rm -f $(OBJS) $(BIN)

distclean: clean
	rm -f *~ $(SRC_DIR)/*~ $(MODES_DIR)/*~ $(HASH_DIR)/*~

.PHONY: all clean distclean