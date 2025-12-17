CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector
LIBS = -lcrypto

SRC_DIR = src
MODES_DIR = src/modes
HASH_DIR = src/hash
MAC_DIR = src/mac
KDF_DIR = src/kdf

OBJS = \
    $(SRC_DIR)/cli_parser.o \
    $(SRC_DIR)/file_io.o \
    $(SRC_DIR)/ecb.o \
    $(SRC_DIR)/main.o \
    $(SRC_DIR)/csprng.o \
    $(SRC_DIR)/aead.o \
    $(MODES_DIR)/cbc.o \
    $(MODES_DIR)/cfb.o \
    $(MODES_DIR)/ofb.o \
    $(MODES_DIR)/ctr.o \
    $(MODES_DIR)/gcm.o \
    $(HASH_DIR)/sha256.o \
    $(HASH_DIR)/blake2b.o \
    $(MAC_DIR)/hmac.o \
    $(KDF_DIR)/pbkdf2.o

BIN = cryptocore

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(SRC_DIR)/cli_parser.o: $(SRC_DIR)/cli_parser.c $(SRC_DIR)/cli_parser.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/file_io.o: $(SRC_DIR)/file_io.c $(SRC_DIR)/file_io.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/ecb.o: $(SRC_DIR)/ecb.c $(SRC_DIR)/ecb.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/main.o: $(SRC_DIR)/main.c \
                   $(SRC_DIR)/cli_parser.h \
                   $(SRC_DIR)/file_io.h \
                   $(MODES_DIR)/gcm.h \
                   $(HASH_DIR)/sha256.h \
                   $(HASH_DIR)/blake2b.h \
                   $(MAC_DIR)/hmac.h \
                   $(KDF_DIR)/pbkdf2.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/csprng.o: $(SRC_DIR)/csprng.c $(SRC_DIR)/csprng.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/aead.o: $(SRC_DIR)/aead.c $(SRC_DIR)/aead.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/cbc.o: $(MODES_DIR)/cbc.c $(MODES_DIR)/cbc.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/cfb.o: $(MODES_DIR)/cfb.c $(MODES_DIR)/cfb.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/ofb.o: $(MODES_DIR)/ofb.c $(MODES_DIR)/ofb.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/ctr.o: $(MODES_DIR)/ctr.c $(MODES_DIR)/ctr.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MODES_DIR)/gcm.o: $(MODES_DIR)/gcm.c $(MODES_DIR)/gcm.h
	$(CC) $(CFLAGS) -c $< -o $@

$(HASH_DIR)/sha256.o: $(HASH_DIR)/sha256.c $(HASH_DIR)/sha256.h
	$(CC) $(CFLAGS) -c $< -o $@

$(HASH_DIR)/blake2b.o: $(HASH_DIR)/blake2b.c $(HASH_DIR)/blake2b.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MAC_DIR)/hmac.o: $(MAC_DIR)/hmac.c $(MAC_DIR)/hmac.h
	$(CC) $(CFLAGS) -c $< -o $@

$(KDF_DIR)/pbkdf2.o: $(KDF_DIR)/pbkdf2.c $(KDF_DIR)/pbkdf2.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)

distclean: clean
	rm -f *~ $(SRC_DIR)/*~ $(MODES_DIR)/*~ $(HASH_DIR)/*~ $(MAC_DIR)/*~ $(KDF_DIR)/*~

.PHONY: all clean distclean