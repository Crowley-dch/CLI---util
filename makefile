CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector -Wno-deprecated-declarations
LIBS = -lcrypto

SRC_DIR = src
MODES_DIR = src/modes
HASH_DIR = src/hash
MAC_DIR = src/mac
KDF_DIR = src/kdf
TESTS_DIR = tests

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
    $(KDF_DIR)/pbkdf2.o \
    $(KDF_DIR)/hkdf.o  

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
                   $(KDF_DIR)/pbkdf2.h \
                   $(KDF_DIR)/hkdf.h  # НОВОЕ: добавлена зависимость
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

$(KDF_DIR)/hkdf.o: $(KDF_DIR)/hkdf.c $(KDF_DIR)/hkdf.h
	$(CC) $(CFLAGS) -c $< -o $@

TEST_KDF_OBJS = $(KDF_DIR)/pbkdf2.o $(KDF_DIR)/hkdf.o $(MAC_DIR)/hmac.o $(HASH_DIR)/sha256.o

test_kdf_rfc: $(TESTS_DIR)/test_kdf_rfc.c $(TEST_KDF_OBJS)
	$(CC) $(CFLAGS) -o $(TESTS_DIR)/test_kdf_rfc $(TESTS_DIR)/test_kdf_rfc.c $(TEST_KDF_OBJS) $(LIBS)
	$(TESTS_DIR)/test_kdf_rfc

test_kdf_comprehensive: $(TESTS_DIR)/test_kdf_comprehensive.c $(TEST_KDF_OBJS)
	$(CC) $(CFLAGS) -o $(TESTS_DIR)/test_kdf_comprehensive $(TESTS_DIR)/test_kdf_comprehensive.c $(TEST_KDF_OBJS) $(LIBS)
	$(TESTS_DIR)/test_kdf_comprehensive

test_hkdf: $(TESTS_DIR)/test_hkdf.c $(TEST_KDF_OBJS)
	$(CC) $(CFLAGS) -o $(TESTS_DIR)/test_hkdf $(TESTS_DIR)/test_hkdf.c $(TEST_KDF_OBJS) $(LIBS)
	$(TESTS_DIR)/test_hkdf

test_kdf_all: test_kdf_rfc test_kdf_comprehensive test_hkdf

test_all: $(BIN)
	@echo "=== Running all tests ==="
	@if [ -f "./tests/test_all_modes.sh" ]; then \
		./tests/test_all_modes.sh; \
	else \
		echo "Warning: test_all_modes.sh not found"; \
	fi
	@if [ -f "./tests/test_derive.sh" ]; then \
		./tests/test_derive.sh; \
	else \
		echo "Note: Create test_derive.sh for KDF testing"; \
	fi

clean:
	rm -f $(OBJS) $(BIN) \
	      $(TESTS_DIR)/test_kdf_rfc $(TESTS_DIR)/test_kdf_comprehensive $(TESTS_DIR)/test_hkdf \
	      $(TESTS_DIR)/test_*.o

distclean: clean
	rm -f *~ $(SRC_DIR)/*~ $(MODES_DIR)/*~ $(HASH_DIR)/*~ $(MAC_DIR)/*~ $(KDF_DIR)/*~ $(TESTS_DIR)/*~

.PHONY: all clean distclean test_kdf_rfc test_kdf_comprehensive test_hkdf test_kdf_all test_all