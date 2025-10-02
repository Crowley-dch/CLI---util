CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector
LDFLAGS = -lcrypto

SRCDIR = src
OBJ = $(SRCDIR)/cli_parser.o $(SRCDIR)/file_io.o $(SRCDIR)/ecb.o $(SRCDIR)/main.o

all: cryptocore

cryptocore: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o cryptocore

.PHONY: all clean
