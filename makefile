CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector
LDFLAGS = -lcrypto

SRCDIR = src
MODESDIR = $(SRCDIR)/modes

BASE_OBJ = $(SRCDIR)/cli_parser.o $(SRCDIR)/file_io.o $(SRCDIR)/ecb.o $(SRCDIR)/main.o $(SRCDIR)/csprng.o
MODES_OBJ = $(MODESDIR)/cbc.o $(MODESDIR)/cfb.o $(MODESDIR)/ofb.o $(MODESDIR)/ctr.o 

OBJ = $(BASE_OBJ) $(MODES_OBJ)

all: cryptocore

cryptocore: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(MODESDIR)/%.o: $(MODESDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(MODESDIR)/*.o cryptocore

.PHONY: all clean