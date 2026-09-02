CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
TARGET = server_2423
SRC = server_2423.c
LIBS = -lcrypt

.PHONY: all run clean help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(TARGET) data/ *.log *.o

help:
	@echo "Usage:"
	@echo "  make         - Build the server executable ($(TARGET))"
	@echo "  make run     - Build and launch the server"
	@echo "  make clean   - Remove binaries, data directory, and log files"
