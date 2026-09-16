CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude
LIBS = -lpcap

TARGET = npa

SOURCES = src/main.c src/interface.c src/utils.c src/capture.c src/parser.c src/ip_protocols.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)