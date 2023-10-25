CC=gcc

TARGET   = uds-server
SOURCES  = $(shell echo *.c)
HEADERS  = $(shell echo *.h)

prefix   = /usr/local
bindir   = $(prefix)/bin

all: $(TARGET)
	$(CC) -g -o  $(TARGET) uds-server.c libconfuse.a

debug: CFLAGS += -g -O0 -Wall -Wextra 
debug: $(TARGET)
	$(CC) $(CFLAGS) -o  $(TARGET) uds-server.c libconfuse.a

install: $(TARGET)
	install -s -D $(TARGET) $(DESTDIR)$(bindir)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(TARGET)

clean:
	rm -f $(TARGET)

distclean: clean

.PHONY : all debug install uninstall clean distclean