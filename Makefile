LUA_PREFIX = /usr/local/
PREFIX	= /usr/local/
MODULE = luadns
VERSION = 1.0.0

INSTALL_PREFIX = $(PREFIX)/lib/lua/5.1/

CC	= gcc
TARGET	= dns.so
OBJS	= dns.o
LIBS	= -lresolv
CFLAGS	= -I $(LUA_PREFIX)/include -fPIC
LDFLAGS	= -shared -fPIC

default: $(TARGET)


install: default
	install -d $(INSTALL_PREFIX)
	install $(TARGET) $(INSTALL_PREFIX)

clean:
	rm -rf $(OBJS) $(TARGET) $(MODULE)-$(VERSION)

package: clean
	mkdir $(MODULE)-$(VERSION)
	cp dns.c COPYING Makefile $(MODULE)-$(VERSION)
	tar cvzf $(MODULE)-$(VERSION).tar.gz $(MODULE)-$(VERSION)
	rm -rf $(MODULE)-$(VERSION)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
