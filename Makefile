CC         = gcc
CFLAGS    ?= -O2 -pipe -Wall -Wextra -Wno-variadic-macros -Wno-strict-aliasing
PKGCONFIG  = pkg-config
STRIP      = strip
INSTALL    = install
UNAME      = uname

OS         = $(shell $(UNAME))
CFLAGS    += $(shell $(PKGCONFIG) --cflags lem)
LUA_PATH   = $(shell $(PKGCONFIG) --variable=path lem)
LUA_CPATH  = $(shell $(PKGCONFIG) --variable=cpath lem)

ifeq ($(OS),Darwin)
SHARED     = -dynamiclib -Wl,-undefined,dynamic_lookup
STRIP_ARGS = -u -r
else
SHARED     = -shared
endif

programs = ssl.so
#scripts  = hathaway.lua

ifdef NDEBUG
CFLAGS += -DNDEBUG
endif

.PHONY: all strip install clean
.PRECIOUS: %.o

all: $(programs)

%.o: %.c
	@echo '  CC $@'
	@$(CC) $(CFLAGS) -fPIC -nostartfiles -c $< -o $@

ssl.o: ssl.c stream.c context.c
	@echo '  CC $@'
	@$(CC) $(CFLAGS) -fPIC -nostartfiles -c $< -o $@

%.so: %.o
	@echo '  LD $@'
	@$(CC) $(SHARED) -lssl $(LDFLAGS) $^ -o $@

%-strip: %
	@echo '  STRIP $<'
	@$(STRIP) $(STRIP_ARGS) $<

strip: $(programs:%=%-strip)

path-install:
	@echo "  INSTALL -d $(LUA_PATH)/lem"
	@$(INSTALL) -d $(DESTDIR)$(LUA_PATH)/lem

%.lua-install: %.lua path-install
	@echo "  INSTALL $<"
	@$(INSTALL) -m644 $< $(DESTDIR)$(LUA_PATH)/lem/$<

cpath-install:
	@echo "  INSTALL -d $(LUA_CPATH)/lem"
	@$(INSTALL) -d $(DESTDIR)$(LUA_CPATH)/lem

ssl.so-install: ssl.so cpath-install
	@echo "  INSTALL $<"
	@$(INSTALL) $< $(DESTDIR)$(LUA_CPATH)/lem/$<

%.so-install: %.so cpath-install
	@echo "  INSTALL $<"
	@$(INSTALL) $< $(DESTDIR)$(LUA_CPATH)/lem/ssl/$<

install: $(programs:%=%-install) $(scripts:%=%-install)

clean:
	rm -f $(programs) *.o *.c~ *.h~
