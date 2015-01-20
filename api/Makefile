PCP_ROOT ?= ../

LIBRARY := libpcp

SRC_C := pcp.c

EXTRA_CFLAGS = -I$(PCP_ROOT)/../apteryx
EXTRA_CFLAGS += -I. `$(PKG_CONFIG) --cflags glib-2.0`
EXTRA_LDFLAGS = -L$(PCP_ROOT)/../apteryx/
EXTRA_LDFLAGS += `$(PKG_CONFIG) --libs glib-2.0` -lapteryx

all: $(LIBRARY).so

install: all
	@install -D $(LIBRARY).so $(DESTDIR)/$(PREFIX)/lib/$(LIBRARY).so
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D $(LIBRARY).h $(DESTDIR)/$(PREFIX)/include/$(LIBRARY).h

clean:
	@echo "Cleaning..."
	@rm -fr $(OBJDIR) $(LIBRARY).a $(LIBRARY).so $(TEST_APPS)

.PHONY: all install test clean

include $(PCP_ROOT)/common.mk

