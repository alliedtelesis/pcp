PCP_ROOT ?= ../

SRC_C := pcpd.c packets_pcp.c packets_pcp_serialization.c

EXTRA_CFLAGS = -I. `$(PKG_CONFIG) --cflags glib-2.0` -I../api
EXTRA_CFLAGS += -I$(CROSS_DEV_ROOT_DIR)/usr/include/glib-2.0
EXTRA_CFLAGS += -I$(CROSS_DEV_ROOT_DIR)/usr/lib/glib-2.0/include
EXTRA_LDFLAGS ?= -L../../apteryx -lapteryx -lglib-2.0
EXTRA_LDFLAGS += `$(PKG_CONFIG) --libs-only-l glib-2.0` -L../api -lpcp -lpthread

all: pcpd

install: all
	install -D pcpd $(DESTDIR)/$(PREFIX)/sbin/pcpd

pcpd: $(SRC_C)
	@echo "Building pcpd"
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) -o $@ $(SRC_C) $(EXTRA_LDFLAGS)

clean:
	@echo "Cleaning..."
	@rm -fr $(OBJDIR) pcpd

.PHONY: all install test clean

include $(PCP_ROOT)/common.mk
