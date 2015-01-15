# Common Makefile components
BUILDDIRS = $(SUBDIRS:%=build-%)
INSTALLDIRS = $(SUBDIRS:%=install-%)
CLEANDIRS = $(SUBDIRS:%=clean-%)
TOOLDIRS = $(SUBDIRS:%=tool-%)
TOOLAPPDIRS = $(SUBDIRS:%=tool-apps-%)
TESTDIRS = $(SUBDIRS:%=test-%)
TESTAPPDIRS = $(SUBDIRS:%=test-apps-%)

PATHS?=.
SRCDIR?=.
OBJDIR?=.obj
PREFIX?=/usr/
DESTDIR?=./
PKG_CONFIG?=pkg-config
LD_LIBRARY_PATH:="$(PCP_ROOT)/../apteryx"
TEST_APPS?=

CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld

SRCS=$(SRC_C:%.c=$(SRCDIR)/%.c)
OBJS+=$(SRC_C:%.c=$(OBJDIR)/%.o)
DIRS+=$(PATHS:%=$(OBJDIR)/%/)

CFLAGS := -g -O2 -Wall

EXTRA_CFLAGS += -fPIC -Wno-comment -std=c99 -D_GNU_SOURCE

$(DIRS):
	@mkdir -p $@

$(LIBRARY).so: $(DIRS) $(OBJS)
	@echo "Creating library "$@""
	@$(CC) $(LDFLAGS) --shared -o $@ $(OBJS) $(EXTRA_LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@echo "Compiling "$<""
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@
	@$(CC) -MM $(CFLAGS) $(EXTRA_CFLAGS) $< > $(OBJDIR)/$*.d

apteryxd = \
	if test -e /tmp/apteryxd.pid; then \
		kill -TERM `cat /tmp/apteryxd.pid` && sleep 0.1; \
	fi; \
	rm -f /tmp/apteryxd.pid; \
	LD_LIBRARY_PATH=$(PCP_ROOT)/../apteryx $(PCP_ROOT)/../apteryx/apteryxd -b -p /tmp/apteryxd.pid && sleep 0.1; \
	LD_LIBRARY_PATH=$(PCP_ROOT)/../apteryx:./ $(TEST_WRAPPER) ./$(1); \
	kill -TERM `cat /tmp/apteryxd.pid`;

all: $(BUILDDIRS)
$(DIRS): $(BUILDDIRS)
$(BUILDDIRS):
	$(MAKE) -C $(@:build-%=%)

install: $(INSTALLDIRS) all
$(INSTALLDIRS):
	$(MAKE) -C $(@:install-%=%) install

install-tools: $(TOOLAPPDIRS) $(TOOLS)
	for i in $(TOOLS) ; do \
		install -D $$i $(DESTDIR)/$(PREFIX)/bin/$$i ; \
	done

$(TOOLAPPDIRS):
	$(MAKE) -C $(@:tool-apps-%=%) install-tools

tools: $(TOOLDIRS) $(TOOLS)
$(TOOLDIRS):
	$(MAKE) -C $(@:tool-%=%) tools

test: $(TESTDIRS)
$(TESTDIRS):
	$(MAKE) -C $(@:test-%=%) test

install-test: $(TESTAPPDIRS) $(TEST_APPS)
	for i in $(TEST_APPS) ; do \
		install -D $$i $(DESTDIR)/$(PREFIX)/bin/$$i ; \
	done

$(TESTAPPDIRS):
	$(MAKE) -C $(@:test-apps-%=%) install-test

clean: $(CLEANDIRS)
$(CLEANDIRS):
	$(MAKE) -C $(@:clean-%=%) clean

.PHONY: subdirs $(DIRS)
.PHONY: subdirs $(BUILDDIRS)
.PHONY: subdirs $(INSTALLDIRS)
.PHONY: subdirs $(TOOLDIRS)
.PHONY: subdirs $(TESTDIRS)
.PHONY: subdirs $(CLEANDIRS)
.PHONY: all install clean tool test
