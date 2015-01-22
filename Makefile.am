# Top level Makefile for PCP

PCP_ROOT ?= $(shell pwd)
export PCP_ROOT

AUTOMAKE_OPTIONS = foreign
SUBDIRS = api pcpd

include $(PCP_ROOT)/common.mk

AM_CFLAGS = -Wall -Werror \
	    -I$(CROSS_DEV_ROOT_DIR)/usr/include/glib-2.0 \
	    -I$(CROSS_DEV_ROOT_DIR)/usr/lib/glib-2.0/include
AM_CPPFLAGS = \
	    -I. -I$(CROSS_DEV_ROOT_DIR)/usr/include/glib-2.0 \
	    -I$(CROSS_DEV_ROOT_DIR)/usr/lib/glib-2.0/include

if HAVE_UNITTEST
bin_PROGRAMS = packets_pcp_unit_tests libpcp_unit_tests

packets_pcp_unit_tests_SOURCES = tests/packets_pcp_unit_tests.c pcpd/packets_pcp_serialization.c pcpd/packets_pcp.c
packets_pcp_unit_tests_CFLAGS  = $(AM_CFLAGS) -g $(NOVAPROVA_CFLAGS)
packets_pcp_unit_tests_LDADD   = $(NOVAPROVA_LIBS) $(GLIBMM_LIBS) $(GOBJECT_LIBS) $(LIBXMLXX_LIBS) $(LIBXML_LIBS) $(SIGCXX_LIBS)

libpcp_unit_tests_SOURCES = tests/libpcp_unit_tests.c api/pcp.c
libpcp_unit_tests_CFLAGS  = $(AM_CFLAGS) -g $(NOVAPROVA_CFLAGS) -D_GNU_SOURCE
libpcp_unit_tests_LDADD   = $(NOVAPROVA_LIBS) $(GLIBMM_LIBS) $(GOBJECT_LIBS) $(LIBXMLXX_LIBS) $(LIBXML_LIBS) $(SIGCXX_LIBS)
libpcp_unit_tests_LDFLAGS = -lapteryx
endif
