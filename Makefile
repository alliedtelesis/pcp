# Top level Makefile for firewall

PCP_ROOT?=$(shell pwd)
export PCP_ROOT

SUBDIRS = api pcpd

include $(PCP_ROOT)/common.mk
