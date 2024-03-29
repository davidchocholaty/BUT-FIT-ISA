#**********************************************************
#
# File: Makefile
# Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>
# Project: Project for the course ISA - variant 1
#          - Generation of NetFlow data from captured
#            network traffic.
# Description: Makefile for NetFlow exporter
#
#**********************************************************

CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic -g
LDFLAGS = -lpcap
EXECUTABLE = flow
ERR = error
OPT = option
UTIL = util
MEM = memory
PCAP = pcap
NFV5 = netflow_v5
TREE = tree
OBJS = $(EXECUTABLE).o $(ERR).o $(OPT).o $(UTIL).o $(MEM).o $(PCAP).o $(NFV5).o $(TREE).o
LOGIN = xchoch09
TAR_FILE = $(LOGIN).tar
TAR_OPTIONS =  --exclude-vcs -cvf

.PHONY: all pack run clean

all: $(EXECUTABLE)

pack: $(TAR_FILE)

run: $(EXECUTABLE)
	./$(EXECUTABLE) $(ARGS)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE) *.o $(TAR_FILE)

$(TAR_FILE): *.c *.h Makefile manual.pdf flow.1 README
	tar $(TAR_OPTIONS) $@ $^
