#**********************************************************
#
# File: Makefile
# Created: 2022-09-28
# Last change: 2022-09-28
# Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>
# Project: Project for the course ISA - variant 1
#          - Generation of NetFlow data from captured
#            network traffic.
# Description: Makefile for NetFlow exporter
#
#**********************************************************

CC = gcc
# TODO uncomment options
CFLAGS = -std=gnu99 # -Wall -Wextra -Werror -pedantic -g
LDFLAGS = -lpcap
EXECUTABLE = flow
ERR = error
OPT = option
OBJS = $(EXECUTABLE).o $(ERR).o $(OPT).o
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

$(TAR_FILE): *.c *.h Makefile manual.pdf flow.1
	tar $(TAR_OPTIONS) $@ $^
