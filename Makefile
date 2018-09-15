# CROSS_COMPILE ?= aarch64-linux-gnu-

CC = $(CROSS_COMPILE)gcc
CFLAGS = -march=armv8-a+crypto+crc+lse -O0 -g

all: tb

tb: asimd_aes.o
