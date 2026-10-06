# VISTA eBPF Program Makefile
# Requires: clang, llvm, libbpf-dev, linux-headers-$(uname -r)

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
          -I/usr/include/$(shell uname -m)-linux-gnu \
          -Wall -Werror

TARGET := vista_ipsec_monitor.bpf.o
SOURCE := vista_ipsec_monitor.bpf.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CLANG) $(CFLAGS) -c $< -o $@

skeleton: $(TARGET)
	$(BPFTOOL) gen skeleton $(TARGET) > vista_ipsec_monitor.skel.h

clean:
	rm -f $(TARGET) vista_ipsec_monitor.skel.h

.PHONY: all clean skeleton
