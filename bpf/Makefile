CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Wno-unused-value -Wno-pointer-sign
LIBBPF_HEADERS ?= /usr/include

SRC := ebpfca.bpf.c
OBJ := ebpfca.bpf.o

.PHONY: all clean

all: $(OBJ)

$(OBJ): $(SRC) common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I$(LIBBPF_HEADERS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)
