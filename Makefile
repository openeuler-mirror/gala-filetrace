#dependencies: libcurl-devel libelf-dev libbpf-devel zlib-devel clang llvm bpftool nlohmann-json-devel

REQUIRED_TOOLS := clang llvm bpftool
REQUIRED_PKGS := libcurl-devel libelf-dev libbpf-devel zlib-devel

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
    TARGET_ARCH := arm64
endif

TARGETS := $(patsubst %.c,%.o,$(wildcard *.c))

CFLAGS = -Wno-error 
CFLAGS += -Wno-unknown-attributes
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -g0 -fno-asynchronous-unwind-tables
#CINCLUDE = -I/usr/src/kernels/5.10.0-136.32.0.108.iss22.aarch64
CINCLUDE = -I/usr/src/kernels/$(shell uname -r)

CLANG ?= clang
CLANGXX ?= clang++
LLC ?= llc

OUTPUT_DIR ?= output
BPF_OBJ := $(OUTPUT_DIR)/filetrace.bpf.o


all: $(TARGETS) filetrace.skel.h filetrace.o filetrace

.PHONY: clean

clean:
	@echo "Cleaning up ..."
	@rm -rf $(OUTPUT_DIR) filetrace filetrace.o filetrace.skel.h

$(TARGETS): %.o: %.c | $(OUTPUT_DIR)
	@echo "Compiling $< to $@ ..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@$(CLANG) -S $(CFLAGS) -D__TARGET_ARCH_$(TARGET_ARCH) -g -O2 -emit-llvm -c $<
	@$(LLC) -march=bpf -filetype=obj -o $(OUTPUT_DIR)/$@ ${@:.o=.ll}
	@rm ${@:.o=.ll}

# create skeleton include file
filetrace.skel.h: $(BPF_OBJ)
	@echo "Generating skeleton header file for BPF object ..."
	@bpftool gen skeleton $< > $@

#compile filetrace.cpp to filetrace.o
filetrace.o: filetrace.cpp 
	@echo "Compiling $< to $@ ..."
	@$(CLANGXX) -c $(CFLAGS) $(CINCLUDE) -I./ -o $(OUTPUT_DIR)/$@   $<

filetrace: $(OUTPUT_DIR)/filetrace.o
	@echo "Linking filetrace.o to filetrace ..."
	@$(CLANGXX) -o $@ $< -lelf -lz -lbpf -I./ $(CINCLUDE) $(CFLAGS)
	
$(OUTPUT_DIR):
	@mkdir $(OUTPUT_DIR)
