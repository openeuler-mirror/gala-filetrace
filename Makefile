REQUIRED_TOOLS := clang llvm bpftool
REQUIRED_PKGS := libcurl-devel libbpf-devel zlib-devel nlohmann-json-devel bpftool clang llvm
REQUIRED_FILES := /usr/include/httplib.h

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
CFLAGS += -ferror-limit=5
CFLAGSPLUS += -std=c++17
ifeq ($(DEBUG),1)
    CXXFLAGS += -DDEBUG
    CFLAGS += -DDEBUG
endif


# Linker flags: prefer /usr/local/lib64 if present (where you said prometheus-cpp is installed)
LDFLAGS = -lelf -lcurl -lbpf -lcpp-httplib -lprometheus-cpp-core  -lprometheus-cpp-push -lprometheus-cpp-pull
EXTRA_LIBDIRS := $(shell [ -d /usr/local/lib64 ] && echo -L/usr/local/lib64 || echo )
#EXTRA_LIBDIRS += $(shell [ -d /usr/local/lib ] && echo -L/usr/local/lib || echo )
LDFLAGS += $(EXTRA_LIBDIRS)

CINCLUDE = -I./
CINCLUDE += -I/usr/local/include/
#CINCLUDE += -I/usr/src/kernels/$(shell uname -r)

CLANG ?= clang
CLANGXX ?= clang++
LLC ?= llc

OUTPUT_DIR ?= output
BPF_OBJ := $(OUTPUT_DIR)/filetrace.bpf.o


all: $(TARGETS) filetrace.skel.h filetrace.o exporter.o post.o logger.o filetrace

.PHONY: clean

clean:
	@echo "Cleaning up ..."
	@rm -rf $(OUTPUT_DIR) filetrace filetrace.o filetrace.skel.h

$(TARGETS): %.o: %.c | $(OUTPUT_DIR)
	@echo "Compiling $< to $@ ..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@#$(CLANG) -S $(CFLAGS) -D__TARGET_ARCH_$(TARGET_ARCH) -g -O2 -emit-llvm -c $<
	@#$(LLC) -march=bpf -filetype=obj -o $(OUTPUT_DIR)/$@ ${@:.o=.ll}
	@#rm ${@:.o=.ll}
	@$(CLANG) -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) $(CFLAGS) -g -O2 -c $< -o $(OUTPUT_DIR)/$@

# create skeleton include file
filetrace.skel.h: $(BPF_OBJ)
	@echo "Generating skeleton header file for BPF object ..."
	@bpftool gen skeleton $< > $@

#compile filetrace.cpp to filetrace.o
filetrace.o: filetrace.cpp 
	@echo "Compiling $< to $@ ..."
	@$(CLANGXX) -c $(CFLAGS) $(CFLAGSPLUS) $(CINCLUDE)  -o $(OUTPUT_DIR)/$@ $<

logger.o: logger.cpp
	@echo "Compiling logger.cpp to logger.o ..."
	@$(CLANGXX) -c $(CFLAGS) $(CFLAGSPLUS) $(CINCLUDE) -o $(OUTPUT_DIR)/$@ $<

exporter.o: exporter.cpp
	@echo "Compiling exporter.cpp to exporter.o ..."
	@$(CLANGXX)  -c $(CFLAGS) $(CFLAGSPLUS)  $(CINCLUDE) -o $(OUTPUT_DIR)/$@ $<

post.o: post.cpp $(OUTPUT_DIR)/exporter.o
	@echo "Compiling post.cpp to post.o ..."
	@$(CLANGXX) -c $(CFLAGS) $(CFLAGSPLUS)  $(CINCLUDE) -o $(OUTPUT_DIR)/$@ $<

filetrace: $(OUTPUT_DIR)/filetrace.o $(OUTPUT_DIR)/exporter.o $(OUTPUT_DIR)/post.o $(OUTPUT_DIR)/logger.o
	@echo "Linking filetrace.o exporter.o post.o to filetrace ..."
	@$(CLANGXX)  $(PROM_LIBS) $(LDFLAGS) $(CINCLUDE) $(CFLAGS)  $(CFLAGSPLUS) -o $@ $^

$(OUTPUT_DIR):
	@mkdir $(OUTPUT_DIR)

install:
	@install -d $(DESTDIR)/usr/bin
	@install -m 755 filetrace $(DESTDIR)/usr/bin/filetrace
	@install -d $(DESTDIR)/etc/gala-filetrace
	@install -m 644 config/gala-filetrace.json $(DESTDIR)/etc/gala-filetrace/gala-filetrace.json
	@install -d $(DESTDIR)/usr/lib/systemd/system
	@install -m 644 config/gala-filetrace.service $(DESTDIR)/usr/lib/systemd/system/gala-filetrace.service

deps:
	@for tool in $(REQUIRED_TOOLS); do \
			if ! command -v $$tool >/dev/null 2>&1; then \
					echo "Missing tool: $$tool. Installing..."; \
					sudo yum install -y $$tool; \
			else \
					echo "Found tool: $$tool"; \
			fi \
	done
	@for pkg in $(REQUIRED_PKGS); do \
			if ! rpm -q $$pkg >/dev/null 2>&1; then \
					echo "Missing package: $$pkg. Installing..."; \
					sudo yum install -y $$pkg; \
			else \
					echo "Found package: $$pkg"; \
			fi \
	done
	@for path in $(REQUIRED_FILES); do \
			if ! test -s $$path >/dev/null 2>&1; then \
					echo "Missing file: $$path. Installing..."; \
					sudo yum install -y $$path; \
			else \
					echo "Found file: $$path"; \
			fi \
	done
