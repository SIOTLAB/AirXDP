LIB_DIR ?= ../lib
CC:=gcc
CLANG:=clang
LLC:=llc
LDLIBS += -l:libxdp.a -l:libbpf.a -lpthread -lm -lelf -lz
OBJECT_LIBBPF = $(LIB_DIR)/install/lib/libbpf.a
LDFLAGS += -L$(LIB_DIR)/install/lib
OBJECT_LIBXDP = $(LIB_DIR)/install/lib/libxdp.a
CFLAGS += -I$(LIB_DIR)/install/include
BPF_CFLAGS += -I$(LIB_DIR)/install/include

XDP_TARGETS  := xdp_redirect_program
USER_TARGETS := psf

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

$(USER_TARGETS): %: %.c   
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) \
	 $< $(LDLIBS)

$(XDP_OBJ): %.o: %.c  
	$(QUIET_CLANG)$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

.PHONY: clean $(CLANG) $(LLC)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

all: llvm-check $(USER_TARGETS) $(XDP_OBJ)

clean:
	$(Q)rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) *.ll