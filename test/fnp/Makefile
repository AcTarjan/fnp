FNP_ROOT ?= ../..
BUILD_DIR ?= $(FNP_ROOT)/build
DPDK_DIR ?= /opt/dpdk

CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra

DPDK_LIBDIR := $(shell if [ -d "$(DPDK_DIR)/lib/$(shell $(CC) -dumpmachine)" ]; then echo "$(DPDK_DIR)/lib/$(shell $(CC) -dumpmachine)"; elif [ -d "$(DPDK_DIR)/lib64" ]; then echo "$(DPDK_DIR)/lib64"; else echo "$(DPDK_DIR)/lib"; fi)

CPPFLAGS += -I$(FNP_ROOT)/inc -I$(DPDK_DIR)/include
LDFLAGS += -L$(BUILD_DIR) -L$(DPDK_LIBDIR) -Wl,-rpath,$(abspath $(BUILD_DIR)) -Wl,-rpath,$(DPDK_LIBDIR) -Wl,--no-as-needed
LDLIBS += -lfnp-api -pthread -lm -ldl -lnuma -lpcap \
	-lrte_pdump -lrte_timer -lrte_hash -lrte_cmdline -lrte_pci -lrte_ethdev \
	-lrte_mbuf -lrte_mempool -lrte_mempool_ring -lrte_rcu -lrte_ring -lrte_eal

TARGET := fnp-udp
SRCS := fnp-udp.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
