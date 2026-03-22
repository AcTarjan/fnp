FNP_ROOT ?= ../..
BUILD_DIR ?= $(FNP_ROOT)/build
DPDK_DIR ?= /opt/dpdk

CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra

CPPFLAGS += -I$(FNP_ROOT)/inc -I$(DPDK_DIR)/include
LDFLAGS += -Wl,--no-as-needed

FNP_API_STATIC := $(BUILD_DIR)/libfnp-api.a

LDLIBS += $(FNP_API_STATIC) -pthread -lm -ldl -lnuma -latomic

TARGETS := fnp-demo
SRCS := main.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGETS)

fnp-demo: main.o
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) $(OBJS) fnp-udp fnp-virt fnp-udp.o tmp_tun_create tmp_tun_create.c
