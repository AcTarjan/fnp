TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH="/root/fstack-1.23"
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -I../../src/common/

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma

#SRC_FILES = udp_server.c
SRC_FILES = udp_client.c
SRC_FILES += ../../src/common/fnp_common.c

TARGET="fstack-udp-server"

all:
	cc ${CFLAGS} -DINET6 -o ${TARGET} ${SRC_FILES} ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET}
