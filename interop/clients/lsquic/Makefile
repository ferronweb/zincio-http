CC = gcc
CXX = g++

BORINGSSL_DIR ?= boringssl
LSQUIC_DIR ?= lsquic
# Directory holding the configured lsquic build tree. Defaults to in-tree;
# point this at an out-of-source build (e.g. lsquic-build) when one exists.
LSQUIC_BUILD_DIR ?= $(LSQUIC_DIR)

CFLAGS = -Wall -Wextra -O2 -g
CPPFLAGS = -I $(BORINGSSL_DIR)/include -I $(LSQUIC_DIR)/include

TARGET = interop-driver-lsquic
SRCS = main.c endpoint.c
OBJS = $(SRCS:.c=.o)

LSQUIC_LIB = $(LSQUIC_BUILD_DIR)/src/liblsquic/liblsquic.a
BORINGSSL_LIBS = $(BORINGSSL_DIR)/libssl.a $(BORINGSSL_DIR)/libcrypto.a

all: $(TARGET)

$(TARGET): $(OBJS) $(LSQUIC_LIB) $(BORINGSSL_LIBS)
	$(CXX) $(CFLAGS) -o $@ $(OBJS) $(LSQUIC_LIB) $(BORINGSSL_LIBS) \
		-lstdc++ -lm -lz -lpthread

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
