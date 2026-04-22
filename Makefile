#CC = clang
#
#CFLAGS = -Wall -Wextra -g -std=c11 \
#-I./include/argtable3/src \
#-I./include \
#-I./include/tiny-AES-c \
#--target=x86_64-pc-windows-msvc \
#--sysroot=/opt/xwin
#
#
#TARGET = munchy
#
## include ALL source files explicitly
#SRCS = $(wildcard *.c) \
#       $(wildcard ./include/*/*.c) \
#       $(wildcard ./include/argtable3/src/*.c)
#
#
#OBJS = $(SRCS:.c=.o)
#
#all: $(TARGET)
#
## LINK step (ONLY objects, no .c files!)
#$(TARGET): $(OBJS)
#	cd ./include/tiny-AES-c && rm -f test.c 
#	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) -L/usr/x86_64-w64-mingw32/lib -ldbghelp -lntdll -lrpcrt4 -ladvapi32 -lnetapi32 -s 
#	mkdir -p ./build
#	mv $(TARGET).exe ./build/
#
## COMPILE step
#%.o: %.c
#	$(CC) $(CFLAGS) -c $< -o $@
#
#clean:
#	rm -f $(OBJS)
#	rm -f ./build/*
#
#.PHONY: all clean


CC = clang-cl
XWIN = $(HOME)/.xwin

CFLAGS = -Wall -Wextra -g -std=c11 \
  --target=x86_64-pc-windows-msvc \
  -imsvc $(XWIN)/crt/include \
  -imsvc $(XWIN)/sdk/include/ucrt \
  -imsvc $(XWIN)/sdk/include/um \
  -imsvc $(XWIN)/sdk/include/shared \
  -I./include/argtable3/src \
  -I./include \
  -I./include/tiny-AES-c


LDFLAGS = \
  -fuse-ld=lld-link \
  -Xlinker -machine:x64 \
  -Xlinker -libpath:$(XWIN)/crt/lib/x86_64 \
  -Xlinker -libpath:$(XWIN)/sdk/lib/um/x86_64 \
  -Xlinker -libpath:$(XWIN)/sdk/lib/ucrt/x86_64 \
  -Xlinker rpcrt4.lib \
  -Xlinker kernel32.lib \
  -Xlinker advapi32.lib \
  -Xlinker netapi32.lib \
  -Xlinker secur32.lib \
  -Xlinker uuid.lib \
  -Xlinker oldnames.lib \
  -Xlinker libcmt.lib \
  -Xlinker libvcruntime.lib \
  -Xlinker libucrt.lib \
  -Xlinker dbghelp.lib

#LDFLAGS = \
#  -fuse-ld=lld-link \
#  -Xlinker -machine:x64 \
#  -Xlinker -libpath:$(XWIN)/crt/lib/x86_64 \
#  -Xlinker -libpath:$(XWIN)/sdk/lib/um/x86_64 \
#  -Xlinker -libpath:$(XWIN)/sdk/lib/ucrt/x86_64 \
#  -Xlinker rpcrt4.lib \
#  -Xlinker kernel32.lib \
#  -Xlinker advapi32.lib \
#  -Xlinker netapi32.lib \
#  -Xlinker secur32.lib \
#  -Xlinker uuid.lib \
#  -Xlinker oldnames.lib \
#  -Xlinker libcmt.lib \
#  -Xlinker libvcruntime.lib \
#  -Xlinker libucrt.lib


TARGET = munchy

SRCS = $(wildcard *.c) \
       $(wildcard ./include/*/*.c) \
       $(wildcard ./include/argtable3/src/*.c)

OBJS = $(patsubst %.c,build/%.o,$(SRCS))

all: build/$(TARGET).exe

build/%.o: %.c
	@mkdir -p $(dir $@)
	cd include/tiny-AES-c && rm -f test.c
	$(CC) $(CFLAGS) -c $< -o $@

build/$(TARGET).exe: $(OBJS)
	@mkdir -p build
	$(CC) --target=x86_64-pc-windows-msvc $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf build

.PHONY: all clean
