CC = clang-cl
XWIN = $(HOME)/.xwin

CFLAGS = -w -g -01 -std=c11 \
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
  -Xlinker /ignore:4099 \
  -Xlinker -machine:x64 \
  -Xlinker -libpath:$(XWIN)/crt/lib/x86_64 \
  -Xlinker -libpath:./lib \
  -Xlinker -libpath:$(XWIN)/sdk/lib/um/x86_64 \
  -Xlinker -libpath:$(XWIN)/sdk/lib/ucrt/x86_64 \
  -Xlinker /DEFAULTLIB:rpcrt4.lib \
  -Xlinker /DEFAULTLIB:kernel32.lib \
  -Xlinker /DEFAULTLIB:advapi32.lib \
  -Xlinker /DEFAULTLIB:netapi32.lib \
  -Xlinker /DEFAULTLIB:secur32.lib \
  -Xlinker /DEFAULTLIB:uuid.lib \
  -Xlinker /DEFAULTLIB:oldnames.lib \
  -Xlinker /DEFAULTLIB:libcmt.lib \
  -Xlinker /DEFAULTLIB:libvcruntime.lib \
  -Xlinker /DEFAULTLIB:libucrt.lib \
  -Xlinker /DEFAULTLIB:dbghelp.lib \
  -Xlinker /DEFAULTLIB:wldap32.lib \
  -Xlinker /DEFAULTLIB:ole32.lib \
  -Xlinker /DEFAULTLIB:msasn1.min.lib \
  -Xlinker /DEFAULTLIB:ntdll.min.lib \
  -Xlinker /DEFAULTLIB:cryptdll.lib \
  -Xlinker /DEFAULTLIB:user32.lib




TARGET = munchy

SRCS = $(wildcard *.c) \
       $(wildcard ./include/*/*.c) \
       $(wildcard ./include/drsr/*.cpp) \
       $(wildcard ./include/argtable3/src/*.c)

OBJS = $(patsubst %.c,build/%.o,$(SRCS))

all: build/$(TARGET).exe

build/%.o: %.c
	@mkdir -p $(dir $@)
	cd include/tiny-AES-c && rm -f test.c
	$(CC) $(CFLAGS) -c $< -o $@

build/$(TARGET).exe: $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@
# 	$(CC) --target=x86_64-pc-windows-msvc $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf build

.PHONY: all clean
