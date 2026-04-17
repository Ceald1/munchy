## 1. Variables: Define compiler, flags, and targets
#CC = clang
#CFLAGS = -Wall -Wextra -g -std=c11 -s -I/usr/x86_64-w64-mingw32/include -I./include/argtable3/src -I./include --target=x86_64-w64-windows-gnu
#TARGET = $(target)
#
## 2. Source and Object Files: Automatically find .c files and name .o files
#SRCS = $(wildcard *.c)
#OBJS = $(SRCS:.c=.o)
#
## 3. Default Target: The first rule is run by default when you type 'make'
#all: $(TARGET)
#
## 4. Link Step: Create the final executable from object files
#$(TARGET): $(OBJS)
#	$(CC) $(CFLAGS) ./include/*.c ./include/argtable3/src/*.c -o $(TARGET) $(OBJS)
#	mkdir -p ./build
#	mv *.exe ./build/
#
## 5. Compile Step: Pattern rule to build .o files from .c files
#%.o: %.c
#	$(CC) $(CFLAGS) -c $< -o $@
#
## 6. Clean: Remove build artifacts to start fresh
#clean:
#	rm -f *.o *.exe *.dll
#	rm ./build/*.exe ./build/*.dll
#
#.PHONY: all clean
#
#
CC = clang

CFLAGS = -Wall -Wextra -g -std=c11 -s \
-I/usr/x86_64-w64-mingw32/include \
-I./include/argtable3/src \
-I./include \
-I./include/tiny-AES-c \
--target=x86_64-w64-windows-gnu

TARGET = munchy

# include ALL source files explicitly
SRCS = $(wildcard *.c) \
       $(wildcard ./include/*.c) \
       $(wildcard ./include/argtable3/src/*.c) \
       $(wildcard ./include/tiny-AES-c/*.c)

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

# LINK step (ONLY objects, no .c files!)
$(TARGET): $(OBJS)
	cd ./include/tiny-AES-c && rm -f test.c 
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) -ldbghelp
	mkdir -p ./build
	mv $(TARGET).exe ./build/

# COMPILE step
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
	rm -f ./build/*

.PHONY: all clean
