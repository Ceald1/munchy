# 1. Variables: Define compiler, flags, and targets
CC = clang
CFLAGS = -Wall -Wextra -g -std=c11 -s -I/usr/x86_64-w64-mingw32/include -I./include/argtable3/src --target=x86_64-w64-windows-gnu
TARGET = $(target)

# 2. Source and Object Files: Automatically find .c files and name .o files
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# 3. Default Target: The first rule is run by default when you type 'make'
all: $(TARGET)

# 4. Link Step: Create the final executable from object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) ./include/argtable3/src/*.c -o $(TARGET) $(OBJS)
	mv *.exe ./build/

# 5. Compile Step: Pattern rule to build .o files from .c files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 6. Clean: Remove build artifacts to start fresh
clean:
	rm -f *.o *.exe *.dll
	rm ./build/*.exe ./build/*.dll

.PHONY: all clean

