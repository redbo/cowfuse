C_FLAGS=-O3 -fomit-frame-pointer -s -Wall -Werror

all:
	gcc $(C_FLAGS) -D_FILE_OFFSET_BITS=64 -o cowfuse cowfuse.c -lfuse

