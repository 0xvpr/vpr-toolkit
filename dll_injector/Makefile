# Makeflags += silent

TARGET=dll_injector

CC=-w64-mingw32-gcc
CFLAGS=-std=c99 -Wall -Werror -Wextra -O2 -s \
	   -Wno-unused-parameter -Wno-int-conversion -Wno-pointer-to-int-cast

CC32=$(addprefix i686, $(CC))
CC64=$(addprefix x86_64, $(CC))

BIN=bin
SRC=src
OBJ=build
SRCS=$(wildcard $(SRC)/*.c)

INCLUDE=include
INCLUDES=$(addprefix -I, $(INCLUDE))

all: $(TARGET)

$(TARGET): $(OBJ) $(BIN)
	$(CC32) $(CFLAGS) $(SRCS) $(INCLUDES) -o $(BIN)/$(TARGET)32.exe
	$(CC64) $(CFLAGS) $(SRCS) $(INCLUDES) -o $(BIN)/$(TARGET)64.exe

$(OBJ):
	mkdir -p $@

$(BIN):
	mkdir -p $@

clean:
	rm $(OBJ)/*
	rm $(BIN)/*
