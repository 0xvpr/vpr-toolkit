TARGET=dll_injector

CC=gcc
LD=gcc
CFLAGS=-std=c99 -Wall -Wextra -O2 -static -s
LDFLAGS=-lmingw32

CC32=$(addprefix i686-w64-mingw32-, $(CC))
CC64=$(addprefix x86_64-w64-mingw32-, $(CC))
LD32=$(addprefix i686-w64-mingw32-, $(LD))
LD64=$(addprefix x86_64-w64-mingw32-, $(LD))

BIN=bin

SRC=src
OBJ=build
32OBJ=$(OBJ)/x86
64OBJ=$(OBJ)/x64
SRCS=$(wildcard $(SRC)/*.c)
32OBJS=$(patsubst $(SRC)/%.c, $(32OBJ)/%.o, $(SRCS))
64OBJS=$(patsubst $(SRC)/%.c, $(64OBJ)/%.o, $(SRCS))

INCLUDE=include
INCLUDES=$(addprefix -I, $(INCLUDE))

all: $(TARGET)

$(TARGET): $(32OBJ) $(32OBJS) $(64OBJ) $(64OBJS) $(OBJ) $(BIN)
	$(LD32) $(32OBJS) $(LDFLAGS) -o $(BIN)/$(TARGET)_x86.exe
	$(LD64) $(64OBJS) $(LDFLAGS) -o $(BIN)/$(TARGET)_x64.exe

$(32OBJS): $(32OBJ)/%.o : $(SRC)/%.c
	$(CC32) $(CFLAGS) $(INCLUDES) -c $^ -o $@

$(64OBJS): $(64OBJ)/%.o : $(SRC)/%.c
	$(CC64) $(CFLAGS) $(INCLUDES) -c $^ -o $@

$(32OBJ):
	mkdir -p $@

$(64OBJ):
	mkdir -p $@

$(BIN):
	mkdir -p $@

clean:
	rm -fr $(OBJ)
	rm -fr $(BIN)/*.exe
