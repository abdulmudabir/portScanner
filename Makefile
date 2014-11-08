CC = g++
CPFLAGS = -g -Wall -Wextra
LDFLAGS = -lm -pthread

SRC = portScanner.cpp ps_lib.cpp
OBJ = $(SRC:.cpp=.o)
BIN = portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) $(OBJ) -o $(BIN)

%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)