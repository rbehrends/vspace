CXXFLAGS=-g -std=c++11
BLD=build
BIN=bin
LIB=$(BLD)/vspace.o
HEADERS=vspace.h
SRC=$(wildcard example*.cc)
OBJ=$(patsubst %.cc,$(BLD)/%.o,$(SRC))
EXE=$(patsubst %.cc,$(BIN)/%,$(SRC))

$(shell mkdir -p $(BLD) $(BIN))

all: $(EXE)

$(EXE): $(BIN)/%: $(BLD)/%.o $(LIB)
	$(CXX) -g -o $@ $+
$(OBJ) $(LIB): $(BLD)/%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BLD) $(BIN)

.PHONY: clean
