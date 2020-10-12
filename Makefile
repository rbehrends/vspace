CXXFLAGS=-g -std=c++11
BLD=build
BIN=bin
LIB=$(BLD)/vspace.o
HEADERS=vspace.h
TESTS=tests
SRC=$(wildcard $(TESTS)/*.cc)
OBJ=$(patsubst $(TESTS)/%.cc,$(BLD)/%.o,$(SRC))
EXE=$(patsubst $(TESTS)/%.cc,$(BIN)/%,$(SRC))

$(shell mkdir -p $(BLD) $(BIN))

all: $(EXE)

$(EXE): $(BIN)/%: $(BLD)/%.o $(LIB)
	$(CXX) -g -o $@ $+
$(OBJ): $(BLD)/%.o: $(TESTS)/%.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. -c -o $@ $<
$(LIB): $(BLD)/%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BLD) $(BIN)

.PHONY: clean
