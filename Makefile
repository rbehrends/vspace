CXXFLAGS=-g -std=c++11
BLD=build
LIB=$(BLD)/vspace.o
HEADERS=vspace.h
SRC=$(wildcard example*.cc)
OBJ=$(patsubst %.cc,$(BLD)/%.o,$(SRC))
EXE=$(patsubst %.cc,%,$(SRC))

$(shell mkdir -p $(BLD))

all: $(EXE)

$(EXE): %: build/%.o $(LIB)
	$(CXX) -g -o $@ $+
$(OBJ) $(LIB): $(BLD)/%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(EXE) $(BLD)

.PHONY: clean
