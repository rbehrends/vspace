CXXFLAGS=-g -std=c++11
OBJ=example.o vspace.o
EXE=example
all: $(EXE)
$(EXE): $(OBJ)
	$(CXX) -g -o $(EXE) $(OBJ)

example.o: example.cc vspace.h
vspace.o: vspace.cc vspace.h

clean:
	rm -f $(EXE) $(OBJ)

.PHONY: clean
