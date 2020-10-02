CXXFLAGS=-g -std=c++11
OBJ=vspace.o
EXE=example example2
all: $(EXE)
%: %.o vspace.o
	$(CXX) -g -o $@ $+

example.o: example.cc vspace.h
example2.o: example2.cc vspace.h
vspace.o: vspace.cc vspace.h

clean:
	rm -f $(EXE) $(OBJ)

.PHONY: clean
