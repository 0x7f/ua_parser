UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CXX=g++-4.9
endif
ifeq ($(UNAME_S),Darwin)
	CXX=clang++
endif

CXXFLAGS=-I.
CXXFLAGS+=-std=c++14
CXXFLAGS+=-Werror -Wextra -Wall -Wno-unused-parameter -Wmissing-declarations

.PHONY: test
test: test/test.cpp ua_parser.hpp
	$(CXX) $(CXXFLAGS) test/test.cpp -lgtest -ljsoncpp -o test/test
	./test/test

clean:
	rm -f test/test
