CXX      = g++
CXXFLAGS = -Wall -Wextra -g -fno-stack-protector -D_FORTIFY_SOURCE=0

all: bank

bank: main.cpp
	$(CXX) $(CXXFLAGS) -o bank main.cpp

clean:
	rm -f bank
