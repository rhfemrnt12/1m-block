LDLIBS=-lnetfilter_queue

all: 1m_block

1m_block: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: 1m_block.cpp libnet-headers.h
	g++ -c -o main.o 1m_block.cpp -lnetfilter_queue
clean:
	rm -f 1m_block *.o
