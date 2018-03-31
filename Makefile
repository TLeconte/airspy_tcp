CFLAGS= -Wall -Ofast -pthread  `pkg-config --cflags libairspy`
LDLIBS= -lm -pthread  `pkg-config --libs libairspy` -lusb-1.0

airspy_tcp:	airspy_tcp.o
	$(CC) airspy_tcp.o -o $@ $(LDLIBS)

clean:
	@\rm -f *.o airspy_tcp
