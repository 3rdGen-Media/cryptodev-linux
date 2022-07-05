CFLAGS=-g -O2 -Wall
g
all: benchmark

benchmark: main.c libthreshold.a
	gcc $(CFLAGS) -DDEBUG -o $@ $^ -lssl -lcrypto libthreshold.a

.o:
	gcc $(CCFLAGS) -c $< -o $@

libthreshold.a: benchmark.o hash.o threshold.o
	ar  rcs $@ $^

clean:
	rm -f *.o *~ benchmark libthreshold.a
