CFLAGS=-g -O2 -Wall

sha: sha.c
	gcc $(CFLAGS) -DDEBUG -o $@ $^ ../lib/libthreshold.a

aes: aes.c
	gcc $(CFLAGS) -DDEBUG -o $@ $^ ../lib/libthreshold.a

clean:
	rm -f *.o
