CFLAGS = -Wall -Werror -std=c11
CC = gcc

scc: scc.c

test: scc
	./test.sh

clean:
	rm -f scc *.o *~ tmp*