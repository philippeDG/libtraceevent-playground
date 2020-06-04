CC=gcc

LIBPATH = /home/phil/repo/linux/tools/lib/traceevent
LIB = traceevent

LDFLAGS = -ldl -L$(LIBPATH) -l$(LIB) -Wl,-rpath=$(LIBPATH) -lglib-2.0

EXEC = traceevent_playground

CFLAGS=-g -I$(LIBPATH) -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

$(EXEC): parse_file.o
	gcc -o $@ $^ $(LDFLAGS)

parse_file.o: parse_file.c
	gcc -c $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(EXEC) *.o
