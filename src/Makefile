CC=gcc

LIBPATH = /home/phil/repo/linux/tools/lib/traceevent
LIB = traceevent

LDFLAGS = -L$(LIBPATH) -l$(LIB) -ldl -Wl,-rpath=$(LIBPATH) -lglib-2.0 -fsanitize=address

EXEC = traceevent_playground

CFLAGS=-g -I$(LIBPATH) -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -fsanitize=address

$(EXEC): parse_file.o
	gcc -o $@ $^ $(LDFLAGS)

parse_file.o: parse_file.c
	gcc -c $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(EXEC) *.o
