CFLAGS = -g -g3 -O0 -Werror -Wall 

CC = gcc

EXEC = my_proc

LDFLAGS = -shared

LIBPATH = /usr/local/lib64/


my_proc: my_proc.c
	$(CC) -o $(EXEC) $(LIBPATH)libtraceevent.so my_proc.c $(LDFLAGS)

clean:
	rm -f my_proc.o $(EXEC)

