CC=gcc

LIBPATH = /home/phil/repo/linux/tools/lib/traceevent
LIB = traceevent

FLAGS = -ldl -Wl

EXEC = my_proc

all: my_proc.c
	gcc -o $(EXEC) my_proc.c -I$(LIBPATH) -L$(LIBPATH) -l$(LIB) $(FLAGS),-rpath=$(LIBPATH)
clean:
	rm -f *.out $(EXEC)
