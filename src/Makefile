CC=gcc

LIBPATH = /home/phil/repo/linux/tools/lib/traceevent
LIB = traceevent

FLAGS = -ldl

EXEC = my_proc

LINKERARGS = -Wl,-rpath=$(LIBPATH)

$(EXEC): my_proc.c
	gcc -o $@ $^ -I$(LIBPATH) -L$(LIBPATH) -l$(LIB) $(FLAGS) $(LINKERARGS)
clean:
	rm -f $(EXEC)
