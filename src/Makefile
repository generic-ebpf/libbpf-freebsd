CFLAGS= \
	-O2 \
	-Wall

OBJS= \
	bpf.o \
	libbpf.o

libbpf.a: $(OBJS)
	ar rc $@ $(OBJS)

clean:
	- rm -f $(OBJS) libbpf.a
