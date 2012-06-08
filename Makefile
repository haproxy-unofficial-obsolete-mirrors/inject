OBJS     = inject injectl4

CC       = gcc
OPTS     = -Os -momit-leaf-frame-pointer
CPU      = -march=i686
CPU_OPTS = -mpreferred-stack-boundary=2 -falign-functions=1 -falign-loops=1 -falign-jumps=1
LD_OPTS  = -s
DEFINES  = -DENABLE_SPLICE -DENABLE_TRUNC
CFLAGS   = $(CPU) $(CPU_OPTS) $(OPTS) $(LD_OPTS) $(DEFINES)

all: $(OBJS)

inject: inject.c
	$(CC) $(CFLAGS) -o $@ $< -lm

injectl4: inject.c
	$(CC) $(CFLAGS) -o $@ $< -DDONT_ANALYSE_HTTP_HEADERS -lm

clean:
	rm -f $(OBJS) core *~ *.orig *.rej *.o

