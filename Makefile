CFLAGS = -Wall -Wno-unused-function -Wtype-limits -DUSE_SSL -DUSE_THREAD -D_XOPEN_SOURCE=700 -D_ISOC99_SOURCE  -g -O2 -Wall -D_FILE_OFFSET_BITS=64 -I/root/xiayi/libfuse-fuse-2.9.9/include
CFLAGS += -DFAST_PARSER
CFLAGS += -DSET_REALTIME
CFLAGS += -DDEBUG
LDFLAGS = -L. -L/usr/lib/i386-linux-gnu/
LIBS = -lfuse -lpthread -ldl -lcrypto -lssl
httpfs2:http_parser.c httpfs2.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)
clean:
	rm -rf *.o httpfs2

