C=gcc
CFLAGS= -O1 -Wall
all:
	$(CC) $(CFLAGS) -Iutil.h client_PFS.c -o client_PFS -lssl -lcrypto
	$(CC) $(CFLAGS) -Iutil.h server_PFS.c -o server_PFS -lssl -lcrypto

client:
	$(CC) $(CFLAGS) -Iutil.h client_PFS.c -o client_PFS -lssl -lcrypto

server:
	$(CC) $(CFLAGS) -Iutil.h server_PFS.c -o server_PFS -lssl -lcrypto

clean:
	        $(RM) server_PFS client_PFS
