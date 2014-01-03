#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include "util.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ./server_PFS <port number> <private key> <certificate of server> <CA sert>
int main(int argc, char const *argv[])
{
	int i, j;
	// ssl setup
	SSL_CTX *ctx;
	SSL *ssl[MAX];
	SSL_METHOD *meth;

	// Load encryption & hashing algorithms for the SSL program
	SSL_library_init();
	// Load the error strings for SSL & CRYPTO APIs
	SSL_load_error_strings();
	// Create a SSL_METHOD structure (choose a SSL/TLS protocol version)
	meth = SSLv3_method();
	// Create a SSL_CTX structure
	ctx = SSL_CTX_new(meth);
	if(!ctx)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// Load the server certificate into the SSL_CTX structure
	if(SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// Load the private-key corresponding to the server certificate
	if(SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// Check if the server certificate and private-key matches
	if(!SSL_CTX_check_private_key(ctx))
	{
		printf("Private key does not match the certificate public key\n");
		exit(1);
	}
	// Load the RSA CA certificate into the SSL_CTX structure
	if(!SSL_CTX_load_verify_locations(ctx, argv[4], NULL))
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// Set to require peer (client) certificate verification
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	// Set the verification depth to 1
	SSL_CTX_set_verify_depth(ctx, 1);

	struct sockaddr_in servAddr;
	int servSock; // for listening
	int connectSocks[MAX]; // for connection
	NameList clients;
	clients.num = 0;
	// init connectSocks
	for(i = 0; i < MAX; i++){
		connectSocks[i] = -1;
	}

	// setup sockaddr
	bzero(&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = INADDR_ANY;
	servAddr.sin_port = htons(atoi(argv[1]));

	// create socket
	servSock = socket(AF_INET, SOCK_STREAM, 0);
	if(servSock < 0){
		perror("socket creation");
		exit(1);
	}

	// bind socket with server port
	if(bind(servSock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0){
		perror("bind socket");
		exit(1);
	}

	// set to non-block mode
	if(fcntl(servSock, F_SETFL, O_NDELAY) < 0){
		perror("set non-block");
		exit(1);
	}

	// listen on the port
	if(listen(servSock, MAX) < 0){
		perror("listen on the port");
		exit(1);
	}

	int nbytes;
	int flag;

	Packet sendFlieListPacket, sendCmdPacket;
	Packet recvPacket;

	sendCmdPacket.type = 0;
	recvPacket.type = 100;
	strcpy(sendCmdPacket.cmd, "Client existed");
	sendFlieListPacket.type = 1;
	sendFlieListPacket.fileList.num = 0;

	while(1)
	{
		// accept the client connection and set non-block
		for(i = 0; i < MAX; i++)
		{
			if(connectSocks[i] == -1)
			{
				connectSocks[i] = accept(servSock, NULL, sizeof(struct sockaddr_in));
				if(connectSocks[i] > 0)
				{
					printf("Client connected via TCP\n");
					ssl[i] = SSL_new(ctx);

					// Assign the socket into the SSL structure
					SSL_set_fd(ssl[i], connectSocks[i]);
					// Perform SSL Handshake on the SSL server
					nbytes = SSL_accept(ssl[i]);
					// printf("%d\n", nbytes);
					if(nbytes == 1)
					{
						printf("Client connected via SSL\n");
					}
					if(nbytes <= 0)
					{
						SSL_get_error(ssl[i], nbytes);
					}
					// set connectSock to non-block
					if(fcntl(connectSocks[i], F_SETFL, O_NDELAY) < 0)
					{
						perror("Cannot set connect sock non-block");
					}
				}
			}
		}

		// recv file list or command from client, recv type 0 for command, 1 for file list
		for(i = 0; i < MAX; i++)
		{
			if(connectSocks[i] > 0)
			{
				nbytes = SSL_read(ssl[i], &recvPacket, sizeof(Packet));
				if(nbytes > 0)
				{
					// if recv new file list
					if(recvPacket.type == 1)
					{
						// check if already client name already existed
						flag = isExisted(&clients, recvPacket.fileList.owner);
						// new client
						if(flag == 0)
						{
							printf("Receive new file list from client %s\n", recvPacket.fileList.owner);
							mergeFileList(&sendFlieListPacket.fileList, &recvPacket.fileList);	
							for(j = 0; j < MAX; j++)
							{
								if(connectSocks[j] > 0)
								{
									nbytes = SSL_write(ssl[j], &sendFlieListPacket, sizeof(Packet));
									if(nbytes < 0)
									{
										perror("Push updated file list");
									}
									if(nbytes > 0)
									{
										printf("Push master file list\n");
									}
								}
							}	
						}
						// client already existed
						if(flag == 1)
						{
							nbytes = SSL_write(ssl[i], &sendCmdPacket, sizeof(Packet));
							if(nbytes < 0)
							{
								perror("Send command");
							}
						}	
					}
					// if receive command from client
					if(recvPacket.type == 0)
					{
						printf("Client: %s\n", recvPacket.cmd);
						// ls command
						if(strcmp(recvPacket.cmd, "ls") == 0)
						{
							nbytes = SSL_write(ssl[i], &sendFlieListPacket, sizeof(Packet));
							if(nbytes < 0)
							{
								perror("Response to ls command");
							}
						}
						// exit command
						if(strcmp(recvPacket.cmd, "exit") == 0)
						{
							// deregister client and push the updated file list
							deregisterClient(&clients, &sendFlieListPacket.fileList, recvPacket.fileList.owner);
							// close this socket
							SSL_shutdown(ssl[i]);
							close(connectSocks[i]);
							SSL_free(ssl[i]);
							connectSocks[i] = -1;
							for(j = 0; j < MAX; j++)
							{
								if(connectSocks[j] > 0)
								{
									nbytes = SSL_write(ssl[j], &sendFlieListPacket, sizeof(Packet));
									if(nbytes < 0)
									{
										perror("Push updated file list");
									}
									if(nbytes > 0)
									{
										printf("Push the updated file list after one client exit\n");
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
