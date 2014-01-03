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
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include "util.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ./client_PFS <Client Name> <Server IP> <Server Port> <Private Key> <Certificate of this Client> <CA Cert>
int main(int argc, char const *argv[])
{
    const char *keyName = argv[4]; 
    const char *certName = argv[5];
    const char *CACert = argv[6];
    // ssl setup
    SSL_CTX *ctx;
    SSL *clieSSL, *p2pSSL;
    SSL_METHOD *meth;
    // Load encryption & hashing algorithms for the SSL program
    SSL_library_init();
    // Load the error strings for SSL & CRYPTO APIs
    SSL_load_error_strings();
    // Create an SSL_METHOD structure (choose an SSL/TLS protocol version)
    meth = SSLv3_method();
    // Create an SSL_CTX structure
    ctx = SSL_CTX_new(meth);
    // Create an SSL_CTX structure
    ctx = SSL_CTX_new(meth);

    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Load the client certificate into the SSL_CTX structure
    if(SSL_CTX_use_certificate_file(ctx, argv[5], SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Load the private-key corresponding to the client certificate
    if(SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Check if the client certificate and private-key matches
    if(!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public key\n");
        exit(1);
    }   
    // Load the RSA CA certificate into the SSL_CTX structure
    // This will allow this client to verify the server's certificate
    if(!SSL_CTX_load_verify_locations(ctx, argv[6], NULL))
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Set flag in context to require peer (server) certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

	struct sockaddr_in remoteAddr, p2pAddr;
	int clieSock;   // for connecting to server
	int p2pSock;    // for p2p transfer
    int peerSock = -1;

	// setup sockaddr
	bzero(&remoteAddr, sizeof(remoteAddr));
	remoteAddr.sin_family = AF_INET;
	remoteAddr.sin_addr.s_addr = inet_addr(argv[2]);
	remoteAddr.sin_port = htons(atoi(argv[3]));

	bzero(&p2pAddr, sizeof(p2pAddr));
	p2pAddr.sin_family = AF_INET;
	p2pAddr.sin_addr.s_addr = inet_addr(argv[2]);
	p2pAddr.sin_port = htons((int)(9500 + (argv[1][0] - 'A')));

	// create socket
	clieSock = socket(AF_INET, SOCK_STREAM, 0);
	p2pSock = socket(AF_INET, SOCK_STREAM, 0);
	if(clieSock < 0 || p2pSock < 0){
		perror("socket creation");
		exit(1);
	}

	if (fcntl(p2pSock, F_SETFL, O_NDELAY)<0)
    {
        perror("error set non-block for client-p2p socket");
        exit(1);
    }
    // bind socket with p2p port
	if(bind(p2pSock, (struct sockaddr *)&p2pAddr, sizeof(p2pAddr)) < 0){
		perror("bind socket");
		exit(1);
	}

	// listen on the p2p port
	if(listen(p2pSock, MAX) < 0){
		perror("listen on the port");
		exit(1);
	}

	// connect to server
	if(connect(clieSock, (struct sockaddr *)&remoteAddr, sizeof(remoteAddr)) < 0){
		perror("connect to server");
		exit(1);
	}

    // create ssl struct
    clieSSL = SSL_new(ctx);
    // Assign the socket into the SSL structure
    SSL_set_fd(clieSSL, clieSock);
    // Perform SSL Handshake on the SSL client
    if(SSL_connect(clieSSL) == 1)
    {
        printf("ssl connected to server\n");
    }

    // set sockets to non-block mode
    if (fcntl(clieSock, F_SETFL, O_NDELAY) < 0)
    {
        perror("error set non-block for client-server socket");
        exit(1);
    }
	// get local file info list
    FileList masterList;
    Packet localFileListPacket, sendCmdPacket, recvPacket;
    localFileListPacket.type = 1;
    sendCmdPacket.type = 0;
	
    struct stat st;
	getFileList(&(localFileListPacket.fileList));
	strcpy(localFileListPacket.fileList.owner, argv[1]);
    strcpy(sendCmdPacket.fileList.owner, argv[1]);
	int i;
	for(i = 0; i < localFileListPacket.fileList.num; i++)
    {
		stat(localFileListPacket.fileList.files[i].fileName, &st);
		localFileListPacket.fileList.files[i].fileSize = st.st_size;
		strcpy(localFileListPacket.fileList.files[i].fileOwner, argv[1]);
		strcpy(localFileListPacket.fileList.files[i].ownerIP, argv[2]);
		localFileListPacket.fileList.files[i].ownerPort = 9500 + (argv[1][0] - 'A');
	}
	printFileList(&(localFileListPacket.fileList));

	// upload file list to server
	int nbytes;
    nbytes = SSL_write(clieSSL, &localFileListPacket, sizeof(Packet));
	if(nbytes < 0){
		perror("init upload");
		exit(1);
	}

	char command[128];
    while(1)
    {
        printf("Input command: ls, get, exit\n");

        while(!kbhit())
        {
            // no user input, recv from server
            nbytes = SSL_read(clieSSL, &recvPacket, sizeof(Packet));
            if (nbytes > 0)
            {
                if (recvPacket.type == 0)
                {
                    if (strcmp(recvPacket.cmd, "Client existed")==0)
                    {
                        // client already existed, quit
                        printf("Client %s already registered with server, exiting...\n", argv[1]);
                        exit(1);
                    }
                }
                else
                {// recv file list
                    printf("Received master file list from server\n");
                    copyFileList(&(masterList), &(recvPacket.fileList));
                    printFileList(&(masterList));
                }
                printf("input command: ls, get, exit\n");
            }
            // try to accept on p2p listen socket
            peerSock = accept(p2pSock, NULL, sizeof(struct sockaddr_in));
            if(peerSock > 0)
            {
                // create p2p ssl
                p2pSSL = SSL_new(ctx);
                // Assign the socket into the SSL structure
                SSL_set_fd(p2pSSL, peerSock);
                // Perform SSL Handshake on the client recv cmd
                nbytes = SSL_accept(p2pSSL);
                if(nbytes == 1)
                {
                    printf("Accpeted connection from remote client via SSL\n");
                }
                sleep(1);
                // connection established

                // peer-2-peer connection handling                
                int rtn = 1, fsize, size_per_send;
                char fname[128];
                DataPacket recvDataPacket, sendDataPacket;
                FILE *file;
                
                // try to receive from remote peer
                nbytes = SSL_read(p2pSSL, &recvDataPacket, sizeof(DataPacket));
                if (nbytes > 0)
                {
                    // check cmd field
                    printf("Receive command '%s' from remote peer\n", recvDataPacket.cmd);
                    if (strstr(recvDataPacket.cmd, "get"))
                    {
                        // parse file name
                        char* sec_arg = strstr(recvDataPacket.cmd, " ");
                        strcpy(fname, sec_arg+1);
                        file = fopen(fname, "rb");
                        if (file == NULL)
                        {
                            printf("Failed open file %s.\n", fname);
                            strcpy(sendDataPacket.cmd, "File Not Found");
                            // nbytes = send(peerSock, &sendDataPacket, sizeof(DataPacket), 0);
                            nbytes = SSL_write(p2pSSL, &sendDataPacket, sizeof(DataPacket));
                            if (nbytes < 0)
                            {
                                perror("error send cmd File Not Found to remote peer");
                            }
                            rtn = 0;
                        }
                        strcpy(sendDataPacket.cmd, "Sending");
                        // nbytes = send(peerSock, &sendDataPacket, sizeof(DataPacket), 0);
                        nbytes = SSL_write(p2pSSL, &sendDataPacket, sizeof(DataPacket));
                        if (nbytes < 0)
                        {
                            perror("error send cmd Sending to remote peer");
                        }
                        struct stat st;
                        stat(fname, &st);
                        fsize = st.st_size;
                        int repeats = (int) (fsize/MAXBUFFSIZE) + 1;
                        for (i = 0; i < repeats; i++)
                        {
                            size_per_send = (MAXBUFFSIZE) < (fsize-i*MAXBUFFSIZE) ? (MAXBUFFSIZE):(fsize-i*MAXBUFFSIZE);
                            int readed = fread(sendDataPacket.payload, sizeof(char), size_per_send, file);
                            sendDataPacket.size = readed;
                            // nbytes = send(peerSock, &sendDataPacket, sizeof(DataPacket), 0);
                            nbytes = SSL_write(p2pSSL, &sendDataPacket, sizeof(DataPacket));
                            if (nbytes < 0)
                            {
                                perror("error send file to remote peer");
                            }
                        }
                        fclose(file);
                        printf("File sent\n");
                        // receive response from reomte peer
                        nbytes = SSL_read(p2pSSL, &recvDataPacket, sizeof(DataPacket));
                        if (nbytes > 0)
                        {
                            if (strcmp(recvDataPacket.cmd, "File received")==0)
                            {
                                printf("Remote peer received file %s\n", fname);
                            }
                        }
                        else
                        {
                            perror("error recv peer file received msg");
                        }
                    }
                    else
                    {
                        printf("Unexpected remote command: %s\n", recvDataPacket.cmd);
                        rtn = 0;
                    }
                }
                else
                {
                    perror("error recv in handleRemotePeerConnection");
                    rtn = 0;
                }
                sleep(1);
                close(peerSock);
                printf("Input command: ls, get, exit\n");
            }
        }
		gets(command);
		// ls command
		if(strcmp(command, "ls") == 0)
        {
            strcpy(sendCmdPacket.cmd, command);
            nbytes = SSL_write(clieSSL, &sendCmdPacket, sizeof(Packet));
			if(nbytes < 0)
            {
				perror("send ls command");
			}
        }
        if (strcmp(command, "exit") == 0)
        {
            // deregister with server
            strcpy(sendCmdPacket.cmd, command);
            nbytes = SSL_write(clieSSL, &sendCmdPacket, sizeof(Packet));
            if (nbytes < 0)
            {
                perror("send exit command");
            }
            else
            {
                printf("Client %s exiting...\n", argv[1]);
                close(p2pSock);
                close(clieSock);
                exit(1);
            }
        }
        if (strstr(command, "get"))
        {
            connectRemotePeer(command, &masterList, argv[1], keyName, certName, CACert);
        }
    }
	return 0;
}
