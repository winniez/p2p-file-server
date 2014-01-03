#include <sys/socket.h>
#include <sys/stat.h>
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
#include <dirent.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUFFSIZE 1000
#define MAX 30

typedef struct
{
    char fileName[128];
    int fileSize;
    char fileOwner[8];
    char ownerIP[128];
    int ownerPort;
} FileInfo;

typedef struct
{
    char names[MAX][8];
    char num;
} NameList;

typedef struct
{
    int num;
    char owner[8];
    FileInfo files[MAX];
} FileList;

// type = 1 for file list, type = 0 for command
typedef struct 
{
    int type;
    char cmd[256];
    FileList fileList;
} Packet;

typedef struct 
{
    int size;
    char payload[MAXBUFFSIZE];
    char cmd[256];
} DataPacket;

// client get local files and construct local file list
void getFileList(FileList *fileList){
    struct dirent **namelist;
    int n;
    n = scandir(".", &namelist, 0, alphasort);
    if(n < 0)
    {
        perror("scan dir");
        exit(1);
    }
    fileList->num = 0;
    while(n--)
    {
        if((strcmp(namelist[n]->d_name, "..") != 0) && (strcmp(namelist[n]->d_name, ".") != 0 ))
        {
            strcpy(fileList->files[fileList->num].fileName, namelist[n]->d_name);
            fileList->num++;
        }
        free(namelist[n]);
    }
    free(namelist);
}

void printFileList(FileList *fileList){
    int i;
    printf("\nFile name\t||File size Byte||File owner\t||Owner IP\t||Owner port\n");
    for(i = 0; i < fileList->num; i++)
    {
        printf("%s\t||%d\t\t||%s\t\t||%s\t||%d\n",
               fileList->files[i].fileName,
               fileList->files[i].fileSize,
               fileList->files[i].fileOwner,
               fileList->files[i].ownerIP,
               fileList->files[i].ownerPort);
    }
    printf("\n");
}

void copyFileList(FileList *copyto, FileList *from)
{
    int i;
    copyto->num = from->num;
    for (i = 0; i < from->num; i++)
    {
        strcpy(copyto->files[i].fileName, from->files[i].fileName);
        strcpy(copyto->files[i].fileOwner, from->files[i].fileOwner);
        copyto->files[i].fileSize = from->files[i].fileSize;
        strcpy(copyto->files[i].ownerIP, from->files[i].ownerIP);
        copyto->files[i].ownerPort = from->files[i].ownerPort;
    }
}

// merge origin master file list with new file list
void mergeFileList(FileList *master, FileList *newList){
    int i;
    int size = master->num;
    for(i = size; i < size + newList->num; i++)
    {
        strcpy(master->files[i].fileName, newList->files[i - size].fileName);
        strcpy(master->files[i].fileOwner, newList->files[i - size].fileOwner);
        master->files[i].fileSize = newList->files[i - size].fileSize;
        strcpy(master->files[i].ownerIP, newList->files[i - size].ownerIP);
        master->files[i].ownerPort = newList->files[i - size].ownerPort;
    }
    master->num = size + newList->num;
}

// check if client already existed
// 0 for new client, 1 for already existed
int isExisted(NameList *clients, char *name)
{
    int flag = 0;
    int i;
    for(i = 0; i < MAX; i++)
    {
        if(strcmp(clients->names[i], name) == 0)
        {
            flag = 1;
            return flag;
        }
    }
    strcpy(clients->names[clients->num], name);
    clients->num++;
    return flag;
}

// use select to check if there is keyboard input
// 0 for no input, non-zero for input
int kbhit()
{
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

// remove exit clinet's file list from master file list
void deregisterClient(NameList *clients, FileList *master, char *name)
{
    // remove client name from name list
    int i = 0;
    while(strcmp(clients->names[i], name) != 0)
    {
        i++;
    }
    int j;
    for(j = i; j < clients->num; j++)
    {
        strcpy(clients->names[j], clients->names[j+1]);
    }
    clients->num--;

    // remove client's file list from master file list
    // get the position of exit client in the master file list
    int pos1 = 0, pos2 = 0;
    for(i = 0; i < master->num; i++)
    {
        if(strcmp(master->files[i].fileOwner, name) == 0)
        {
            pos1 = i;
            pos2 = pos1;
            while(strcmp(master->files[pos2].fileOwner, name) == 0)
            {
                pos2++;
            }
            break;
        }
    }
    // overwrite these entries with the following entries
    int range = pos2 - pos1;
    master->num -= range;
    printf("Num of files in master file list: %d\n", master->num);
    for(i = pos1; i < master->num; i++)
    {
        strcpy(master->files[i].fileName, master->files[i + range].fileName);
        strcpy(master->files[i].fileOwner, master->files[i + range].fileOwner);
        master->files[i].fileSize = master->files[i + range].fileSize;
        strcpy(master->files[i].ownerIP, master->files[i + range].ownerIP);
        master->files[i].ownerPort = master->files[i + range].ownerPort;
    }
    for(i = master->num; i < MAX; i++)
    {
        bzero(&master->files[i], sizeof(FileInfo));
    }
}


/* int connectRemotePeer(char* cmd, FileList *master)
 * Connect remote client
 * return 0 for error, return 1 for success
 */
int connectRemotePeer(char* cmd, FileList *master, char *initiator, const char *keyName, const char *certName, const char *CACert)
{
    // ssl setup
    SSL_CTX *ctx;
    SSL *connectSSL;
    SSL_METHOD *meth;
    // Load encryption & hashing algorithms for the SSL program
    SSL_library_init();
    // Load the error strings for SSL & CRYPTO APIs
    SSL_load_error_strings();
    // Create an SSL_METHOD structure (choose an SSL/TLS protocol version)
    meth = SSLv3_method();
    // Create an SSL_CTX structure
    ctx = SSL_CTX_new(meth);
    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Load the client certificate into the SSL_CTX structure
    if(SSL_CTX_use_certificate_file(ctx, certName, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Load the private-key corresponding to the client certificate
    if(SSL_CTX_use_PrivateKey_file(ctx, keyName, SSL_FILETYPE_PEM) <= 0)
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
    if(!SSL_CTX_load_verify_locations(ctx, CACert, NULL))
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Set flag in context to require peer (server) certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    int rtn = 1;
    DataPacket recvPacket, sendPacket;
    int nbytes, fsize, remoteport, i, connectSock;
    char fname[128], remoteIP[128];
    FILE *file;
    struct sockaddr_in remotePeerAddr;

    // parse file name
    char *sec_arg = strstr(cmd, " ");
    strcpy(fname, sec_arg+1);
    // identify remote peer owns the file
    int index = -2;
    for (i = 0; i < master->num; i++)
    {
        if (strcmp(fname, master->files[i].fileName)==0)
        {
            if (strcmp(master->files[i].fileOwner, initiator) == 0)
            {index = -1;}
            else 
            {
                index = i;
                break;
            }
        }
    }
    if (index == -2)
    {
        printf("File %s is not in master file list, giving up...\n",fname);
        rtn = 0;
        return rtn;
    }
    if (index == -1)
    {
        printf("Only available copy of file %s is local, giving up...\n", fname);
        rtn = 0;
        return rtn;
    }
    printf("Find file in master list\n");
    fsize = master->files[index].fileSize;
    remoteport = master->files[index].ownerPort;
    strcpy(remoteIP, master->files[index].ownerIP);
    // set remote address
    bzero(&remotePeerAddr, sizeof(remotePeerAddr));
    remotePeerAddr.sin_family = AF_INET;
    remotePeerAddr.sin_addr.s_addr = inet_addr(remoteIP);
    remotePeerAddr.sin_port = htons(remoteport);

    // create new socket and connect remote client
    connectSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connect(connectSock, (struct sockaddr*)&(remotePeerAddr), sizeof(remotePeerAddr)) == 0)
    {
        printf("Connected to remote peer via TCP\n");
        // create ssl struct
        connectSSL = SSL_new(ctx);
        // Assign the socket into the SSL structure
        SSL_set_fd(connectSSL, connectSock);
        // Perform SSL Handshake on the SSL client
        nbytes = SSL_connect(connectSSL);
        if(nbytes == 1)
        {
            printf("Connected to remote peer via SSL\n");
        }
        // send command
        strcpy(sendPacket.cmd, cmd);
        nbytes = SSL_write(connectSSL, &sendPacket, sizeof(DataPacket));
        if (nbytes < 0)
        {
            printf("error send %s cmd to peer", cmd);
            rtn = 0;
            return rtn;
        }
        // recv
        nbytes = SSL_read(connectSSL, &recvPacket, sizeof(DataPacket));
        if (nbytes < 0)
        {
            perror("error recv from remote client");
            rtn = 0;
            return rtn;
        }
        if (strstr(recvPacket.cmd, "File Not Found"))
        {
            printf("Remote client says: %s\n", recvPacket.cmd);
            rtn = 0;
            return rtn;
        }
        if (strstr(recvPacket.cmd, "Sending"))
        {
            printf("Receiving file %s...\n", fname);
            // receive and write file
            file = fopen(fname,"wb");
            int repeats = (int) (fsize/MAXBUFFSIZE)+1;
            for (i = 0; i < repeats; i++)
            {
                nbytes = SSL_read(connectSSL, &recvPacket, sizeof(DataPacket));
                if (nbytes > 0)
                {
                    fwrite(recvPacket.payload, sizeof(char), recvPacket.size, file);
                }
            }
            fclose(file);
            printf("File %s received.\n", fname);
            strcpy(sendPacket.cmd, "File received");
            nbytes = SSL_write(connectSSL, &sendPacket, sizeof(DataPacket));
            if (nbytes < 0)
            {
                perror("error to send cmd File received");
            }
        }
        else
        {
            printf("Cannot get file %s, remote peer says %s\n",fname, recvPacket.cmd);
            rtn = 0;
        }
        sleep(1);
        close(connectSock);
    }
    else
    {
        printf("failed connect to peer IP %s port %d\n", remoteIP, remoteport);
        perror("");
        rtn = 0;
    }
    return rtn;
}
