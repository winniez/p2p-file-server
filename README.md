Encrypted Peer to Peer File Server 
Yisha Wu and Xinying Zeng
Dec. 8th 2013

Test instructions:
Compile the source code by "make all".
Put server_PFS, client_PFS, clientX.cert and clientX.key in separate folder. Copy cacert.pem to each folder.

To run server:
./server_PFS 9000 server.key server.crt cacert.pem

To run client:
./client_PFS A 127.0.1.1 9000 clientA_priv.key clientA.crt cacert.pem
./client_PFS B 127.0.1.1 9000 clientB_priv.key clientB.crt cacert.pem
./client_PFS C 127.0.1.1 9000 clientC_priv.key clientC.crt cacert.pem

NOTICE: 
client port is selected based on client name, port = 9500 + (clientName[0] - 'A').
client "AB" and "AC" would try to listen on same port and cause failure.
Also make sure the ports are available on the test machine. 

The system provides following functionalities:
1  clients are able to connect to the server via TCP
2  clients connect and disconnect from peers appropriately in order to retrieve files
3  clients can execute the commands (‘ls’,’get’,’exit’)
3.1 ‘ls’ retrieves latest file list and prints to console
3.2 ‘get’ retrieves file directly from peer
3.3 ‘exit’ exits client
4. server adds to and removes from master file list appropriately
5. server provides a master file list to all clients
6. certificate creation using the openSSL command line tool 
7. SSL encrypted communication

How it works:
Server:
- Server starts first and listen on designated port. 
- Server accept client connection. If success, server keeps records of the socket descriptor returned by accept func; set the socket to non-block mode.
- Server try to recv from connected clients. On receiving a client file list. Server first checks if the client has registered with server. If client with same name has already registered, server would send exit command to this client. If client has not registered yet, server register client name in a namelist, merge the master file list with client file list received. On receiving a command "ls" or "exit", server push master file list to the client for "ls", or server deregister client from file list and remove entries associated with this client from master file list. Server would push the updated master file list to all connected client. 

Client:
- Client starts up, listens on its peer-to-peer socket, sets peer-to-peer socket to non-block mode. 
- Client connects to server. Once connected to server, set the client-server socket to non-block mode. client sends its local file list to server. 
- Client recv updated file list / "exit" command from server. 
- Client accepts incoming connection on peer-to-peer socket. Recv "get file" command from peer and send file. An error command would be send to the peer if the file is not found. 
- After finishes file transferring. Clients send and recv confirmation and close the sockets. 
- When user input "exit", client send "exit" command to server. close sockets and exit. 

Encrypted communication:
- First initiate OpenSSL (SSL_load_error_strings();ERR_load_BIO_strings();OpenSSL_add_all_algorithms();)
- After TCP connection established, 
-- get new SSL state with context with "SSL *ssl = SSL_new(ctx);""
-- set connection to SSL state with "SSL_set_fd(ssl, client);" 
-- start the handshaking with "SSL_accept(ssl); " 
-- send and recv using "bytes = SSL_read(ssl, buf, sizeof(buf));" and "SSL_write(ssl, reply, strlen(reply));"
-- close connection and clean up using "client = SSL_get_fd(ssl);", "SSL_free(ssl);" and "close(sd);"










