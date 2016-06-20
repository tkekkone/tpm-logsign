void *connection_handler(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	int read_size, i;
	char *message , client_message[2000];
	char hex[2];
	BYTE *PCRvalue, *validationdata;
	UINT32 validationdatalength = 0;

	//Send some messages to the client
	message = "Send command upload, attest or extend\n";
	write(sock , message , strlen(message));
	//Receive a message from client
	while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
	{
		//end of string marker
		client_message[read_size] = '\0';
		if(strstr(client_message, "extend")!=NULL){
			readAPCR(14, &PCRvalue);
			message = "PCR current value: ";						
			write(sock , message, strlen(message));			
			for(i=0; i<20; i++){
				sprintf(hex, "%02x",PCRvalue[i] & 0xff);
				write(sock , hex, strlen(hex));			
			}
			message = "\nExtending PCR..";									
			write(sock , message, strlen(message));			
			extendFileContentToPCR("files.txt", 14);
			readAPCR(14, &PCRvalue);
			message = "\nNew PCR value: ";				
			write(sock , message, strlen(message));
			for(i=0; i<20; i++){
				sprintf(hex, "%02x",PCRvalue[i] & 0xff);
				write(sock , hex, strlen(hex));			
			}
			message = "\nDone\n";									
			write(sock , message, strlen(message));										
		}
		else if(strstr(client_message, "upload")!=NULL){
			message = "uploading files listed to server\n";
			write(sock , message , strlen(message));
			printf("%s", message);

		}
		else if(strstr(client_message, "attest")!=NULL){
			message = "generating attestation information\n";
			write(sock , message , strlen(message));
			createAttestorFile(14, "abcdefghijklmnopqrstuvw",&validationdata, &validationdatalength);
			for(i=0; i<validationdatalength; i++){
				sprintf(hex, "%02x",validationdata[i] & 0xff);
				write(sock , hex, strlen(hex));			
			}
			printf("%s ", message);
		}
		else if(strstr(client_message, "verify")!=NULL){
			message = "Verifying a signature\n";
			write(sock , message , strlen(message));
		}
		else {
		message = "unknown command\n";
		write(sock , message , strlen(message));
		}

		//clear the message buffer
		memset(client_message, 0, 2000);
	}
	if(read_size == 0)
		{
		puts("Client disconnected");
		fflush(stdout);
		}
	else if(read_size == -1)
		{
		perror("recv failed");
		}
	return 0;
} 

int start()
{
	int socket_desc , client_sock , c;
	struct sockaddr_in server , client;
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}
	puts("Socket created");
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8888 );
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
	puts("bind done");
	//Listen
	listen(socket_desc , 3);
	
	//Accept and incoming connection
	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);
	pthread_t thread_id;
	while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		puts("Connection accepted");
		if( pthread_create( &thread_id , NULL , connection_handler , (void*) &client_sock) < 0)
			{
			perror("could not create thread");
			return 1;
			}
		//Now join the thread , so that we dont terminate before the thread
		//pthread_join( thread_id , NULL);
		puts("Handler assigned");
	}
	if (client_sock < 0)
	{
		perror("accept failed");
		return 1;
	}
	return 0;
}
