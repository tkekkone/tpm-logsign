
void sendHTTPRequest(char* url){

  CURLcode res; 
  CURL *curl;
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    }
  }

void getDataFile(char* file){
  printf("Filename: %s\n ", file);
  const char* filename = (const char*)file;
  FILE *filehandle;
  filehandle = fopen(filename, "r");
  char c;
  if (filehandle) {
    while ((c = getc(filehandle)) != EOF)
	printf("%c", c);
    fclose(filehandle);
  }		

}


