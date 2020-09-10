#include <sys/inotify.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <limits.h>

#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

int processedlines = 0 ;

void readFile(){
//open file, skip n lines, read line, sign line, repeat until end, store line number namespace	
	//printf("Start readfile\n\n\n");
	fflush(stdout);
	FILE *syslogfile, *outfile;
	char *linebuffer = NULL;
	size_t linesize = 0;	
	ssize_t linelength;
	int linescanner = 0;
	BYTE *signature, *hexSignature;
	outfile = fopen("signedsyslog", "a");
	syslogfile = fopen("/var/log/auth.log", "r");
	//fseek(syslogfile, bytesread, SEEK_SET);
	//printf("bytesread %i\n",bytesread);
	BYTE *writeline;
	
	while((linelength=getline(&linebuffer, &linesize, syslogfile))>2){	
		linescanner++;			
		if(processedlines>linescanner){
		    //printf("Processedlines: %i Linescanner: %i\n", processedlines, linescanner);			
			continue;
		}
		processedlines++;
		if(strstr(linebuffer, "tpmd")==NULL){		
			signData(linebuffer, linelength, &signature, &hexSignature);			
			//printf("malloclenght: %i\n", linelength+strlen(hexSignature)+3);
			writeline = malloc(linelength+strlen(hexSignature)+12);			
			linebuffer[strlen(linebuffer)-1] = ' ';
			strcpy(writeline, linebuffer);
			strcat(writeline, "hexdata: ");
			strcat(writeline, hexSignature);
			strcat(writeline, "\n");			
			writeSyslog(1, writeline);
			write(fileno(outfile), writeline,strlen(writeline));  								
			free(writeline);
			free(linebuffer);
			linebuffer = NULL;
			free(hexSignature);
			free(signature);
			}			
		}	
	//printf("Done reading file\n");
	fclose(outfile);
	fclose(syslogfile);
	
}

void syslogmonitor(){
	const char *filename = "/var/log/auth.log";
	int inotfd = inotify_init();
	int watch_desc = inotify_add_watch(inotfd, filename, IN_MODIFY);
	size_t bufsiz = sizeof(struct inotify_event) + PATH_MAX + 1;
	struct inotify_event* event;
	char buf[BUF_LEN] __attribute__ ((aligned(8)));
	ssize_t numRead;
	char *p;
	
	//Just count lines to start with new lines only
	FILE *syslogfile;
	syslogfile = fopen("/var/log/auth.log", "r");
	char ch;
	while(!feof(syslogfile))
	{
	  ch = fgetc(syslogfile);
	  if(ch == '\n')
	  {
		processedlines++;
	  }
	}
	fclose(syslogfile);
	
		
	for (;;) {                                  /* Read events forever */
		
		 numRead = read(inotfd, buf, BUF_LEN); //segmentation fault
		 printf("New event\n");
		 if (numRead == 0)
             printf("read() from inotify fd returned 0!");
 
         if (numRead == -1)
             printf("read");
 
         printf("Read %ld bytes from inotify fd\n", (long) numRead);
		
		
		//read event type, currently only listening to modify
         /*for (p = buf; p < buf + numRead; ) {
             event = (struct inotify_event *) p;
             displayInotifyEvent(event);
 
             p += sizeof(struct inotify_event) + event->len;
			 
         }*/
		 readFile();
     }
}




void displayInotifyEvent(struct inotify_event *i)
 {
     printf("    wd =%2d; ", i->wd);
     if (i->cookie > 0)
         printf("cookie =%4d; ", i->cookie);
 
     printf("mask = ");
     if (i->mask & IN_ACCESS)        printf("IN_ACCESS ");
     if (i->mask & IN_ATTRIB)        printf("IN_ATTRIB ");
     if (i->mask & IN_CLOSE_NOWRITE) printf("IN_CLOSE_NOWRITE ");
     if (i->mask & IN_CLOSE_WRITE)   printf("IN_CLOSE_WRITE ");
     if (i->mask & IN_CREATE)        printf("IN_CREATE ");
     if (i->mask & IN_DELETE)        printf("IN_DELETE ");
     if (i->mask & IN_DELETE_SELF)   printf("IN_DELETE_SELF ");
     if (i->mask & IN_IGNORED)       printf("IN_IGNORED ");
     if (i->mask & IN_ISDIR)         printf("IN_ISDIR ");
     if (i->mask & IN_MODIFY)        printf("IN_MODIFY ");
     if (i->mask & IN_MOVE_SELF)     printf("IN_MOVE_SELF ");
     if (i->mask & IN_MOVED_FROM)    printf("IN_MOVED_FROM ");
     if (i->mask & IN_MOVED_TO)      printf("IN_MOVED_TO ");
     if (i->mask & IN_OPEN)          printf("IN_OPEN ");
     if (i->mask & IN_Q_OVERFLOW)    printf("IN_Q_OVERFLOW ");
     if (i->mask & IN_UNMOUNT)       printf("IN_UNMOUNT ");
     printf("\n");
 
     if (i->len > 0)
         printf("        name = %s\n", i->name);
 }
