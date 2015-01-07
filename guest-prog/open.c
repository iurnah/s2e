/*  open.c */

#include <fcntl.h>         /* defines options flags */
#include <sys/types.h>     /* defines types used by sys/stat.h */
#include <sys/stat.h>      /* defines S_IREAD & S_IWRITE  */
#include <sys/time.h>	   /* defines the time variable struct */
#include <unistd.h>		   /* defines syscalls */
#include <stdio.h>		   /* defines io functions */
#include <stdlib.h>		   /* defines standard library */
#include <string.h>
#include <sys/syscall.h>

//#include "s2e.h"
	
static char message1[] = "DATAFILE CONTENTS";
static char message2[] = "TEXTFILE CONTENTS";

int main(int argc, char * argv[])
{
	int fd;
	char buffer[80];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	//char str[2];
	/*
	printf("Enter 1 characters: ");
	if(!fgets(str, sizeof(str), stdin))
		return 1;
	*/
	//s2e_enable_forking();
	//s2e_make_symbolic(str, 1 , "str");
		
	//if(*argv[1] == '\n'){
	if(argc <= 1){
		printf("*** Not Enough Input!!! ***\n");
	} else {
		if(*argv[1] >= 'a' && *argv[1] <= 'z'){
		/* open datafile.dat for read/write access   (O_RDWR)
		create datafile.dat if it does not exist  (O_CREAT)
		return error if datafile already exists   (O_EXCL)
		permit read/write access to file  (S_IWRITE | S_IREAD)
		*/	
		fd = open("datafile.dat",O_RDWR | O_CREAT | O_EXCL, S_IREAD | S_IWRITE);
        if (fd != -1)
           {
           printf("datafile.dat opened for read/write access\n");
           if(write(fd, message1, sizeof(message1)) < 0)
				printf("*** write datafile.dat failed ***\n");
				
           lseek(fd, 0L, 0);     /* go back to the beginning of the file */
           if (read(fd, buffer, sizeof(message1)) == sizeof(message1))
              printf("\"%s\" was written to datafile.dat\n", buffer);
           else
              printf("*** error reading datafile.dat ***\n");
           close (fd);
           }
        else
           printf("*** datafile.dat already exists ***\n");
           	
		} else {

		fd = open("textfile.txt",O_RDWR | O_CREAT | O_EXCL, S_IREAD | S_IWRITE);
        if (fd != -1)
           {
           printf("textfile.txt opened for read/write access\n");

           if(write(fd, message2, sizeof(message2)) < 0)
				printf("*** write textfile.txt failed ***\n");
				
           lseek(fd, 0L, 0);     /* go back to the beginning of the file */
           if (read(fd, buffer, sizeof(message2)) == sizeof(message2))
              printf("\"%s\" was written to textfile.txt\n", buffer);
           else
              printf("*** error reading textfile.txt ***\n");
           close (fd);
           }
        else
           printf("*** textfile.txt already exists ***\n");

		}
	}

	//s2e_disable_forking();
	//s2e_get_example(str, 2);
	syscall(SYS_gettimeofday, &tv, NULL);

	//printf("'%c' %02x \n", str[0], (unsigned char) str[0]);
	if(argc >= 2)
		printf("'%c' %02x \n", *argv[1], (unsigned char) *argv[1]);
	
	return 0;
}

