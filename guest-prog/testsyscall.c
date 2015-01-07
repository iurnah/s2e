#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <unistd.h> 

int main(int argc, char **argv)
{
    char *file = "/home/rui/abc";
    struct timeval tv;
    int rc, rd;
    printf("address of string: %#x\n", file);
    printf("address of string: %#x\n", &file);
    rd = syscall(SYS_mknod, file, S_IFREG, 0);
    if(rd == 0){
		printf("mknod: /home/rui/abc succesful!\n");
	}
		
	if(argc <= 1){
		rc = syscall(SYS_chmod, file, 0444);
		printf("chmod = %d\n", rc);
	} else if(argv[1][0] == argv[1][1]){
		gettimeofday(&tv, NULL);
		printf("===== [%c] == [%c] ======\n", argv[1][0], argv[1][1]);	
	}else if(argv[1][0] < argv[1][1]){
		syscall(SYS_gettid);
		printf("<<<<< [%c] << [%c] <<<<<<\n", argv[1][0], argv[1][1]);	
	}else {
		syscall(SYS_gettimeofday, &tv, NULL);
		printf(">>>>> [%c] >> [%c] >>>>>>\n", argv[1][0], argv[1][1]);
	}
	
	return 0;
}
