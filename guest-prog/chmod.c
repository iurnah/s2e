#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

void main(){          
	
	char *file = "/home/rui/abc";
    int rc;
    rc = syscall(SYS_chmod, file, 0444);
    if (rc == -1)
		printf("failed!, %d\n", rc);
	else 
		printf("OK!!! %p\n", file);
}
