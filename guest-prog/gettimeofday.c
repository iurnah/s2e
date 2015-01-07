#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>

void main(void)
{
    struct timeval tv;

    /* glibc wrapped */
    gettimeofday(&tv, NULL);

    /* Explicit syscall */
    syscall(SYS_gettimeofday, &tv, NULL);

    return;
}
