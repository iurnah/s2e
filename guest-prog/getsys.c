/* get vsyscall address and test - compile with -m32 on x86_64 */
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

static unsigned int getsys(char **envp) {
        Elf32_auxv_t *auxv;

        /* walk past all env pointers */
        while (*envp++ != NULL)
                ;
        /* and find ELF auxiliary vectors (if this was an ELF binary) */
        auxv = (Elf32_auxv_t *) envp;

        for ( ; auxv->a_type != AT_NULL; auxv++){
                if (auxv->a_type == AT_SYSINFO){
                        printf("address: 0x%#x\n", auxv->a_un.a_val);
                        return auxv->a_un.a_val;
				}
		}
		
        fprintf(stderr, "no AT_SYSINFO auxv entry found\n");
        exit(1);
}

unsigned int sys, pid;

int main(int argc, char **argv, char **envp) {
        sys = getsys(envp);
        __asm__(
"               movl $20, %eax  \n"     /* getpid system call */
"               call *sys       \n"     /* vsyscall */
"               movl %eax, pid  \n"     /* get result */
        );
        printf("pid was %d\n", pid);
        while(1);
        return 0;
}
