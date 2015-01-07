#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <elf.h>

static unsigned int getsys(char **envp) {
        Elf32_auxv_t *auxv;

        /* walk past all env pointers */
        while (*envp++ != NULL)
                ;
        /* and find ELF auxiliary vectors (if this was an ELF binary) */
        auxv = (Elf32_auxv_t *) envp;

        for ( ; auxv->a_type != AT_NULL; auxv++)
                if (auxv->a_type == AT_SYSINFO)
                        return auxv->a_un.a_val;

        fprintf(stderr, "no AT_SYSINFO auxv entry found\n");
        exit(1);
}
unsigned int sys, gs, *base;

static void getgs() {
        __asm__("mov %gs, gs\n");
        if ((gs & 7) != 3) {
                fprintf(stderr, "unexpected gs = 0x%x\n", gs);
                exit(1);
        }
}

static void getta(){
        struct user_desc u;
        int i;

        u.entry_number = (gs >> 3);
        if (syscall(__NR_get_thread_area, &u)) {
                perror("get_thread_area");
                exit(1);
        }
        base = (unsigned int *) u.base_addr;

        for (i=0; i<100; i++)
                if (base[i] == sys)
                        goto gotit;
        fprintf(stderr, "didn't find the sysinfo entry\n");
        exit(1);

 gotit:
        printf("Enter the kernel via  call *%%gs:0x%x .\n", 4*i);
}

int main(int argc, char **argv, char **envp) {
        sys = getsys(envp); printf("sys = 0x%x\n", sys);
        getgs();            printf("gs = 0x%x\n", gs);
        getta();
        return 0;
}
