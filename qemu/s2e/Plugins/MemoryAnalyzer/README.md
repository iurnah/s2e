Design of MemoryAnalysis S2E Plugin
===

####Table of Contents
- [Testing Program] (#Testing_Program)
- [Events(Signal) Based System Design](#Events_System)
	- [MemoryAnalysis.cpp](#MemoryAnalysis.cpp)
	- [SyscallMonitor.cpp](#SyscallMonitor.cpp)
	- [LibcallMonitor.cpp](#LibcallMonitor.cpp)
	- [shadow_mem.cpp](#shadow_mem.cpp)
- [](#)
- [](#)
- [](#)
- [](#)
- [](#)
- [](#)
- [](#)

<a name="Testing_Program" />
## Testing Program

I will use the following program to test the Plugin. After this simple program works perfect, we can start to looking into more complex one. The program is from [this document](http://www.di.uevora.pt/~lmr/syscalls.html) (Page 8).

     /*  open.c */

     #include <fcntl.h>         /* defines options flags */
     #include <sys/types.h>     /* defines types used by sys/stat.h */
     #include <sys/stat.h>      /* defines S_IREAD & S_IWRITE  */

     static char message[] = "Hello, world";

     int main()
     {
        int fd;
        char buffer[80];

        /* open datafile.dat for read/write access   (O_RDWR)
           create datafile.dat if it does not exist  (O_CREAT)
           return error if datafile already exists   (O_EXCL)
           permit read/write access to file  (S_IWRITE | S_IREAD)
        */
     fd = open("datafile.dat",O_RDWR | O_CREAT | O_EXCL, S_IREAD | S_IWRITE);
        if (fd != -1)
           {
           printf("datafile.dat opened for read/write access\n");
           write(fd, message, sizeof(message));
           lseek(fd, 0L, 0);     /* go back to the beginning of the file */
           if (read(fd, buffer, sizeof(message)) == sizeof(message))
              printf("\"%s\" was written to datafile.dat\n", buffer);
           else
              printf("*** error reading datafile.dat ***\n");
           close (fd);
           }
        else
           printf("*** datafile.dat already exists ***\n");
        exit (0);
     }

<a name="Events_System" />
## Events(Signal) Based System Design

__Story:__ Signals defined in plugin Header(.h), Connected in initialization step(.cpp), triggered by instrumenting function calls in QEMU. Those functions could be defined in plugins.

Other than the event based mechanism, we also should take care of the s2e custom instructions, combined with KLEE, are the engine of Symbolic execution. This is the second part of the design will be saved later.

<a name="MemoryAnalysis.cpp" />
## MemoryAnalysis.cpp

This file will implement the taint propagation when maintain a shadown memory data structure. The shadow memory is implemented in [shadow_mem.cpp](#shadow_mem.cpp), which is borrowed from Rewards implementation.

<a name="SyscallMonitor.cpp" />
## SyscallMonitor.cpp


<a name="LibcallMonitor.cpp" />
## LibcallMonitor.cpp


<a name="shadow_mem.cpp" />
## shadow_mem.cpp


## References
[]()