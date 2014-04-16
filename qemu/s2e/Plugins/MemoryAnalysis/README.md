Design of MemoryAnalysis S2E Plugin
===

####Table of Contents
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


<a name="Events_System" />
## Events(Signal) Based System Design

__Story:__ Signals defined in plugin Header(.h), Connected in initialization step(.cpp), triggered by instrumenting function calls in QEMU. Those functions could be defined in plugins.

Other than the event based mechanism, we also should take care of the s2e custom instructions, combined with KLEE, are the engine of Symbolic execution. This is the second part of the design will be saved later.

<a name="MemoryAnalysis.cpp" />
## MemoryAnalysis.cpp

This file will implement the taint propagation when maintain a shadown memory data structure. The shadow memory is implemented in [shadow_mem.cpp](#shadow_mem.cpp)

<a name="SyscallMonitor.cpp" />
## SyscallMonitor.cpp


<a name="LibcallMonitor.cpp" />
## LibcallMonitor.cpp


<a name="shadow_mem.cpp" />
## shadow_mem.cpp