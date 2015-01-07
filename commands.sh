#0. ###############################################################################
#
# copy the guest tools from host to guest.
#
###################################################################################
# boot qemu
./build/i386-softmmu/qemu-system-i386 ../s2e-discs/s2e_disk.raw

# copy stuff
scp <your_login_on_host>@<your_host_name>:path/to/tutorial1.c .

#1. ###############################################################################
#
# save vm in non-s2e mode and reboot in s2e mode
#
###################################################################################
./build/qemu-release/i386-softmmu/qemu-system-i386 -net none your_image.raw.s2e
# Wait until Linux is loaded, login into the system. Then press
# Ctrl + Alt + 2 and type 'savevm 1' then 'quit'.
# Notice that we use i386-softmmu, which is the build with S2E **disabled**.
./build/qemu-release/i386-s2e-softmmu/qemu-system-i386 -m 512M -net none ../s2e-discs/s2e_disk.raw.s2e -loadvm 1 -s2e-config-file ./config/memorytracer.lua -s2e-verbose
# Wait until the snapshot is resumed, then type in the guest 

./tutorial1
# Notice that we use i386-s2e-softmmu, which is the build with S2E ENABLED.

#2. ###############################################################################
#
# guest command
#
###################################################################################
LD_PRELOAD=./guest/build/init_env.so ./prog2 --select-process-code --sym-args 0 1 1; ./guest/build/s2ecmd kill 0 "message want to output"

#3. ###############################################################################
#
# output memory trace and other utilities
#
###################################################################################
#This is to get the memory tracer from the binary file.
./build/tools-release/Release+Asserts/bin/tbtrace -trace=./s2e-out-7/ExecutionTracer.dat -outputdir=./s2e-out-7/traces -printMemory -printRegisters

#This is to get the coverage of the code from the trace results.
./build/tools-release/Release+Asserts/bin/coverage -trace=./s2e-last/ExecutionTracer.dat -outputdir=./s2e-last/ -moddir=./coverage/

#4. ###############################################################################
#
# using s2eget command
#
###################################################################################
# 1. using the s2eget command on guest
./build/qemu-release/i386-softmmu/qemu-system-i386 -m 512M -net none your_image.raw.s2e
# 2. this will stuck,
./s2eget <program>
# 3. save a virtual machine, when reboot the virtual machine, the program will be copied
# 4. Ctrl + Alt + 2 and type 'savevm 1' then 'quit'.
# 5. start with s2e mode,
./build/qemu-release/i386-s2e-softmmu/qemu-system-i386 -m 512M -net none ../s2e-discs/s2e_disk.raw.s2e -loadvm 1 -s2e-config-file ./config/memorytracer.lua -s2e-verbose

#5. ###############################################################################
#
# run QEMU with native build and copying file to guest
#
###################################################################################
./build/qemu-release/i386-softmmu/qemu-system-i386 your_image.raw
# scp coping the test code to guest machine
scp <your_login_on_host>@<your_host_name>:path/to/tutorial1.c .
scp <your_login_on_host>@<your_host_name>:path/to/s2e/guest/include/s2e.h .
# compile and run code in the guest
gcc -O3 tutorial1.c -o tutorial1
./tutorial
