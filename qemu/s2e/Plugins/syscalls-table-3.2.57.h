{ 0, "sys_restart_syscall", 1, "", "", "", "", "", "", "" },
{ 1, "sys_exit", 1, "int", "", "", "", "", "", "" },
{ 2, "sys_fork", 7, "unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " struct pt_regs *" },
{ 3, "sys_read", 3, "unsigned int", " char __user *", " size_t", "", "", "", "" },
{ 4, "sys_write", 3, "unsigned int", " const char __user *", " size_t", "", "", "", "" },
{ 5, "sys_open", 3, "const char __user *", " int", " int", "", "", "", "" },
{ 6, "sys_close", 1, "unsigned int", "", "", "", "", "", "" },
{ 7, "sys_waitpid", 3, "pid_t", " int __user *", " int", "", "", "", "" },
{ 8, "sys_creat", 2, "const char __user *", " int", "", "", "", "", "" },
{ 9, "sys_link", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 10, "sys_unlink", 1, "const char __user *", "", "", "", "", "", "" },
{ 11, "sys_execve", 3, "char __user *", " char __user * __user *", " char __user * __user *", "", "", "", "" },
{ 12, "sys_chdir", 1, "const char __user *", "", "", "", "", "", "" },
{ 13, "sys_time", 1, "time_t __user *", "", "", "", "", "", "" },
{ 14, "sys_mknod", 3, "const char __user *", " int", " unsigned", "", "", "", "" },
{ 15, "sys_chmod", 2, "const char __user *", " mode_t", "", "", "", "", "" },
{ 16, "sys_lchown16", 3, "const char __user *", " old_uid_t", " old_gid_t", "", "", "", "" },
{ 17, "not implemented", "", "", "", "", "", "", "", "" },
{ 18, "sys_stat", 2, "const char __user *", " struct __old_kernel_stat __user *", "", "", "", "", "" },
{ 19, "sys_lseek", 3, "unsigned int", " off_t", " unsigned int", "", "", "", "" },
{ 20, "sys_getpid", 1, "", "", "", "", "", "", "" },
{ 21, "sys_mount", 5, "char __user *", " char __user *", " char __user *", " unsigned long", " void __user *", "", "" },
{ 22, "sys_oldumount", 1, "char __user *", "", "", "", "", "", "" },
{ 23, "sys_setuid16", 1, "old_uid_t", "", "", "", "", "", "" },
{ 24, "sys_getuid16", 1, "", "", "", "", "", "", "" },
{ 25, "sys_stime", 1, "time_t __user *", "", "", "", "", "", "" },
{ 26, "sys_ptrace", 4, "long", " long", " unsigned long", " unsigned long", "", "", "" },
{ 27, "sys_alarm", 1, "unsigned int", "", "", "", "", "", "" },
{ 28, "sys_fstat", 2, "unsigned int", " struct __old_kernel_stat __user *", "", "", "", "", "" },
{ 29, "sys_pause", 1, "", "", "", "", "", "", "" },
{ 30, "sys_utime", 2, "char __user *", " struct utimbuf __user *", "", "", "", "", "" },
{ 31, "not implemented", "", "", "", "", "", "", "", "" },
{ 32, "not implemented", "", "", "", "", "", "", "", "" },
{ 33, "sys_access", 2, "const char __user *", " int", "", "", "", "", "" },
{ 34, "sys_nice", 1, "int", "", "", "", "", "", "" },
{ 35, "not implemented", "", "", "", "", "", "", "", "" },
{ 36, "sys_sync", 1, "", "", "", "", "", "", "" },
{ 37, "sys_kill", 2, "int", " int", "", "", "", "", "" },
{ 38, "sys_rename", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 39, "sys_mkdir", 2, "const char __user *", " int", "", "", "", "", "" },
{ 40, "sys_rmdir", 1, "const char __user *", "", "", "", "", "", "" },
{ 41, "sys_dup", 1, "unsigned int", "", "", "", "", "", "" },
{ 42, "sys_pipe", 1, "int __user *", "", "", "", "", "", "" },
{ 43, "sys_times", 1, "struct tms __user *", "", "", "", "", "", "" },
{ 44, "not implemented", "", "", "", "", "", "", "", "" },
{ 45, "sys_brk", 1, "unsigned long", "", "", "", "", "", "" },
{ 46, "sys_setgid16", 1, "old_gid_t", "", "", "", "", "", "" },
{ 47, "sys_getgid16", 1, "", "", "", "", "", "", "" },
{ 48, "sys_signal", 2, "int", " __sighandler_t", "", "", "", "", "" },
{ 49, "sys_geteuid16", 1, "", "", "", "", "", "", "" },
{ 50, "sys_getegid16", 1, "", "", "", "", "", "", "" },
{ 51, "sys_acct", 1, "const char __user *", "", "", "", "", "", "" },
{ 52, "sys_umount", 2, "char __user *", " int", "", "", "", "", "" },
{ 53, "not implemented", "", "", "", "", "", "", "", "" },
{ 54, "sys_ioctl", 3, "unsigned int", " unsigned int", " unsigned long", "", "", "", "" },
{ 55, "sys_fcntl", 3, "unsigned int", " unsigned int", " unsigned long", "", "", "", "" },
{ 56, "not implemented", "", "", "", "", "", "", "", "" },
{ 57, "sys_setpgid", 2, "pid_t", " pid_t", "", "", "", "", "" },
{ 58, "not implemented", "", "", "", "", "", "", "", "" },
{ 59, "sys_olduname", 1, "struct oldold_utsname __user *", "", "", "", "", "", "" },
{ 60, "sys_umask", 1, "int", "", "", "", "", "", "" },
{ 61, "sys_chroot", 1, "const char __user *", "", "", "", "", "", "" },
{ 62, "sys_ustat", 2, "unsigned", " struct ustat __user *", "", "", "", "", "" },
{ 63, "sys_dup2", 2, "unsigned int", " unsigned int", "", "", "", "", "" },
{ 64, "sys_getppid", 1, "", "", "", "", "", "", "" },
{ 65, "sys_getpgrp", 1, "", "", "", "", "", "", "" },
{ 66, "sys_setsid", 1, "", "", "", "", "", "", "" },
{ 67, "sys_sigaction", 3, "int", " const struct old_sigaction __user *", " struct old_sigaction __user *", "", "", "", "" },
{ 68, "sys_sgetmask", 1, "", "", "", "", "", "", "" },
{ 69, "sys_ssetmask", 1, "int", "", "", "", "", "", "" },
{ 70, "sys_setreuid16", 2, "old_uid_t", " old_uid_t", "", "", "", "", "" },
{ 71, "sys_setregid16", 2, "old_gid_t", " old_gid_t", "", "", "", "", "" },
{ 72, "sys_sigsuspend", 3, "int", " int", " old_sigset_t", "", "", "", "" },
{ 73, "sys_sigpending", 1, "old_sigset_t __user *", "", "", "", "", "", "" },
{ 74, "sys_sethostname", 2, "char __user *", " int", "", "", "", "", "" },
{ 75, "sys_setrlimit", 2, "unsigned int", " struct rlimit __user *", "", "", "", "", "" },
{ 76, "sys_old_getrlimit", 2, "unsigned int", " struct rlimit __user *", "", "", "", "", "" },
{ 77, "sys_getrusage", 2, "int", " struct rusage __user *", "", "", "", "", "" },
{ 78, "sys_gettimeofday", 2, "struct timeval __user *", " struct timezone __user *", "", "", "", "", "" },
{ 79, "sys_settimeofday", 2, "struct timeval __user *", " struct timezone __user *", "", "", "", "", "" },
{ 80, "sys_getgroups16", 2, "int", " old_gid_t __user *", "", "", "", "", "" },
{ 81, "sys_setgroups16", 2, "int", " old_gid_t __user *", "", "", "", "", "" },
{ 82, "sys_old_select", 1, "struct sel_arg_struct __user *", "", "", "", "", "", "" },
{ 83, "sys_symlink", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 84, "sys_lstat", 2, "const char __user *", " struct __old_kernel_stat __user *", "", "", "", "", "" },
{ 85, "sys_readlink", 3, "const char __user *", " char __user *", " int", "", "", "", "" },
{ 86, "sys_uselib", 1, "const char __user *", "", "", "", "", "", "" },
{ 87, "sys_swapon", 2, "const char __user *", " int", "", "", "", "", "" },
{ 88, "sys_reboot", 4, "int", " int", " unsigned int", " void __user *", "", "", "" },
{ 89, "sys_old_readdir", 3, "unsigned", " struct old_linux_dirent __user *", " unsigned", "", "", "", "" },
{ 90, "sys_old_mmap", 1, "struct mmap_arg_struct __user *", "", "", "", "", "", "" },
{ 91, "sys_munmap", 2, "unsigned long", " size_t", "", "", "", "", "" },
{ 92, "sys_truncate", 2, "const char __user *", " long", "", "", "", "", "" },
{ 93, "sys_ftruncate", 2, "unsigned int", " unsigned long", "", "", "", "", "" },
{ 94, "sys_fchmod", 2, "unsigned int", " mode_t", "", "", "", "", "" },
{ 95, "sys_fchown16", 3, "unsigned int", " old_uid_t", " old_gid_t", "", "", "", "" },
{ 96, "sys_getpriority", 2, "int", " int", "", "", "", "", "" },
{ 97, "sys_setpriority", 3, "int", " int", " int", "", "", "", "" },
{ 98, "not implemented", "", "", "", "", "", "", "", "" },
{ 99, "sys_statfs", 2, "const char __user * path", " struct statfs __user *", "", "", "", "", "" },
{ 100, "sys_fstatfs", 2, "unsigned int", " struct statfs __user *", "", "", "", "", "" },
{ 101, "sys_ioperm", 3, "unsigned", " unsigned", "", "", "", "", "" },
{ 102, "sys_socketcall", 2, "int", " unsigned long __user *", "", "", "", "", "" },
{ 103, "sys_syslog", 3, "int", " char __user *", " int", "", "", "", "" },
{ 104, "sys_setitimer", 3, "int", " struct itimerval __user *", " struct itimerval __user *", "", "", "", "" },
{ 105, "sys_getitimer", 2, "int", " struct itimerval __user *", "", "", "", "", "" },
{ 106, "sys_newstat", 2, "const char __user *", " struct stat __user *", "", "", "", "", "" },
{ 107, "sys_newlstat", 2, "const char __user *", " struct stat __user *", "", "", "", "", "" },
{ 108, "sys_newfstat", 2, "unsigned int", " struct stat __user *", "", "", "", "", "" },
{ 109, "sys_uname", 1, "struct old_utsname __user *", "", "", "", "", "", "" },
{ 110, "sys_iopl", 2, "unsigned", " struct pt_regs *", "", "", "", "", "" },
{ 111, "sys_vhangup", 1, "", "", "", "", "", "", "" },
{ 112, "not implemented", "", "", "", "", "", "", "", "" },
{ 113, "sys_vm86old", 2, "struct vm86_struct __user *", " struct pt_regs *", "", "", "", "", "" },
{ 114, "sys_wait4", 4, "pid_t", " int __user *", " int", " struct rusage __user *", "", "", "" },
{ 115, "sys_swapoff", 1, "const char __user *", "", "", "", "", "", "" },
{ 116, "sys_sysinfo", 1, "struct sysinfo __user *", "", "", "", "", "", "" },
{ 117, "sys_ipc", 6, "unsigned int", " int", " unsigned long", " unsigned long", " void __user *", " long", "" },
{ 118, "sys_fsync", 1, "unsigned int", "", "", "", "", "", "" },
{ 119, "sys_sigreturn", 1, "struct pt_regs *", "", "", "", "", "", "" },
{ 120, "sys_clone", 4, "unsigned long", " unsigned long", " unsigned long", " unsigned long", "", "", "" },
{ 121, "sys_setdomainname", 2, "char __user *", " int", "", "", "", "", "" },
{ 122, "sys_newuname", 1, "struct new_utsname __user *", "", "", "", "", "", "" },
{ 123, "sys_modify_ldt", 3, "int", " void __user *", " unsigned", "", "", "", "" },
{ 124, "sys_adjtimex", 1, "struct timex __user *", "", "", "", "", "", "" },
{ 125, "sys_mprotect", 3, "unsigned long", " size_t", " unsigned long", "", "", "", "" },
{ 126, "sys_sigprocmask", 3, "int", " old_sigset_t __user *", " old_sigset_t __user *", "", "", "", "" },
{ 127, "not implemented", "", "", "", "", "", "", "", "" },
{ 128, "sys_init_module", 3, "void __user *", " unsigned long", " const char __user *", "", "", "", "" },
{ 129, "sys_delete_module", 2, "const char __user *", " unsigned int", "", "", "", "", "" },
{ 130, "not implemented", "", "", "", "", "", "", "", "" },
{ 131, "sys_quotactl", 4, "unsigned int", " const char __user *", " qid_t", " void __user *", "", "", "" },
{ 132, "sys_getpgid", 1, "pid_t", "", "", "", "", "", "" },
{ 133, "sys_fchdir", 1, "unsigned int", "", "", "", "", "", "" },
{ 134, "sys_bdflush", 2, "int", " long", "", "", "", "", "" },
{ 135, "sys_sysfs", 3, "int", " unsigned long", " unsigned long", "", "", "", "" },
{ 136, "sys_personality", 1, "unsigned int", "", "", "", "", "", "" },
{ 137, "not implemented", "", "", "", "", "", "", "", "" },
{ 138, "sys_setfsuid16", 1, "old_uid_t", "", "", "", "", "", "" },
{ 139, "sys_setfsgid16", 1, "old_gid_t", "", "", "", "", "", "" },
{ 140, "sys_llseek", 5, "unsigned int", " unsigned long", " unsigned long", " loff_t __user *", " unsigned int", "", "" },
{ 141, "sys_getdents", 3, "unsigned int", " struct linux_dirent __user *", " unsigned int", "", "", "", "" },
{ 142, "sys_select", 5, "int", " fd_set __user *", " fd_set __user *", " fd_set __user *", " struct timeval __user *", "", "" },
{ 143, "sys_flock", 2, "unsigned int", " unsigned int", "", "", "", "", "" },
{ 144, "sys_msync", 3, "unsigned long", " size_t", " int", "", "", "", "" },
{ 145, "sys_readv", 3, "unsigned long", " const struct iovec __user *", " unsigned long", "", "", "", "" },
{ 146, "sys_writev", 3, "unsigned long", " const struct iovec __user *", " unsigned long", "", "", "", "" },
{ 147, "sys_getsid", 1, "pid_t", "", "", "", "", "", "" },
{ 148, "sys_fdatasync", 1, "unsigned int", "", "", "", "", "", "" },
{ 149, "sys_sysctl", 1, "struct __sysctl_args __user *", "", "", "", "", "", "" },
{ 150, "sys_mlock", 2, "unsigned long", " size_t", "", "", "", "", "" },
{ 151, "sys_munlock", 2, "unsigned long", " size_t", "", "", "", "", "" },
{ 152, "sys_mlockall", 1, "int", "", "", "", "", "", "" },
{ 153, "sys_munlockall", 1, "", "", "", "", "", "", "" },
{ 154, "sys_sched_setparam", 2, "pid_t", " struct sched_param __user *", "", "", "", "", "" },
{ 155, "sys_sched_getparam", 2, "pid_t", " struct sched_param __user *", "", "", "", "", "" },
{ 156, "sys_sched_setscheduler", 3, "pid_t", " int", " struct sched_param __user *", "", "", "", "" },
{ 157, "sys_sched_getscheduler", 1, "pid_t", "", "", "", "", "", "" },
{ 158, "sys_sched_yield", 1, "", "", "", "", "", "", "" },
{ 159, "sys_sched_get_priority_max", 1, "int", "", "", "", "", "", "" },
{ 160, "sys_sched_get_priority_min", 1, "int", "", "", "", "", "", "" },
{ 161, "sys_sched_rr_get_interval", 2, "pid_t", " struct timespec __user *", "", "", "", "", "" },
{ 162, "sys_nanosleep", 2, "struct timespec __user *", " struct timespec __user *", "", "", "", "", "" },
{ 163, "sys_mremap", 5, "unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 164, "sys_setresuid16", 3, "old_uid_t", " old_uid_t", " old_uid_t", "", "", "", "" },
{ 165, "sys_getresuid16", 3, "old_uid_t __user *", " old_uid_t __user *", " old_uid_t __user *", "", "", "", "" },
{ 166, "sys_vm86", 3, "unsigned", " unsigned", " struct pt_regs *", "", "", "", "" },
{ 167, "not implemented", "", "", "", "", "", "", "", "" },
{ 168, "sys_poll", 3, "struct pollfd __user *", " unsigned int", " long", "", "", "", "" },
{ 169, "not implemented", "", "", "", "", "", "", "", "" },
{ 170, "sys_setresgid16", 3, "old_gid_t", " old_gid_t", " old_gid_t", "", "", "", "" },
{ 171, "sys_getresgid16", 3, "old_gid_t __user *", " old_gid_t __user *", " old_gid_t __user *", "", "", "", "" },
{ 172, "sys_prctl", 5, "int", " unsigned long", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 173, "sys_rt_sigreturn", 1, "", "", "", "", "", "", "" },
{ 174, "sys_rt_sigaction", 4, "int", " const struct sigaction __user *", " struct sigaction __user *", " size_t", "", "", "" },
{ 175, "sys_rt_sigprocmask", 4, "int", " sigset_t __user *", " sigset_t __user *", " size_t", "", "", "" },
{ 176, "sys_rt_sigpending", 2, "sigset_t __user *", " size_t", "", "", "", "", "" },
{ 177, "sys_rt_sigtimedwait", 4, "const sigset_t __user *", " siginfo_t __user *", " const struct timespec __user *", " size_t", "", "", "" },
{ 178, "sys_rt_sigqueueinfo", 3, "int", " int", " siginfo_t __user *", "", "", "", "" },
{ 179, "sys_rt_sigsuspend", 2, "sigset_t __user *", " size_t", "", "", "", "", "" },
{ 180, "sys_pread64", 4, "unsigned int", " char __user *", " size_t", " loff_t", "", "", "" },
{ 181, "sys_pwrite64", 4, "unsigned int", " const char __user *", " size_t", " loff_t", "", "", "" },
{ 182, "sys_chown16", 3, "const char __user *", " old_uid_t", " old_gid_t", "", "", "", "" },
{ 183, "sys_getcwd", 2, "char __user *", " unsigned long", "", "", "", "", "" },
{ 184, "sys_capget", 2, "cap_user_header_t", " cap_user_data_t", "", "", "", "", "" },
{ 185, "sys_capset", 2, "cap_user_header_t", " const cap_user_data_t", "", "", "", "", "" },
{ 186, "sys_sigaltstack", 7, "const stack_t __user *", " stack_t __user *", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " struct pt_regs *" },
{ 187, "sys_sendfile", 4, "int", " int", " off_t __user *", " size_t", "", "", "" },
{ 188, "not implemented", "", "", "", "", "", "", "", "" },
{ 189, "not implemented", "", "", "", "", "", "", "", "" },
{ 190, "sys_vfork", 7, "unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " struct pt_regs *" },
{ 191, "sys_getrlimit", 2, "unsigned int", " struct rlimit __user *", "", "", "", "", "" },
{ 192, "sys_mmap_pgoff", 6, "unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", "" },
{ 193, "sys_truncate64", 2, "const char __user *", " loff_t", "", "", "", "", "" },
{ 194, "sys_ftruncate64", 2, "unsigned int", " loff_t", "", "", "", "", "" },
{ 195, "sys_stat64", 2, "const char __user *", " struct stat64 __user *", "", "", "", "", "" },
{ 196, "sys_lstat64", 2, "const char __user *", " struct stat64 __user *", "", "", "", "", "" },
{ 197, "sys_fstat64", 2, "unsigned long", " struct stat64 __user *", "", "", "", "", "" },
{ 198, "sys_lchown", 3, "const char __user *", " uid_t", " gid_t", "", "", "", "" },
{ 199, "sys_getuid", 1, "", "", "", "", "", "", "" },
{ 200, "sys_getgid", 1, "", "", "", "", "", "", "" },
{ 201, "sys_geteuid", 1, "", "", "", "", "", "", "" },
{ 202, "sys_getegid", 1, "", "", "", "", "", "", "" },
{ 203, "sys_setreuid", 2, "uid_t", " uid_t", "", "", "", "", "" },
{ 204, "sys_setregid", 2, "gid_t", " gid_t", "", "", "", "", "" },
{ 205, "sys_getgroups", 2, "int", " gid_t __user *", "", "", "", "", "" },
{ 206, "sys_setgroups", 2, "int", " gid_t __user *", "", "", "", "", "" },
{ 207, "sys_fchown", 3, "unsigned int", " uid_t", " gid_t", "", "", "", "" },
{ 208, "sys_setresuid", 3, "uid_t", " uid_t", " uid_t", "", "", "", "" },
{ 209, "sys_getresuid", 3, "uid_t __user *", " uid_t __user *", " uid_t __user *", "", "", "", "" },
{ 210, "sys_setresgid", 3, "gid_t", " gid_t", " gid_t", "", "", "", "" },
{ 211, "sys_getresgid", 3, "gid_t __user *", " gid_t __user *", " gid_t __user *", "", "", "", "" },
{ 212, "sys_chown", 3, "const char __user *", " uid_t", " gid_t", "", "", "", "" },
{ 213, "sys_setuid", 1, "uid_t", "", "", "", "", "", "" },
{ 214, "sys_setgid", 1, "gid_t", "", "", "", "", "", "" },
{ 215, "sys_setfsuid", 1, "uid_t", "", "", "", "", "", "" },
{ 216, "sys_setfsgid", 1, "gid_t", "", "", "", "", "", "" },
{ 217, "sys_pivot_root", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 218, "sys_mincore", 3, "unsigned long", " size_t", " unsigned char __user * vec", "", "", "", "" },
{ 219, "sys_madvise", 3, "unsigned long", " size_t", " int", "", "", "", "" },
{ 220, "sys_getdents64", 3, "unsigned int", " struct linux_dirent64 __user *", " unsigned int", "", "", "", "" },
{ 221, "sys_fcntl64", 3, "unsigned int", " unsigned int", " unsigned long", "", "", "", "" },
{ 222, "not implemented", "", "", "", "", "", "", "", "" },
{ 223, "not implemented", "", "", "", "", "", "", "", "" },
{ 224, "sys_gettid", 1, "", "", "", "", "", "", "" },
{ 225, "sys_readahead", 3, "int", " loff_t", " size_t", "", "", "", "" },
{ 226, "sys_setxattr", 5, "const char __user *", " const char __user *", " const void __user *", " size_t", " int", "", "" },
{ 227, "sys_lsetxattr", 5, "const char __user *", " const char __user *", " const void __user *", " size_t", " int", "", "" },
{ 228, "sys_fsetxattr", 5, "int", " const char __user *", " const void __user *", " size_t", " int", "", "" },
{ 229, "sys_getxattr", 4, "const char __user *", " const char __user *", " void __user *", " size_t", "", "", "" },
{ 230, "sys_lgetxattr", 4, "const char __user *", " const char __user *", " void __user *", " size_t", "", "", "" },
{ 231, "sys_fgetxattr", 4, "int", " const char __user *", " void __user *", " size_t", "", "", "" },
{ 232, "sys_listxattr", 3, "const char __user *", " char __user *", " size_t", "", "", "", "" },
{ 233, "sys_llistxattr", 3, "const char __user *", " char __user *", " size_t", "", "", "", "" },
{ 234, "sys_flistxattr", 3, "int", " char __user *", " size_t", "", "", "", "" },
{ 235, "sys_removexattr", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 236, "sys_lremovexattr", 2, "const char __user *", " const char __user *", "", "", "", "", "" },
{ 237, "sys_fremovexattr", 2, "int", " const char __user *", "", "", "", "", "" },
{ 238, "sys_tkill", 2, "int", " int", "", "", "", "", "" },
{ 239, "sys_sendfile64", 4, "int", " int", " loff_t __user *", " size_t", "", "", "" },
{ 240, "sys_futex", 6, "u32 __user *", " int", " u32", " struct timespec __user *", " u32 __user *", " u32", "" },
{ 241, "sys_sched_setaffinity", 3, "pid_t", " unsigned int", " unsigned long __user *", "", "", "", "" },
{ 242, "sys_sched_getaffinity", 3, "pid_t", " unsigned int", " unsigned long __user *", "", "", "", "" },
{ 243, "sys_set_thread_area", 1, "struct user_desc __user *", "", "", "", "", "", "" },
{ 244, "sys_get_thread_area", 1, "struct user_desc __user *", "", "", "", "", "", "" },
{ 245, "sys_io_setup", 2, "unsigned", " aio_context_t __user *", "", "", "", "", "" },
{ 246, "sys_io_destroy", 1, "aio_context_t", "", "", "", "", "", "" },
{ 247, "sys_io_getevents", 5, "aio_context_t", " long", " long", " struct io_event __user *", " struct timespec __user *", "", "" },
{ 248, "sys_io_submit", 3, "aio_context_t", "", " struct iocb __user * __user *", "", "", "", "" },
{ 249, "sys_io_cancel", 3, "aio_context_t", " struct iocb __user *", " struct io_event __user *", "", "", "", "" },
{ 250, "sys_fadvise64", 4, "int", " loff_t", " size_t", " int", "", "", "" },
{ 251, "not implemented", "", "", "", "", "", "", "", "" },
{ 252, "sys_exit_group", 1, "int", "", "", "", "", "", "" },
{ 253, "sys_lookup_dcookie", 3, "u64", " char __user *", " size_t", "", "", "", "" },
{ 254, "sys_epoll_create", 1, "int", "", "", "", "", "", "" },
{ 255, "sys_epoll_ctl", 4, "int", " int", " int", " struct epoll_event __user *", "", "", "" },
{ 256, "sys_epoll_wait", 4, "int", " struct epoll_event __user *", " int", " int", "", "", "" },
{ 257, "sys_remap_file_pages", 5, "unsigned long", " unsigned long", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 258, "sys_set_tid_address", 1, "int __user *", "", "", "", "", "", "" },
{ 259, "sys_timer_create", 3, "clockid_t", " struct sigevent __user *", " timer_t __user * created_timer_id", "", "", "", "" },
{ 260, "sys_timer_settime", 4, "timer_t", " int", " const struct itimerspec __user *", " struct itimerspec __user *", "", "", "" },
{ 261, "sys_timer_gettime", 2, "timer_t", " struct itimerspec __user *", "", "", "", "", "" },
{ 262, "sys_timer_getoverrun", 1, "timer_t", "", "", "", "", "", "" },
{ 263, "sys_timer_delete", 1, "timer_t", "", "", "", "", "", "" },
{ 264, "sys_clock_settime", 2, "clockid_t", " const struct timespec __user *", "", "", "", "", "" },
{ 265, "sys_clock_gettime", 2, "clockid_t", " struct timespec __user *", "", "", "", "", "" },
{ 266, "sys_clock_getres", 2, "clockid_t", " struct timespec __user *", "", "", "", "", "" },
{ 267, "sys_clock_nanosleep", 4, "clockid_t", " int", " const struct timespec __user *", " struct timespec __user *", "", "", "" },
{ 268, "sys_statfs64", 3, "const char __user *", " size_t", " struct statfs64 __user *", "", "", "", "" },
{ 269, "sys_fstatfs64", 3, "unsigned int", " size_t", " struct statfs64 __user *", "", "", "", "" },
{ 270, "sys_tgkill", 3, "int", " int", " int", "", "", "", "" },
{ 271, "sys_utimes", 2, "char __user *", " struct timeval __user *", "", "", "", "", "" },
{ 272, "sys_fadvise64_64", 4, "int", " loff_t", " loff_t", " int", "", "", "" },
{ 273, "not implemented", "", "", "", "", "", "", "", "" },
{ 274, "sys_mbind", 6, "unsigned long", " unsigned long", " unsigned long", " unsigned long __user *", " unsigned long", " unsigned", "" },
{ 275, "sys_get_mempolicy", 5, "int __user *", " unsigned long __user *", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 276, "sys_set_mempolicy", 3, "int", " unsigned long __user *", " unsigned long", "", "", "", "" },
{ 277, "sys_mq_open", 4, "const char __user *", " int", " mode_t", " struct mq_attr __user *", "", "", "" },
{ 278, "sys_mq_unlink", 1, "const char __user *", "", "", "", "", "", "" },
{ 279, "sys_mq_timedsend", 5, "mqd_t", " const char __user *", " size_t", " unsigned int", " const struct timespec __user *", "", "" },
{ 280, "sys_mq_timedreceive", 5, "mqd_t", " char __user *", " size_t", " unsigned int __user *", " const struct timespec __user *", "", "" },
{ 281, "sys_mq_notify", 2, "mqd_t", " const struct sigevent __user *", "", "", "", "", "" },
{ 282, "sys_mq_getsetattr", 3, "mqd_t", " const struct mq_attr __user *", " struct mq_attr __user *", "", "", "", "" },
{ 283, "sys_kexec_load", 4, "unsigned long", " unsigned long", " struct kexec_segment __user *", " unsigned long", "", "", "" },
{ 284, "sys_waitid", 5, "int", " pid_t", " struct siginfo __user *", " int", " struct rusage __user *", "", "" },
{ 285, "not implemented", "", "", "", "", "", "", "", "" },
{ 286, "sys_add_key", 5, "const char __user *", " const char __user *", " const void __user *", " size_t", " key_serial_t", "", "" },
{ 287, "sys_request_key", 4, "const char __user *", " const char __user *", " const char __user *", " key_serial_t", "", "", "" },
{ 288, "sys_keyctl", 5, "int", " unsigned long", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 289, "sys_ioprio_set", 3, "int", " int", " int", "", "", "", "" },
{ 290, "sys_ioprio_get", 2, "int", " int", "", "", "", "", "" },
{ 291, "sys_inotify_init", 1, "", "", "", "", "", "", "" },
{ 292, "sys_inotify_add_watch", 3, "int", " const char __user *", " u32", "", "", "", "" },
{ 293, "sys_inotify_rm_watch", 2, "int", " __s32", "", "", "", "", "" },
{ 294, "sys_migrate_pages", 4, "pid_t", " unsigned long", " const unsigned long __user *", " const unsigned long __user *", "", "", "" },
{ 295, "sys_openat", 4, "int", " const char __user *", " int", " int", "", "", "" },
{ 296, "sys_mkdirat", 3, "int", " const char __user * pathname", " int", "", "", "", "" },
{ 297, "sys_mknodat", 4, "int", " const char __user * filename", " int", " unsigned", "", "", "" },
{ 298, "sys_fchownat", 5, "int", " const char __user *", " uid_t", " gid_t", " int", "", "" },
{ 299, "sys_futimesat", 3, "int", " const char __user *", " struct timeval __user *", "", "", "", "" },
{ 300, "sys_fstatat64", 4, "int", " const char __user *", " struct stat64 __user *", " int", "", "", "" },
{ 301, "sys_unlinkat", 3, "int", " const char __user * pathname", " int", "", "", "", "" },
{ 302, "sys_renameat", 4, "int", " const char __user * oldname", " int", " const char __user * newname", "", "", "" },
{ 303, "sys_linkat", 5, "int", " const char __user *", " int", " const char __user *", " int", "", "" },
{ 304, "sys_symlinkat", 3, "const char __user * oldname", " int", " const char __user * newname", "", "", "", "" },
{ 305, "sys_readlinkat", 4, "int", " const char __user *", " char __user *", " int", "", "", "" },
{ 306, "sys_fchmodat", 3, "int", " const char __user * filename", " mode_t", "", "", "", "" },
{ 307, "sys_faccessat", 3, "int", " const char __user *", " int", "", "", "", "" },
{ 308, "sys_pselect6", 6, "int", " fd_set __user *", " fd_set __user *", " fd_set __user *", " struct timespec __user *", " void __user *", "" },
{ 309, "sys_ppoll", 5, "struct pollfd __user *", " unsigned int", " struct timespec __user *", " const sigset_t __user *", " size_t", "", "" },
{ 310, "sys_unshare", 1, "unsigned long", "", "", "", "", "", "" },
{ 311, "sys_set_robust_list", 2, "struct robust_list_head __user *", " size_t", "", "", "", "", "" },
{ 312, "sys_get_robust_list", 3, "int", " struct robust_list_head __user * __user *", " size_t __user *", "", "", "", "" },
{ 313, "sys_splice", 6, "int", " loff_t __user *", " int", " loff_t __user *", " size_t", " unsigned int", "" },
{ 314, "sys_sync_file_range", 4, "int", " loff_t", " loff_t", " unsigned int", "", "", "" },
{ 315, "sys_tee", 4, "int", " int", " size_t", " unsigned int", "", "", "" },
{ 316, "sys_vmsplice", 4, "int", " const struct iovec __user *", " unsigned long", " unsigned int", "", "", "" },
{ 317, "sys_move_pages", 6, "pid_t", " unsigned long", " const void __user * __user *", " const int __user *", " int __user *", " int", "" },
{ 318, "sys_getcpu", 3, "unsigned __user *", " unsigned __user *", " struct getcpu_cache __user *", "", "", "", "" },
{ 319, "sys_epoll_pwait", 6, "int", " struct epoll_event __user *", " int", " int", " const sigset_t __user *", " size_t", "" },
{ 320, "sys_utimensat", 4, "int", " const char __user *", " struct timespec __user *", " int", "", "", "" },
{ 321, "sys_signalfd", 3, "int", " sigset_t __user *", " size_t", "", "", "", "" },
{ 322, "sys_timerfd_create", 2, "int", " int", "", "", "", "", "" },
{ 323, "sys_eventfd", 1, "unsigned int", "", "", "", "", "", "" },
{ 324, "sys_fallocate", 4, "int", " int", " loff_t", " loff_t", "", "", "" },
{ 325, "sys_timerfd_settime", 4, "int", " int", " const struct itimerspec __user *", " struct itimerspec __user *", "", "", "" },
{ 326, "sys_timerfd_gettime", 2, "int", " struct itimerspec __user *", "", "", "", "", "" },
{ 327, "sys_signalfd4", 4, "int", " sigset_t __user *", " size_t", " int", "", "", "" },
{ 328, "sys_eventfd2", 2, "unsigned int", " int", "", "", "", "", "" },
{ 329, "sys_epoll_create1", 1, "int", "", "", "", "", "", "" },
{ 330, "sys_dup3", 3, "unsigned int", " unsigned int", " int", "", "", "", "" },
{ 331, "sys_pipe2", 2, "int __user *", " int", "", "", "", "", "" },
{ 332, "sys_inotify_init1", 1, "int", "", "", "", "", "", "" },
{ 333, "sys_preadv", 5, "unsigned long", " const struct iovec __user *", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 334, "sys_pwritev", 5, "unsigned long", " const struct iovec __user *", " unsigned long", " unsigned long", " unsigned long", "", "" },
{ 335, "sys_rt_tgsigqueueinfo", 4, "pid_t", " pid_t", " int", " siginfo_t __user *", "", "", "" },
{ 336, "sys_perf_event_open", 5, " struct perf_event_attr __user *", " pid_t", " int", " int", " unsigned long", "", "" },
{ 337, "sys_recvmmsg", 5, "int", " struct mmsghdr __user *", " unsigned int", " unsigned", " struct timespec __user *", "", "" },
{ 338, "sys_fanotify_init", 2, "unsigned int", " unsigned int", "", "", "", "", "" },
{ 339, "sys_fanotify_mark", 5, "int", " unsigned int", " u64", " int", " const char __user *", "", "" },
{ 340, "sys_prlimit64", 4, "pid_t", " unsigned int", " const struct rlimit64 __user *", " struct rlimit64 __user *", "", "", "" },
{ 341, "sys_name_to_handle_at", 5, "int", " const char __user *", " struct file_handle __user *", " int __user *", " int", "", "" },
{ 342, "sys_open_by_handle_at", 3, "int", " struct file_handle __user *", " int", "", "", "", "" },
{ 343, "sys_clock_adjtime", 2, "clockid_t", " struct timex __user *", "", "", "", "", "" },
{ 344, "sys_syncfs", 1, "int", "", "", "", "", "", "" },
{ 345, "sys_sendmmsg", 4, "int", " struct mmsghdr __user *", " unsigned int", " unsigned", "", "", "" },
{ 346, "sys_setns", 2, "int", " int", "", "", "", "", "" },
{ 347, "sys_process_vm_readv", 6, "pid_t", " const struct iovec __user *", " unsigned long", " const struct iovec __user *", " unsigned long", " unsigned long", "" },
{ 348, "sys_process_vm_writev", 6, "pid_t", " const struct iovec __user *", " unsigned long", " const struct iovec __user *", " unsigned long", " unsigned long", "" },
