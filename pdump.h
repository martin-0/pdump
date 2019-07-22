/* (c) 2019 martin */

#ifndef HAVE_TRACER_H
#define HAVE_TRACER_H

#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>

#define	PTRACE_GETREGS(pid, regs)					\
	do {								\
		if (ptrace(PTRACE_GETREGS, pid , NULL, regs) == -1) {	\
			perror ("+pdump: oops: PTRACE_GETREGS");	\
			PTRACE_DETACH(pid)				\
			exit(1);					\
		}							\
	} while(0);			

#define	PTRACE_SETREGS(pid, regs)					\
	do {								\
		if (ptrace(PTRACE_SETREGS, pid , NULL, regs) == -1) {	\
			perror ("+pdump: oops: PTRACE_SETREGS");	\
			PTRACE_DETACH(pid)				\
			exit(1);					\
		}							\
	} while(0);			

#define	PTRACE_SYSCALL(pid) 						\
	do {								\
		if (ptrace(PTRACE_SYSCALL, pid, 0,0) == -1) {		\
			perror("+pdump: oops: PTRACE_SYSCALL");	\
			PTRACE_DETACH(pid)				\
			exit(1);					\
		}							\
	} while(0);						

#define	PTRACE_SINGLESTEP(pid) 						\
	do {								\
		if (ptrace(PTRACE_SINGLESTEP, pid, 0,0) == -1) {	\
			perror("+pdump: oops: PTRACE_SINGLESTEP");	\
			PTRACE_DETACH(pid)				\
			exit(1);					\
		}							\
	} while(0);						

#endif

#define	PTRACE_DETACH(pid) 						\
	do {								\
		if (ptrace(PTRACE_DETACH, pid, 0,0) == -1) {		\
			perror("+pdump: oops: PTRACE_DETACH");		\
			exit(1);					\
		}							\
	} while(0);						


#define	DEFAULT_DUMP_FILE		"dump.out"
#define	DEFAULT_DUMP_SIZE		0x2000
#define	DEFAULT_DUMP_FD			1

#define	DEFAULT_LD64			"/lib64/ld-linux-x86-64.so.2"
#define	DEFAULT_LD32			"/lib/ld-linux.so.2"


// get the entry point address from library
unsigned long get_entry(char* lpath);

// trace the child till it starts executing new program
long get_to_ldentry(struct user_regs_struct* regs, pid_t pid, int* status);

// trace the child till the given ip
int trace_until(struct user_regs_struct* regs, unsigned long ip, pid_t pid, int* status);

// trace the child till it reaches given syscall
int catch_syscall(int* status, pid_t pid, long sysnr, int* intosys);

// assert the current child status ; terminate if child is finished
void assert_status(int* status, pid_t pid);

// prepare the child for the execution after main fork()
void handle_child(char* tracee);

// dump the contents of handful of registers
void regdump(struct user_regs_struct* r);
