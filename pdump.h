/* (c) 2019 martin */

#ifndef HAVE_PDUMP_H
#define HAVE_PDUMP_H

#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

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

#define	PTRACE_DETACH(pid) 						\
	do {								\
		if (ptrace(PTRACE_DETACH, pid, 0,0) == -1) {		\
			perror("+pdump: oops: PTRACE_DETACH");		\
			exit(1);					\
		}							\
	} while(0);						


struct opts_t {
        char* chldpath;			// path to child to be executed
        char* ldpath;			// path to ld.so
        char* dpath;			// path to a dump file
        size_t dsize;			// how much to dump
        unsigned long mask;		// preffered mask
        int reg;			// register that holds .text address before brk()
	int verbose;			// verbose toggle
};

struct regentry_t {
	char* name;
	int idx;
}; 

#ifdef __x86_64__
// let's keep the name different to one defined in sys/reg.h
enum regidx_t {
	reg_rax= 0, reg_rbx, reg_rcx, reg_rdx, reg_rsi, reg_rdi, reg_rbp, reg_rsp, reg_r8, reg_r9, reg_r10,
	reg_r11, reg_r12, reg_r13, reg_r14, reg_r15, reg_rip
};

struct regentry_t  reg_lookup_tbl[] = {
	{ "rax", RAX }, { "rbx", RBX }, { "rcx", RCX }, { "rdx", RDX }, { "rsi", RSI },
	{ "rdi", RDI }, { "rbp", RBP }, { "rsp", RSP }, { "r8", R8 }, { "r9", R9 },
	{ "r10", R10 }, { "r11", R11 }, { "r12", R12 }, { "r13", R13 }, { "r14", R14 },
	{ "r15", R14 }, { "rip", RIP }
};

#define	DEFAULT_LD			"/lib64/ld-linux-x86-64.so.2"
#define	DEFAULT_BASEREG			( reg_rbp )
#define	DEFAULT_MASK			0xfffffffffffff000

#else
enum regidx_t {
	reg_eax = 0, reg_ebx, reg_ecx, reg_edx, reg_esi, reg_edi, reg_ebp, reg_eip
};

struct regentry_t  reg_lookup_tbl[] = {
	{ "eax", EAX }, { "ebx", EBX }, { "ecx", ECX }, { "edx", EDX }, { "esi", ESI },
	{ "edi", EDI }, { "ebp", EBP }, { "eip", EIP }
};

#define	DEFAULT_LD			"/lib/ld-linux.so.2"
#define	DEFAULT_BASEREG			( reg_ebp )
#define	DEFAULT_MASK			0xfffff000
#endif

#define	DEFAULT_DUMP_FILE		"dump.out"
#define	DEFAULT_DUMP_SIZE		0x2000

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

// parse input arguments 
int handle_args(struct opts_t* o, int argc, char** argv);

// dump the contents of handful of registers
void regdump(struct user_regs_struct* r);

// print fancy usage
void usage();

#endif /* ifndef HAVE_PDUMP_H */
