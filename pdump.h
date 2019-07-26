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
        char* dpath;			// path to a dump file
        size_t dsize;			// how much to dump
	unsigned long d_addr;		// custom dump address
        unsigned long mask;		// preferred mask
        int reg;			// register that holds .text address before brk()
	int verbose;			// verbose toggle
	int is_static;			// indicates we are working on static binary
	int is_32b;			// tracee is 32b 
};

struct regentry_t {
	char* name;
	int idx;
}; 

#ifdef __x86_64__
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

#define	DEFAULT_BASEREG			( reg_rbp )
#define	DEFAULT_MASK			0xfffffffffffff000

// XXX: maybe I should use PTRACE_GETREGSET 
// some good hints can be found in strace:
//	https://github.com/bnoordhuis/strace/blob/master/syscall.c#L1250
//
// use these to detect the trace mode
#define	REG_CS_64			0x33
#define	REG_CS_x32			0x2bULL		// x32 mode (x86-64 in 32b)
#define	REG_CS_32_COMPAT		0x23ULL		// 32b

#define	SYS32_write			0x4
#define	SYS32_execve			0xb
#define	SYS32_brk			0x2d

#else
enum regidx_t {
	reg_eax = 0, reg_ebx, reg_ecx, reg_edx, reg_esi, reg_edi, reg_ebp, reg_esp, reg_eip
};

struct regentry_t  reg_lookup_tbl[] = {
	{ "eax", EAX }, { "ebx", EBX }, { "ecx", ECX }, { "edx", EDX }, { "esi", ESI },
	{ "edi", EDI }, { "ebp", EBP }, { "esp", UESP}, { "eip", EIP }
};

#define	DEFAULT_BASEREG			( reg_ebp )
#define	DEFAULT_MASK			0xfffff000
#endif	/* ifdef __x86_64__*/


#define	DEFAULT_DUMP_FILE		"dump.out"
#define	DEFAULT_DUMP_SIZE		0x2000

// trace the child till it starts executing new program and detect if tracee is 32b
long get_to_entry(struct user_regs_struct* regs, pid_t pid, int* status, struct opts_t* o);

// trace the child till the given ip
int trace_until(struct user_regs_struct* regs, unsigned long ip, pid_t pid, int* status);

// trace the child till it reaches given syscall
int catch_syscall(struct user_regs_struct* regs, int* status, pid_t pid, long sysnr, int* intosys);

// assert the current child status ; terminate if child is finished
void assert_status(int* status, pid_t pid);

// prepare the child for the execution after main fork()
void handle_child(char* tracee);

// parse input arguments 
int handle_args(struct opts_t* o, int argc, char** argv);

// dump the contents of handful of registers
void regdump(struct user_regs_struct* r);

// print parameters used during execution
void fancy_print(struct opts_t* o);

// print usage
void usage();

#endif /* ifndef HAVE_PDUMP_H */
