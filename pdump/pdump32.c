/* (c) 2019 martin */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <fcntl.h>

#include "pdump.h"

int main(int argc, char** argv) {
	if (argc < 2) {
		fprintf (stderr, "usage: %s /path/to/exe [ /path/to/ld.so ]\n", argv[0]);
		return -1;
	}

	char* ldpath;
	unsigned long ofst_ld_entry = 0;			// elf entry point in ld.so

	// default or user specified
	ldpath = (argc < 3) ? DEFAULT_LD32 : argv[2];

	ofst_ld_entry = get_entry(ldpath);
	fprintf (stderr, "+pdump: ld entry point: %lx\n", ofst_ld_entry);

	pid_t pid;
	if ( (pid=fork()) == 0) {
		handle_child(argv[1]);
	}

	struct user_regs_struct regs;
	unsigned long addr_ld_base = 0;				// current ld base 
	unsigned long ofst_ld_brk_in = 0;			// offset from ld base to brk() syscall entry
	int status, intosys;

	// STEP #1	get the brk() offset in ld.so 
	addr_ld_base = get_to_ldentry(&regs, pid, &status) - ofst_ld_entry;

	// continue the exectution to the next syscall ; the first syscall after execve() is brk()
	PTRACE_SYSCALL(pid)
	intosys = 1;
	while( (catch_syscall(&status, pid, SYS_brk, &intosys)) == 0);
	
	PTRACE_GETREGS(pid, &regs)

	ofst_ld_brk_in = regs.eip - 2 - addr_ld_base;		// -2 to compensate for either syscall or int 0x80

	fprintf(stderr, "+pdump: %u: ld base: 0x%.lx, offset brk: %lx\n", pid, addr_ld_base, ofst_ld_brk_in);

	// we don't care about this child any more .. make sure to wait for it before forking again..
	// XXX: maybe better check on status ?
	PTRACE_DETACH(pid)
	wait(&status);

	// STEP #2:	respawn the child again, stop on syscall/int 0x80 instruction
	if ( (pid=fork()) == 0) {
		handle_child(argv[1]);
	}
	
	unsigned long addr_ld_brk_in = 0;			// actual addr of the brk() in ld.so for current child

	// calculate the new ld_base (due to ASLR) and get the syscall in brk() instruction
	addr_ld_base = get_to_ldentry(&regs, pid, &status) - ofst_ld_entry;
	addr_ld_brk_in = addr_ld_base + ofst_ld_brk_in;

	fprintf (stderr, "+pdump: %u: ld base: 0x%lx, addr ld brk: 0x%lx\n", pid, addr_ld_base, addr_ld_brk_in);

	// trace until the brk() syscall instruction
	if ((trace_until(&regs, addr_ld_brk_in, pid, &status)) != 0) {
		fprintf (stderr, "+pdump: oops: neither trace_until() nor assert_status() didn't catch the condition..\n");
		PTRACE_DETACH(pid)
		exit(1);
	}
	regdump(&regs);

	unsigned long addr_pie_base;

	addr_pie_base = regs.ebp & 0xfffff000;
	fprintf(stderr,"+pdump: %u: child base: 0x%lx\n", pid, addr_pie_base);

	regs.ebx = 1;
	regs.ecx = addr_pie_base;
	regs.edx = DEFAULT_DUMP_SIZE;
	regs.eax = SYS_write;

	PTRACE_SETREGS(pid, &regs)
	PTRACE_DETACH(pid)

        return 0;
}

// requries child to be stopped just before its execve()
long get_to_ldentry(struct user_regs_struct* regs, pid_t pid, int* status) {
	long addr_ld_entry = 0;
	int intosys = 0;

	wait(status);
	assert_status(status, pid);

	if (WSTOPSIG(*status) != SIGSTOP) {
		fprintf(stderr, "oops: get_to_ldentry: process is expected to be stopped by SIGSTOP\n");
		PTRACE_DETACH(pid)
		exit(1);
	}

	// we should be in SIGSTOP now
	PTRACE_SYSCALL(pid)	

	// let the child do the execve()
	while( (catch_syscall(status, pid, SYS_execve, &intosys)) == 0);

	PTRACE_GETREGS(pid, regs)

	addr_ld_entry = regs->eip;

	#ifdef DEBUG
		fprintf(stdout, "DEBUG: get_to_ldentry: got ld_entry: 0x%lx\n", addr_ld_entry);
		regdump(regs);
	#endif
	return addr_ld_entry;
}

int catch_syscall(int* status, pid_t pid, long sysnr, int* intosys) {
	long curnr, ret;
	wait(status);
	assert_status(status, pid);

	if (WSTOPSIG(*status) == SIGTRAP) {
		/* There can be three reasons for SIGTRAP:	*/
		/* 	syscall entry				*/
		/*	syscall leave				*/
		/*	child calls exec			*/

		curnr = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ORIG_EAX, 0);
		ret = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EAX, 0);

		#ifdef DEBUG
			fprintf (stderr, "DEBUG: manage_wait: syscall: %ld, ret: %ld\n", curnr, ret);
		#endif

		// we caught the correct syscall
		if (curnr == sysnr) { 
			// if we are already in syscall we are now leaving and we are done
			if (*intosys)
				return 1;
		
			// else toggle the flag and continue execution	
			*intosys = 1;
		 }
	}

	PTRACE_SYSCALL(pid)
	return 0;	
}

// check if the status is still OK
void assert_status(int* status, pid_t pid) {
	// process finished normally
	if (WIFEXITED(*status)) {
		fprintf(stderr, "+pdump: %u: child finished already.\n", pid);
		exit(0);
	}

	// process was terminated due to receiving signal
	if (WIFSIGNALED(*status)) {
		fprintf(stderr, "+pdump: %u: child finished due to signal: %d\n", pid, WTERMSIG(*status));
		exit(0);
	}

	// handle the situation when the unexpected status
	if (!WIFSTOPPED(*status)) {
		fprintf(stderr, "+pdump: %u: wait() returned unhandled status 0x%x\n", pid, *status);
		PTRACE_DETACH(pid)
		exit(1);
        }
}

void handle_child(char* tracee) {
	/* child */
	if ( (ptrace(PTRACE_TRACEME, 0, 0, 0)) == 0) {
		kill(getpid(), SIGSTOP);

		execl(tracee, tracee, NULL);
		fprintf (stderr, "oops: execl() failed ..\n");
	}
	else {
		fprintf (stderr, "oops: ptrace() failed ..\n");
	}
	exit(2);
}

int trace_until(struct user_regs_struct* regs, unsigned long ip, pid_t pid, int* status) {
	while (1) { 
		PTRACE_SINGLESTEP(pid)
                wait(status);
		assert_status(status, pid);

		PTRACE_GETREGS(pid, regs)

		if (regs->eip == ip)
			return 0;
	}
	return -1;
}

void regdump(struct user_regs_struct* r) {
	fprintf (stderr, "eax\t\t0x%lx\nebx\t\t0x%lx\necx\t\t0x%lx\nedx\t\t0x%lx\n"
		"esp\t\t0x%lx\nebp\t\t0x%lx\nesi\t\t0x%lx\nedi\t\t0x%lx\neip\t\t0x%lx\n\n",
			r->eax, r->ebx, r->ecx, r->edx, r->esp, r->ebp, r->esi, r->edi, r->eip);
}

unsigned long get_entry(char* lib) {
	int fd;
	if ( (fd = open(lib, O_RDONLY)) < 0) {
		perror("oops: failed to open loader lib");
		exit(1);
	}
	unsigned long entry;

	lseek(fd, 0x18, SEEK_SET);
	read(fd, &entry, sizeof(entry));
	close(fd);
	return entry;
}
