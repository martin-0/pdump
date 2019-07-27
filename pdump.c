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
#include <fcntl.h>

#include <string.h>
#include <ctype.h>

#include "pdump.h"

#define	VERSION	"0.4"

int main(int argc, char** argv) {
	struct opts_t opts;

	// set the options first
	handle_args(&opts, argc, argv);

	if (!opts.quiet) {
		fancy_print(&opts);
	}

	int dfd;						// dump fd
	if ( (dfd = open(opts.dpath, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
		fprintf(stderr, "oops: pdump: failed to open dump file %s ", opts.dpath);
		perror("");
		exit(1);
	}

	pid_t pid;
	if ( (pid=fork()) == 0) {
		handle_child(opts.chldpath);
	}

	struct user_regs_struct regs;
	unsigned long addr_start = 0;				// starting address of a program, ld.so or the actual program
	unsigned long ofst_to_brk_in = 0;			// offset from start address to brk() syscall entry
	int status, intosys, sysnr;

	sysnr = SYS_brk;					// first syscall to catch is SYS_brk

	// #STEP #1:	find the offset to brk() syscall

	// get the child to a state just after execve()
	addr_start = get_to_entry(&regs, pid, &status, &opts);

	// makes sense only on 64b platform
	#ifdef __x86_64__
	if (opts.is_32b) {
		opts.mask &= 0xffffffff;
		opts.d_addr &= 0xffffffff;
		sysnr = SYS32_brk;
	}
	#endif

	// continue the exectution to the next syscall; the first syscall after execve() is brk(), let's catch that
	PTRACE_SYSCALL(pid)
	intosys = 1;
	while( (catch_syscall(&regs, &status, pid, sysnr, &intosys)) == 0);
	
	PTRACE_GETREGS(pid, &regs)

	#ifdef __x86_64__
		ofst_to_brk_in = regs.rip - 2 - addr_start;		// -2 to compensate for either syscall or int 0x80
	#else
		ofst_to_brk_in = regs.eip - 2 - addr_start;		// -2 to compensate for either syscall or int 0x80
	#endif

	if (opts.quiet < 2)
		fprintf(stdout, "+pdump: %u: start address: 0x%.lx, offset to brk: 0x%lx\n\n", pid, addr_start, ofst_to_brk_in);

	// we don't care about the child any more.. 
	PTRACE_DETACH(pid)
	wait(&status);

	// child should be dead now .. stop if not
        if ( !WIFEXITED(status) && !WIFSIGNALED(status) ) {
                fprintf(stderr, "+pdump: oops: %u: child is still alive, aborting.\n", pid);
                exit(1);
        }

	// STEP #2:	respawn the child again, stop on syscall/int 0x80 instruction
	if ( (pid=fork()) == 0) {
		handle_child(opts.chldpath);
	}
	
	unsigned long addr_dump_base, addr_brk_in = 0;

	// calculate the new brk() syscall address
	addr_start = get_to_entry(&regs, pid, &status, &opts);
	addr_brk_in = addr_start + ofst_to_brk_in;		// in case of static binary ofst_to_brk_in is the actual address (-addr_start was done during first run)

	if (!opts.quiet) 
		fprintf (stdout, "+pdump: %u: addr start: 0x%lx, addr brk: 0x%lx\n", pid, addr_start, addr_brk_in);

	// trace until the brk() syscall instruction
	if ((trace_until(&regs, addr_brk_in, pid, &status)) != 0) {
		fprintf (stderr, "+pdump: oops: neither trace_until() nor assert_status() caught the condition..\n");
		PTRACE_DETACH(pid)
		exit(1);
	}

	// custom address has the highest priority
	if (opts.d_addr) {
		addr_dump_base = opts.d_addr;
	}
	// static binaries are not PIE
	else if (opts.is_static) {
		addr_dump_base = addr_start & opts.mask;
	}
	else {
		#ifdef __x86_64__
			addr_dump_base = *((unsigned long long*)&regs + reg_lookup_tbl[opts.reg].idx ) & opts.mask;
		#else
			addr_dump_base = *((unsigned long*)&regs + reg_lookup_tbl[opts.reg].idx ) & opts.mask;
		#endif
	}

	if (opts.quiet < 2)
		fprintf(stdout, "+pdump: %u: dump address: 0x%lx\n", pid, addr_dump_base);
	

	if (!opts.quiet) { 
		fprintf(stdout, "\n+pdump: %u: registers just before syscall:\n", pid);
		regdump(&regs);
	}

	#ifdef __x86_64__
		if (opts.is_32b) {
			regs.rbx = dfd;
			regs.rcx = addr_dump_base;
			regs.rdx = opts.dsize;
			regs.rax = SYS32_write;
		}
		else {
			regs.rdi = dfd;
			regs.rsi = addr_dump_base;
			regs.rdx = opts.dsize;
			regs.rax = SYS_write;
		}
	#else
		regs.ebx = dfd;
		regs.ecx = addr_dump_base;
		regs.edx = opts.dsize;
		regs.eax = SYS_write;
	#endif

	PTRACE_SETREGS(pid, &regs)
	PTRACE_DETACH(pid)

	close(dfd);

	if (!opts.quiet) 
		fprintf (stdout, "pdump: done.\n");

        return 0;
}

// requires child to be stopped just before its execve()
long get_to_entry(struct user_regs_struct* regs, pid_t pid, int* status, struct opts_t* o) {
	long addr_entry = 0;
	int intosys = 0;

	wait(status);
	assert_status(status, pid);

	if (WSTOPSIG(*status) != SIGSTOP) {
		fprintf(stderr, "oops: get_to_entry: process is expected to be stopped by SIGSTOP\n");
		PTRACE_DETACH(pid)
		exit(1);
	}

	#ifdef __x86_64__
		unsigned long sysnr_execve = SYS_execve;

		// special attention to %cs register is paid ; if it changes we are very likely tracing 32b process
		while (1) {
			PTRACE_SYSCALL(pid);

			wait(status);
			assert_status(status, pid);

			// basically do the catch_syscall() but pay attention to %cs register
			if (WSTOPSIG(*status) == SIGTRAP) {
				PTRACE_GETREGS(pid, regs);

				// detect 32b process
				if (regs->cs == REG_CS_x32 || regs->cs == REG_CS_32_COMPAT) {
					sysnr_execve = SYS32_execve;
					o->is_32b = 1;
		
					fprintf(stdout, "+pdump: %u: get_to_entry: 32b process detected.\n", pid);
				}
				if (regs->orig_rax == sysnr_execve) {
					// we are done
					if (intosys) 
						break;

					intosys = 1;
				}
			}
		}
	#else
		// on 32b we just need to catch SYS_execve
		PTRACE_SYSCALL(pid);
		while( (catch_syscall(regs, status, pid, SYS_execve, &intosys)) == 0);
	#endif 

	PTRACE_GETREGS(pid, regs)

	#ifdef __x86_64__
		addr_entry = regs->rip;
	#else
		addr_entry = regs->eip;
	#endif

	#ifdef DEBUG
		fprintf(stdout, "DEBUG: get_to_entry: got entry point: 0x%lx\n", addr_entry);
		regdump(regs);
	#endif

	return addr_entry;
}

int catch_syscall(struct user_regs_struct* regs, int* status, pid_t pid, long sysnr, int* intosys) {
	unsigned long curnr;

	#ifdef DEBUG
		unsigned long ret;
	#endif

	wait(status);
	assert_status(status, pid);

	if (WSTOPSIG(*status) == SIGTRAP) {
		/* There can be three reasons for SIGTRAP:	*/
		/* 	syscall entry				*/
		/*	syscall leave				*/
		/*	child calls exec			*/
		PTRACE_GETREGS(pid, regs);

		#ifdef __x86_64__
			curnr = regs->orig_rax;
			#ifdef DEBUG
				ret = regs->rax;
			#endif
		#else
			curnr = regs->orig_eax;
			#ifdef DEBUG
				ret = regs->eax;
			#endif
		#endif

		#if DEBUG > 1
			fprintf (stderr, "DEBUG: catch_syscall: syscall: %lx, catching: %lx, ret: %ld\n", curnr, sysnr, ret);
		#endif

		// we caught the correct syscall
		if (curnr == sysnr) { 
			// if we are already in syscall we are now leaving and we are done
			if (*intosys) {
				return 1;
			}
		
			// else toggle the flag and continue execution	
			*intosys = 1;
		 }
	}

	PTRACE_SYSCALL(pid)

	#if DEBUG > 1
		fprintf(stderr, "DEBUG: catch_syscall: end\n");
	#endif

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
	pid_t chpid = getpid();

	if ( (ptrace(PTRACE_TRACEME, 0, 0, 0)) == 0) {
		kill(chpid, SIGSTOP);

		execl(tracee, tracee, NULL);
		fprintf (stderr, "PID %u: oops: execl() failed ..\n", chpid);
	}
	else {
		fprintf (stderr, "PID %u: oops: ptrace() failed ..\n", chpid);
	}
	exit(2);
}

int trace_until(struct user_regs_struct* regs, unsigned long ip, pid_t pid, int* status) {
	while (1) { 
		PTRACE_SINGLESTEP(pid)
                wait(status);
		assert_status(status, pid);

		PTRACE_GETREGS(pid, regs)

		#ifdef __x86_64__
			if (regs->rip == ip)
				return 0;
		#else
			if (regs->eip == ip)
				return 0;
		#endif
	}
	return -1;
}

void regdump(struct user_regs_struct* r) {
	#ifdef __x86_64__
		fprintf (stdout,"rax\t\t0x%llx\nrbx\t\t0x%llx\nrcx\t\t0x%llx\nrdx\t\t0x%llx\n"
				"rsi\t\t0x%llx\nrdi\t\t0x%llx\nrbp\t\t0x%llx\nrsp\t\t0x%llx\n"
				"r8\t\t0x%llx\nr9\t\t0x%llx\nr10\t\t0x%llx\nr11\t\t0x%llx\n"
				"r12\t\t0x%llx\nr13\t\t0x%llx\nr14\t\t0x%llx\nr15\t\t0x%llx\nrip\t\t0x%llx\n\n", 
				r->rax, r->rbx, r->rcx, r->rdx, r->rsi, r->rdi, r->rbp, r->rsp, r->r8,
				r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15, r->rip);

	#else
		fprintf (stdout,"eax\t\t0x%lx\necx\t\t0x%lx\nedx\t\t0x%lx\nebx\t\t0x%lx\n"
				"esp\t\t0x%lx\nebp\t\t0x%lx\nesi\t\t0x%lx\nedi\t\t0x%lx\neip\t\t0x%lx\n\n",
				r->eax, r->ecx, r->edx, r->ebx, r->esp, r->ebp, r->esi, r->edi, r->eip);
	#endif
}

int handle_args(struct opts_t* o, int argc, char** argv) {
	int i,opt;

	// let's set defaults first
	o->chldpath = NULL;
	o->dpath = DEFAULT_DUMP_FILE;
	o->dsize = DEFAULT_DUMP_SIZE;
	o->d_addr = 0;
	o->mask = DEFAULT_MASK;
	o->reg = DEFAULT_BASEREG;
	o->quiet = 0;
	o->is_static = 0;
	o->is_32b = 0;

	while ((opt = getopt(argc, argv, "f:d:s:ta:m:r:qh?")) != -1 ) {
		switch(opt) {
		case 'f':	o->chldpath = optarg;
				break;

		case 'd':	o->dpath = optarg;
				break;

		case 's':	o->dsize = strtoll(optarg, 0, 16);
				break;

		case 't':	o->is_static = 1;
				break;

		case 'a':	o->d_addr = strtoll(optarg, 0, 16);
				break;

		case 'm':	// set custom mask when figuring out .text base address
				o->mask = strtoll(optarg, 0, 16);
				break;
	
		case 'r':	// map register name to idx
				for (i = 0; i < strlen(optarg); i++) {
					optarg[i] = tolower(optarg[i]);
				}

				// not exactly an eye candy.. 
				#ifdef __x86_64__
					if (strncmp(optarg, "rax", 3) == 0) {
						o->reg = reg_rax;
					}
					else if ((strncmp(optarg, "rbx", 3) == 0)) {
						o->reg = reg_rbx;
					}
					else if ((strncmp(optarg, "rcx", 3) == 0)) {
						o->reg = reg_rcx;
					}
					else if ((strncmp(optarg, "rdx", 3) == 0)) {
						o->reg = reg_rdx;
					}
					else if ((strncmp(optarg, "rsi", 3) == 0)) {
						o->reg = reg_rsi;
					}
					else if ((strncmp(optarg, "rdi", 3) == 0)) {
						o->reg = reg_rdi;
					}
					else if ((strncmp(optarg, "rbp", 3) == 0)) {
						o->reg = reg_rbp;
					}
					else if ((strncmp(optarg, "rsp", 3) == 0)) {
						o->reg = reg_rsp;
					}
					else if ((strncmp(optarg, "r8", 3) == 0)) {
						o->reg = reg_r8;
					}
					else if ((strncmp(optarg, "r9", 3) == 0)) {
						o->reg = reg_r9;
					}
					else if ((strncmp(optarg, "r10", 3) == 0)) {
						o->reg = reg_r10;
					}
					else if ((strncmp(optarg, "r11", 3) == 0)) {
						o->reg = reg_r11;
					}
					else if ((strncmp(optarg, "r12", 3) == 0)) {
						o->reg = reg_r12;
					}
					else if ((strncmp(optarg, "r13", 3) == 0)) {
						o->reg = reg_r13;
					}
					else if ((strncmp(optarg, "r14", 3) == 0)) {
						o->reg = reg_r14;
					}
					else if ((strncmp(optarg, "r15", 3) == 0)) {
						o->reg = reg_r15;
					}
					else if ((strncmp(optarg, "rip", 3) == 0)) {
						o->reg = reg_rip;
					}
					else {
						fprintf(stderr, "pdump: unsupported register %s\n", optarg);
						usage();
					}
				#else
					if (strncmp(optarg, "eax", 3) == 0) {
						o->reg = reg_eax;
					}
					else if ((strncmp(optarg, "ebx", 3) == 0)) {
						o->reg = reg_ebx;
					}
					else if ((strncmp(optarg, "ecx", 3) == 0)) {
						o->reg = reg_ecx;
					}
					else if ((strncmp(optarg, "edx", 3) == 0)) {
						o->reg = reg_edx;
					}
					else if ((strncmp(optarg, "esi", 3) == 0)) {
						o->reg = reg_esi;
					}
					else if ((strncmp(optarg, "edi", 3) == 0)) {
						o->reg = reg_edi;
					}
					else if ((strncmp(optarg, "ebp", 3) == 0)) {
						o->reg = reg_ebp;
					}
					else if ((strncmp(optarg, "esp", 3) == 0)) {
						o->reg = reg_esp;
					}
					else if ((strncmp(optarg, "eip", 3) == 0)) {
						o->reg = reg_eip;
					}
					else {
						fprintf(stderr, "pdump: unsupported register %s\n", optarg);
						usage();
					}
				#endif
				break;

		case 'q':	o->quiet++;
				break;
		case 'h':
		case '?':	
		default: 	usage();
				break;
				
		}
	}

	if (!o->chldpath) {
		fprintf(stderr, "pdump: missing path to an executable\n");
		usage();
	}

	if (o->is_static) {
		o->reg = DEFAULT_BASEREG_STATIC;
	}

	return 0;
}

void fancy_print(struct opts_t* o) {
	fprintf (stderr, "pdump options:\n"
			"  tracee:\t%s\n"
			"  dump file:\t%s\n"
			"  dump size:\t0x%zx\n"
			"  mask:\t\t0x%lx\n",
			o->chldpath, o->dpath, o->dsize, o->mask);

	if( o->d_addr ) {
		fprintf(stderr, "  dump address:\t0x%lx\n\n", o->d_addr);
	}
	else {
		fprintf(stderr, "  base reg:\t%s\n\n", reg_lookup_tbl[o->reg].name);
	}
}

void usage() {
        printf(
		"\nusage: pdump -f /path/to/executable [-q] [-d /path/to/dump] [-s size] {-a} [-t] [-r register] [-m mask]\n\n"
		"\t-f\tBinary to execute.\n\n"
		"\t-d\tDump the address to a custom file.\n\n"
		"\t-t\tExecutable is statically linked. This option changes default dump register to %s.\n\n"
		"\t-a\tStart dumping from custom address. If used -r, -m, -t are ignored.\n\n"
		"\t-s\tDump size (in hexadecimal).\n\n"
		"\t-m\tCustom mask.\n\t\tRegister that is used as a dump starting point is and-ed with the mask. Default mask is 0x%lx. reg & mask = dump start address.\n\n"
		"\t-r\tSpecify register to start dumping from.\n\t\tDepending on the gcc .text address could be in different register.\n\n"

		#ifdef __x86_64__
			"\t\tSupported register names for 64b: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip\n"
			"\t\tSupported register names for 32b: eax, ebx, ecx, edx, esi, edi, ebp, eip\n\n"
		#else 
			"\t\tSupported register names: eax, ebx, ecx, edx, esi, edi, ebp, eip\n\n"
		#endif

		"\t-q\tToggle quiet mode. Multiple -q supress more messages. Current limit is 2.\n\n"
		"\t-? -h\tThis help.\n\n", reg_lookup_tbl[DEFAULT_BASEREG_STATIC].name, DEFAULT_MASK);

	exit(1);
}
