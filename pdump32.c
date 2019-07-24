/* i386 v0.2 (c) 2019 martin */

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

void fancy_print(struct opts_t* o);

int main(int argc, char** argv) {
	struct opts_t opts;

	// set the options first
	handle_args(&opts, argc, argv);

	if (opts.verbose)
		fancy_print(&opts);

	// XXX: do we want to use O_TRUNC really ?

	int dfd;						// dump fd
	if ( (dfd = open(opts.dpath, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
		fprintf(stderr, "oops: pdump: failed to open dump file %s ", opts.dpath);
		perror("");
		exit(1);
	}

	// ld.so entry point
	unsigned long ofst_ld_entry = get_entry(opts.ldpath);

	fprintf (stderr, "pdump: linker entry point: 0x%lx\n", ofst_ld_entry);

	pid_t pid;
	if ( (pid=fork()) == 0) {
		handle_child(opts.chldpath);
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

	fprintf(stderr, "+pdump: %u: ld base: 0x%.lx, offset to brk: 0x%lx\n\n", pid, addr_ld_base, ofst_ld_brk_in);

	// we don't care about the child any more .. kill it.. 
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
	
	unsigned long addr_ld_brk_in = 0;			// actual addr of the brk() in ld.so for current child

	// calculate the new ld_base (due to ASLR) and get the syscall in brk() instruction
	addr_ld_base = get_to_ldentry(&regs, pid, &status) - ofst_ld_entry;
	addr_ld_brk_in = addr_ld_base + ofst_ld_brk_in;

	fprintf (stderr, "+pdump: %u: ld base: 0x%lx, addr ld brk: 0x%lx\n", pid, addr_ld_base, addr_ld_brk_in);

	// trace until the brk() syscall instruction
	if ((trace_until(&regs, addr_ld_brk_in, pid, &status)) != 0) {
		fprintf (stderr, "+pdump: oops: neither trace_until() nor assert_status() caught the condition..\n");
		PTRACE_DETACH(pid)
		exit(1);
	}

	unsigned long addr_pie_base = *((unsigned long*)&regs + reg_lookup_tbl[opts.reg].idx ) & opts.mask;

	fprintf(stderr,"+pdump: %u: child base: 0x%lx\n", pid, addr_pie_base);

	if (opts.verbose) { 
		fprintf(stderr, "\n+pdump: %u: registers just before syscall:\n", pid);
		regdump(&regs);
	}

	regs.ebx = dfd;
	regs.ecx = addr_pie_base;
	regs.edx = opts.dsize;
	regs.eax = SYS_write;

	PTRACE_SETREGS(pid, &regs)
	PTRACE_DETACH(pid)

	close(dfd);

	printf ("pdump: done.\n");
        return 0;
}

// requires child to be stopped just before its execve()
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
	fprintf (stderr,"eax\t\t0x%lx\necx\t\t0x%lx\nedx\t\t0x%lx\nebx\t\t0x%lx\n"
			"esp\t\t0x%lx\nebp\t\t0x%lx\nesi\t\t0x%lx\nedi\t\t0x%lx\neip\t\t0x%lx\n\n",
			r->eax, r->ecx, r->edx, r->ebx, r->esp, r->ebp, r->esi, r->edi, r->eip);
}

unsigned long get_entry(char* lib) {
	int fd;
	if ( (fd = open(lib, O_RDONLY)) < 0) {
		fprintf(stderr, "oops: pdump: failed to open linker %s ", lib);
		perror("");
		exit(1);
	}
	unsigned long entry;

	lseek(fd, 0x18, SEEK_SET);
	read(fd, &entry, sizeof(entry));
	close(fd);
	return entry;
}

int handle_args(struct opts_t* o, int argc, char** argv) {
	int i,opt,reg;
	unsigned long mask;

	// let's set defaults first
	o->chldpath = NULL;
	o->ldpath = DEFAULT_LD;
	o->dpath = DEFAULT_DUMP_FILE;
	o->dsize = DEFAULT_DUMP_SIZE;
	o->mask = DEFAULT_MASK;
	o->reg = DEFAULT_BASEREG;
	o->verbose = 0;

	while ((opt = getopt(argc, argv, "f:l:d:s:m:r:vh?")) != -1 ) {
		switch(opt) {
		case 'f':	o->chldpath = optarg;
				break;

		case 'l':	o->ldpath = optarg;
				break;

		case 'd':	o->dpath = optarg;
				break;

		case 's':	o->dsize = strtoll(optarg, 0, 16);
				break;

		case 'm':	// set custom mask when figuring out .text base address
				o->mask = strtoll(optarg, 0, 16);
				break;
	
		case 'r':	// map register name to idx
				for (i = 0; i < strlen(optarg); i++) {
					optarg[i] = tolower(optarg[i]);
				}

				// not exactly an eye candy.. 
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
				break;

		case 'v':	o->verbose++;
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

	return 0;
}

void fancy_print(struct opts_t* o) {
	fprintf (stderr, "pdump options:\n"
			"  tracee:\t%s\n"
			"  ld.so:\t%s\n"
			"  dump file:\t%s\n"
			"  dump size:\t0x%zx\n"
			"  mask:\t\t0x%lx\n"
			"  base reg:\t%s\n\n", 
			o->chldpath, o->ldpath, o->dpath, o->dsize, o->mask, reg_lookup_tbl[o->reg].name );
}

void usage() {
	printf(
		"\nusage: pdump -f /path/to/executable [-v] [-d /path/to/dump] [-s size] [-l /path/to/ld.so] [-r register] [-m mask]\n\n"
		"\t-f\tBinary to execute.\n\n"
		"\t-l\tPath to a loader (ld.so).\n\n"
		"\t-d\tDump the address to a custom file.\n\n"
		"\t-s\tDump size (in hexadecimal).\n\n"
		"\t-m\tCustom mask.\n\t\tRegister that is used as a dump starting point is and-ed with the mask. Default address is 0x%x. reg & mask = dump start address.\n\n"
		"\t-r\tSpecify register to start dumping from.\n\t\tDepending on the gcc .text address could be in different register. In recent ld versions it's the ebp register.\n\n"
			"\t\tSupported register names: eax, ebx, ecx, edx, esi, edi, ebp, eip\n\n"
		"\t-v\tToggle verbose mode.\n\n"
		"\t-? -h\tThis help.\n\n", DEFAULT_MASK);

	exit(1);
}
