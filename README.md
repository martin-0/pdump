# pdump

Process dumper ( pdump ) is a program aimed to dump a .text of a specified binary. It's a proof of concept that unsetting read permission on a binary doesn't mean user can't read it (at least on i386/x86_64 architecture).

### Quick info

Both static and dynamic exacutables are supported. Dump is achieved using ptrace syscall. Tracer-tracee relationship is estabilshed between pdump and executable. Tracee syscalls are intercepted and contents of the registers are modified to achieve the dump.
This approach works also on newer kernels where PEEK/POKE to a setuid process is not allowed.

Right now two different binaries exist to trace 32b and 64b process.

```sh
$ ./pdump
usage: pdump -f /path/to/executable [-v] [-d /path/to/dump] [-s size] {-a} [-t] [-r register] [-m mask]
$
```

### Demo

```
/pdump -v -f demo -d demo.blob
pdump options:
  tracee:	demo
  dump file:	demo.blob
  dump size:	0x2000
  mask:		0xfffffffffffff000
  base reg:	rbp

+pdump: 27119: start address: 0x7f40fa268090, offset to brk: 0x1ae37

catch me if you can!
+pdump: 27120: addr start: 0x7f63bf494090, addr brk: 0x7f63bf4aeec7
+pdump: 27120: dump address: 0x558513bbe000

+pdump: 27120: registers just before syscall:
rax		0xc
rbx		0x1
rcx		0xc
rdx		0x4d
rsi		0x4f
rdi		0x0
rbp		0x558513bbe040
rsp		0x7ffd853fc248
r8		0x16
r9		0x7f63bf4b4665
r10		0x1
r11		0x346
r12		0x9
r13		0x7f63bf495660
r14		0x1
r15		0x1000
rip		0x7f63bf4aeec7

pdump: done.
$

$ hd -n 64 demo.blob
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  30 05 00 00 00 00 00 00  |..>.....0.......|
00000020  40 00 00 00 00 00 00 00  80 21 00 00 00 00 00 00  |@........!......|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 22 00 21 00  |....@.8...@.".!.|
00000040 
$

```

