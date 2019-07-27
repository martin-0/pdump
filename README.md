# pdump

Process dumper ( pdump ) is a program aimed to dump a .text of a specified binary. It's a proof of concept that unsetting read permission on a binary doesn't mean user can't read it (at least on i386/x86_64 architecture).

### Quick info

Both static and dynamic exacutables are supported. Tracer-tracee relationship is estabilshed between pdump and executable using ptrace(). Tracee syscalls are intercepted and contents of the registers are modified to achieve the dump. This aproach works on a binary that was compiled against libc. 
This approach works also on newer kernels where PEEK/POKE to a setuid process is not allowed.


```
$ ./pdump
usage: pdump -f /path/to/executable [-q] [-d /path/to/dump] [-s size] {-a} [-t] [-r register] [-m mask]
$
```

### Demo

```
$ ./pdump -f demo -d demo.blob
pdump options:
  tracee:       demo
  dump file:    demo.blob
  dump size:    0x2000
  mask:         0xfffffffffffff000
  base reg:     rbp

+pdump: 2780: start address: 0x7fbbba2bb090, offset to brk: 0x1ae37

catch me if you can!
+pdump: 2781: addr start: 0x7f1e4089e090, addr brk: 0x7f1e408b8ec7
+pdump: 2781: dump address: 0x562f43447000

+pdump: 2781: registers just before syscall:
rax             0xc
rbx             0x1
rcx             0xc
rdx             0x4d
rsi             0x5f
rdi             0x0
rbp             0x562f43447040
rsp             0x7ffcbfd7ec18
r8              0x16
r9              0x7f1e408be665
r10             0x1
r11             0x346
r12             0x9
r13             0x7f1e4089f660
r14             0x1
r15             0x1000
rip             0x7f1e408b8ec7

pdump: done.

$ hd -n 64 demo.blob
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  30 05 00 00 00 00 00 00  |..>.....0.......|
00000020  40 00 00 00 00 00 00 00  80 21 00 00 00 00 00 00  |@........!......|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 22 00 21 00  |....@.8...@.".!.|
00000040 
$

```

