# pdump

pdump (process dumper) is a program that dumps the .text of specified binary. It's a proof of concept that unsetting read permission on a binary doesn't mean user can't read it (at least on i386/x86_64 architecture). 

### Quick info

TODO..

Binary has to be dynamically linked. If path to ld.so is not specified default libs are tried. No auto-guessing is done though.
Right now two different binaries exist to trace 32b and 64b process.

```sh
$ ./pdump
usage: ./pdump /path/to/exe [ /path/to/ld.so ]
$
```

### Demo

```
$ ./pdump -f ./demo -v -d demo.blob
pdump options:
  tracee:	./demo
  ld.so:	/lib64/ld-linux-x86-64.so.2
  dump file:	demo.blob
  dump size:	0x2000
  mask:		0xfffffffffffff000
  base reg:	rbp

pdump: linker entry point: 0x1090
+pdump: 3240: ld base: 0x7f49137ef000, offset to brk: 0x1bec7

catch me if you can!
+pdump: 3241: ld base: 0x7f2ba307a000, addr ld brk: 0x7f2ba3095ec7
+pdump: 3241: child base: 0x560a3d49c000

+pdump: 3241: registers just before syscall:
rax		0xc
rbx		0x1
rcx		0xc
rdx		0x4d
rsi		0x4f
rdi		0x0
rbp		0x560a3d49c040
rsp		0x7ffc70a4f478
r8		0x16
r9		0x7f2ba309b665
r10		0x1
r11		0x346
r12		0x9
r13		0x7f2ba307c660
r14		0x1
r15		0x1000
rip		0x7f2ba3095ec7

pdump: done.

$ hd -n 64 demo.blob
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  30 05 00 00 00 00 00 00  |..>.....0.......|
00000020  40 00 00 00 00 00 00 00  80 21 00 00 00 00 00 00  |@........!......|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 22 00 21 00  |....@.8...@.".!.|
00000040 
$

```

