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
$ ./pdump ./demo
+pdump: ld entry point: 1090
+pdump: 30317: ld base: 0x7fa17e607000, offset brk: 1bec7
catch me if you can!
+pdump: 30318: ld base: 0x7f6ff6aae000, addr ld brk: 0x7f6ff6ac9ec7
rax		0xc
rbx		0x1
rcx		0xc
rdx		0x4d
rsp		0x7ffd89782318
rbp		0x556fa4330040
rsi		0x5f
rdi		0x0
rip		0x7f6ff6ac9ec7

+pdump: 30318: child base: 0x556fa4330000

$ hd -n 64 dump.out
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  30 05 00 00 00 00 00 00  |..>.....0.......|
00000020  40 00 00 00 00 00 00 00  80 21 00 00 00 00 00 00  |@........!......|
00000030  00 00 00 00 40 00 38 00  09 00 40 00 22 00 21 00  |....@.8...@.".!.|
00000040
```

