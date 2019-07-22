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
$ ./pdump ./demo > dump
+pdump: ld entry point: 1090
+pdump: 29675: ld base: 0x7f9fef8e0000, offset brk: 1bec7
+pdump: 29676: ld base: 0x7fcf117d6000, addr ld brk: 0x7fcf117f1ec7
rax		0xc
rbx		0x1
rcx		0xc
rdx		0x4d
rsp		0x7ffcb80c7a98
rbp		0x5588d00b5040
rsi		0x5f
rdi		0x0
rip		0x7fcf117f1ec7

+pdump: 29676: child base: 0x5588d00b5000
$ hd -n 64 dump
00000000  63 61 74 63 68 20 6d 65  20 69 66 20 79 6f 75 20  |catch me if you |
00000010  63 61 6e 21 0a 7f 45 4c  46 02 01 01 00 00 00 00  |can!..ELF.......|
00000020  00 00 00 00 00 03 00 3e  00 01 00 00 00 30 05 00  |.......>.....0..|
00000030  00 00 00 00 00 40 00 00  00 00 00 00 00 80 21 00  |.....@........!.|
00000040
```
As the process we are tracing does print output we need to take care of trimming it. 
// **FIXME** : open a file in parent before fork, let the child have the fd opened and dump it to that fd

License
----

BSD

