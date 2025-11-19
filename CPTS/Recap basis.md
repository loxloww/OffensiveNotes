
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

python -c 'import pty; pty.spawn("/bin/bash")'
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