
Exemple scenario and plan for black box pentesting

layer 1 : internet presence
layer 2 : gaterway
layer 3 : accessible services
layer 4 : processes
layer 5 : privileges
layer 6 : Os setup

### infrastructure based enumeraton 

###### internet presence
check certificat infos
crt.sh --> info publique ancien certificat
--> possible de voir les autre sous domaines
passer l ip si dispo dans #shodan

DNS records
#dig 
```bash
dig any dmain.com
```

###### cloud ressource
AWS/GCP/AZure

google dorks
intext:"" inurl:amazon.com
intext:"" inurl:blob.core.windows.net

site : domain.glass

search by keyword :
#grayhatwarfare
look for private key for exemple
### host based enumeration

#### FTP:21


port 21 commands
port 20 data

Most use FTP service
#vsFTPd
config file location --> /etC/vsftpd.conf

user : /etc/ftpusers

```bash
#connect to ftp, anonymous
ftp 10.10.10.2
ls
status
get file
put file
exit

#download all content :
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.13

```

Enumeration
```bash
sudo nmap --script-updatedb
#look for all ftp script available
find / -type f -name ftp* 2>/dev/null | grep scripts
sudo nmap -sV -p21 -sC -A 10.129.14.136
nmap -p 21 -sV --script ftp* 10.129.202.5

#interaction
nc -nv 10.129.14.136 21
telnet 10.129.14.136 21

# if the ftp server use TLs/SSL
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

#### SMB: 445

samba = equivalent smb unix
conf file : /etc/samba/smb.conf

#smbclient #rpcclient #crackmapexec #smbmap #enum4linux 
```bash

smbclient -N -L //10.10.10.2
#-N : anonymous / null-session
 
#connect
smbclient //10.10.10.2/notes
get file
#execute commande on local while still in smb sessions
!<command>

sudo nmap 10.129.14.128 -sV -sC -p139,445

#manual / custom request
rpcclient -U "" 10.10.10.2
srvinfo / enumdomains / enumdomusers / netshareenumall / ...
enumdomusers
queryuser 0x3e8
querygroup 0x201

#Bruteforcing user RIDs
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
#equivalent python from impacket --> samrdump.py
samrdump.py 10.129.14.128

#equivalent of rpcclient
#smbmap 
smbmap -H 10.129.14.128
#crackmapexec
crackmapexec smb 10.129.14.128 --shares -u '' -p ''

#enum4linux 
git clone https://github.com/cddmp/enum4linux-ng.git 
cd enum4linux-ng 
pip3 install -r requirements.txt

./enum4linux-ng.py 10.129.14.128 -A

```