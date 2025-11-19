
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


### Network attcks

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

`