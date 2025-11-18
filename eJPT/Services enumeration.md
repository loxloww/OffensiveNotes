
Nmap services enumeration :

NSE

Metasploit :

Import nmap into metasploit
- start postgres db
- msfconsole
- create workspace

auxilliary modules -> enumeration / information gathering / discovery (no exploitation) 
searching type : type:auxilliary

metasploit is useful for network maping internal network with a 1st foothold in a device.
with a meterpreter session

msfconsole
search portscan
use auxiliary/scanner/portscan/tcp. / usr <index>
show options

(after exploitation and a meterpreter session)
sysinfo
 - find the private LAN
shell
/bin/bash -i
back to meterpreter session
add route
run autoroute -s <LAN subnetwork>
background - to background a session
sessions - to see all sessions
search portscan
set RHOST with LAN ip device (internal network)


services basic enumeration :

FTP
file transfer protocole
port 21 TCP
log with username/password or anonymously if misconfigured

msfconsole
workspace -a ftpspace

metasploit wordlist files location /usr/share/metasploit-framework/data/wordlists/


SMB (Samba pour linux)
simple message block

network file sharing protocole : to share file / peripherals on LAN

port 445
originally run of top of NetBIOS : port 139

auxiliary module to enumerate SMB version, shares, users + bruteforce attack on user/password

Enumeration :

msfconsole
workspace -a smbspace
setg RHOSTS <IP>   - definition d'une variable globale pour tous les modules
search smb
search type:auxiliary name:smb
info
show options

smbclient -L \\\\<IP>\\ -U admin
smblient \\\\<IP>\\<share> -U admin