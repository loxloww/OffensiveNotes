Host discovery

3 méthodes :
SYN ping
ACK Ping
ICMP echo request

Option nmap :

sL simple liste
sP scan ping (ancien de -sn, obselete)
PN skip host discovery, only port scan directly

Par defaut les 2 font sur le port 80 par default mais possible de mettre une liste : nmap -PA/PS22,25,80, 3389 ip
PS (Ping TCP SYN)
PA (Ping TCP ACK)

-sn : skip port scanning, only host discovery

-PE : ICMP echo request 

PU ping UDP

Exemple :

-V version
agressivité : T1-5

nmap -sn -V -T4 <ip>
nmap -sn -V -PS21,22,25,80,445,3389,8080 -PU137,138 -T4 <ip>