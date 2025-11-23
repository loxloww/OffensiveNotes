
-PE --packet-trace --disable-arp-ping :
TTL :
- 64 = OS Linux
- 128 = OS windows


Perform a full TCP port scan on your target and create an HTML report. Submit the number of the highest port as the answer.

```bash

nmap -Pn -oX target -p- 10.129.10.54
xsltproc target.xml -o target.html

```
![[Pasted image 20251122003843.png]]

#### Bypass IDS/IPS

option must harder to filter for FW :
--> sA (ACK)
comapred to -sS and -sT

Decoy
use -D RND:5
entour notre IP avec d autres ip aléatoire

Pour préciser des decoy réaliste :
```bash
nmap -D 10.129.2.15,10.129.2.25,ME,10.129.2.200 ...
```

```bash

sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5


#testing
sudo nmap 10.129.2.28 -n -Pn -p445 -O
#filtered
#use of diferent ip source
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0


```

#### DNS proxying

```bash
#tromper le FW en faisant croire un retour DNS
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

#banner grabbing
sudo ncat -nv --source-port 53 10.129.2.47 50000
```


#### Exercices :

```bash

#EX1
sudo nmap -sV 10.129.2.48
#EX2
sudo nmap -p53 -sU -sV 10.129.2.48 -e tun0 --max-retries=0 --source-port 53
#EX3
sudo nmap -sS 10.129.2.47 -e tun0 --max-retries=0 --source-port 53
sudo ncat -nv --source-port 53 10.129.2.47 50000

```