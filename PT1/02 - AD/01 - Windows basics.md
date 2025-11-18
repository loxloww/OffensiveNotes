#windows 

Commandes à connaitre 
```powershell

#reconaissance de base système

systeminfo
ipconfig /all
netstat
tasklist
whoami

#gestion des utilisateurs

net user
net localgroup

#lister les correctifs / logiciels installés

wmic qfe list
wmic product get name

#reconnaissance réseau

arp -a
route print


```

Outils de défense Windows :
- Windows Update
- Windows Security
	- Virus / threat protection
	- Firewall / network protection
	- App / browser control
	- Device hardware security