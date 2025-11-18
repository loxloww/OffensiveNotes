#writeup #rootme #forensic #rdpcachebitmap

Le fichier donné à une extension bizarre

```zsh

┌──(lolox㉿attackbox1)-[~/Bureau]
└─$ file image_forensic.e01 
image_forensic.e01: EWF/Expert Witness/EnCase image file format

```

#EnCase #ewf #libewf
Article suivi : https://bordas.xyz/etude-dune-image-disque-e01-sous-linux/

' ce sont des volumes qui contiennent une preuve. Leur particularité est que le contenu de ces volumes est inviolable, non-modifiable. '

libewf is a library to access the Expert Witness Compression Format (EWF).
https://github.com/libyal/libewf

```zsh
┌──(lolox㉿attackbox1)-[~/Bureau]
└─$ ewfinfo image_forensic.e01 
ewfinfo 20140816

Acquiry information
        Case number:            1
        Description:            Root-me Challenge - Level : Forensic of course !!!
        Examiner name:          makhno - IT forensic investigator
        Evidence number:        1
        Notes:                  Remote Desktop Display Artifacts ;-)
        Acquisition date:       Sat Jul  2 16:08:57 2016
        System date:            Sat Jul  2 16:08:57 2016
        Operating system used:  Linux
        Software version used:  20140608
        Password:               N/A

EWF information
        File format:            EnCase 6
        Sectors per chunk:      64
        Error granularity:      64
        Compression method:     deflate
        Compression level:      best compression
        Set identifier:         21e99a6f-2155-6f4a-9f8f-52d431d6dd22

Media information
        Media type:             fixed disk
        Is physical:            yes
        Bytes per sector:       512
        Number of sectors:      18420
        Media size:             8.9 MiB (9431040 bytes)

Digest hash information
        MD5:                    ba74f9213ff89221eb9b68cd03ff0242

```

On monte donc ensuite ce volume 

```zsh

┌──(lolox㉿attackbox1)-[~/Bureau]
└─$ sudo mkdir /mnt/ewf1

┌──(lolox㉿attackbox1)-[~/Bureau]
└─$ sudo ewfmount image_forensic.e01 /mnt/ewf1

┌──(lolox㉿attackbox1)-[~/Bureau]
└─$ sudo fdisk -l /mnt/ewf1/ewf1
Disk /mnt/ewf1/ewf1: 8,99 MiB, 9431040 bytes, 18420 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


```

On se rend ensuite dans le dossier ou il y a le point de montage et on tombe sur le fichier ewf1
En regardant les informations du fichier on se rend compte que c'est un .tar

```zsh

┌──(root㉿attackbox1)-[/mnt/ewf1]
└─# file ewf1 
ewf1: POSIX tar archive (GNU)

```

On peut donc tenter de le désarchiver.
Pour des raisons inconnues j'ai du le copier dans un autre dossier avant

```zsh

#erreur
┌──(root㉿attackbox1)-[/mnt/ewf1]
└─# tar -xvf ewf1 
bcache24.bmc
"tar: bcache24.bmc : open impossible: Fonction non implantée"
"tar: Arrêt avec code d'échec à cause des erreurs précédentes"


┌──(root㉿attackbox1)-[/mnt/ewf1]
└─# cp /mnt/ewf1/ewf1 ~/ewf1.tar
cd ~
tar -xvf ewf1.tar

bcache24.bmc

```

On obtient ensuite un fichier en .bmc, après recherche cela semble correspondre a des cache bitmap RDP, ça rejoint l'indice donné dans les informations plus haut

On utilise l'outil l'outil de l'ANSSI : https://github.com/ANSSI-FR/bmc-tools.git


```zsh

┌──(root㉿attackbox1)-[~]
└─# git clone https://github.com/ANSSI-FR/bmc-tools.git
cd bmc-tools
Clonage dans 'bmc-tools'...
remote: Enumerating objects: 112, done.
remote: Counting objects: 100% (41/41), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 112 (delta 28), reused 29 (delta 26), pack-reused 71 (from 1)
"Réception d'objets: 100% (112/112), 42.71 Kio | 1.42 Mio/s, fait."
"Résolution des deltas: 100% (52/52), fait."

┌──(root㉿attackbox1)-[~/bmc-tools]
└─# ls
bmc-tools.py  img  LICENCE.txt  README.md

┌──(root㉿attackbox1)-[~/bmc-tools]
└─# mkdir img

┌──(root㉿attackbox1)-[~/bmc-tools]
└─# python3 bmc-tools.py -s ~/bcache24.bmc -d ./img        
[+++] Processing a single file: '/root/bcache24.bmc'.
[+++] Processing a file: '/root/bcache24.bmc'.
[===] 575 tiles successfully extracted in the end.
[===] Successfully exported 575 files.

┌──(root㉿attackbox1)-[~/bmc-tools]
└─# cp -r img /home/lolox

```

En parcourant les fragments d'images on trouve le flag

![[Pasted image 20250618120023.png]]

#rdp #rdpcachestitcher
Un autre outil qui aurait pu etre intéressant est : https://github.com/BSI-Bund/RdpCacheStitcher
qui permet d'assembler plusieurs bitmap RDP

![[Pasted image 20250618122041.png]]