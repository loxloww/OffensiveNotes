# OSI Layer :

Framework/guidelines -> Network protocols and communication processes

7 Application | HTTP, FTP, SSH, DNS
Provides network services directly to the end users or applications

6 Presentation | SSL/TLS, JPEG, GIF, SSH
Translates data between the application and the lower layers. Data translation, encryption, compression and ensure to present readable data

5 Session | NetBIOS, RPC, APIs
Manage sessions / connections between applications. Handle synchro, dialog control and token management 

4 Transport | TCP, UDP
Ensure end to end communication and provide flow control

3 Network | IP, ICMP
Responsible for logical addressing and routing (Logical addressing)

2 Data | Ethernet
Responsible for framing / bit synchro, addressing, error checking dataframes - (Physical addressing)

1 Physical | USB, Cables, Fiber
Deals with the physical connection between devices

# Network layer

responsible of logical addressing routing and forwading data between devices across different networks
primary goal is determine the optimal path for data travel
ex: 

IP :  fundation of internet 
IP = Header (Essential infos like the source/dest, version number, ttl, protocole type )+ payload
functionality : fragmentation and reassembly, allow the frag of large packets into smaller fragments, size of fragments depend of MTU (maximum transmission unit)
IP addressing type : unicast / broadcast / multicast
Subnetting : divide large ip networkinto smaller one, enhances efficiency and security

IP header format :
IP source address - Packet source
IP destinatuion addres - Packet destination
Time to live - TTL  8 bit to indicate the remaining life of packet
type of service - 8 bit to determine the priority of each packet
Protocol - 8 bit to indicates the data payload type

HEader fields :
Version (4 bits) - purpose: indicate the version of IP protocol used (for ipv4 is 4)
Header length (4bits) - purpose: specifies length of the header par bloc de 32bits (english: 32-bits words). min = 5 (donc 5x32bits = 160bits ou 20octets)et max = 15 (60 octets)
Type of Service (8bits) - no important info
total length (16bits)
identification (16bits) - use for reassembling
flag (3bits)
TTL (8 bits)
![[Pasted image 20250326234554.png]]
![[Pasted image 20250326234624.png]]
  

(TCP require IP to function - encapsulation)

ICMP : Used for error reporting and diagnostic, icmp messages include ping(echo request / echo reply), traceroute and various error messages
