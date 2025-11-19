## Passive recon

What to look for :
- IP
- Directory hidden
- OSINT : Names / email / Phone / addresses
- Web technologies used

Search for file :
sitemap.xml
robots.txt

Tools :
host - linux command, DNS lookup utility
whatweb - linux command, equivalent of wappalyzer
httrack - linux command (launch http server for GUI), to download all website source file for static analysis

whois
Netcraft

Browser Addons :
Give web technologies used by website 
- builtwith
- wappalyzer

Search for file :

MX -> DNS record for mail server
A -> IPV4
AAAA -> IPV6

dnsrecon -d <domain>

dnsdumpster.com - website tool ->. domain research tool
Graph/map of domain infos (A/MX/DNS...)

Wafw00F - detect use of WAF / WAF fingerprinting tool
tool to download on github

(!!passive)
subdomain enum :
sublister -> github repo (python tool)

sublist3er -d <domain> 

google dorks/dorking
site:argedis.fr - only result link to this domain (include subdomain)
site:*.argedis.fr - print all subdomain only
inurl:admin - to look for a specific folder or file
intitle:admin - look in title page

intersting command :
intitle:index of
inurl:password.txt

exploit db specically for dorking :
https://www.exploit-db.com/google-hacking-database

other tool for dorking : 
https://odcrawler.xyz/

The Harvester - OSINT tool to gather emails, names, subdomains, IP, URL
ex: theHarvester -d total -b yahoo,rocketreach

Leaked password databases
Have i be pwned

Active information gathering

DNS Zone transfers
CNAME - alias
difference entre hostname et nameserver ?

DNS interrogation = process of enumerating DNS record, give importants info : IP adress domain, sub domains, mail server etc
Zone file = equivalent of config file
if leak can have a view of an organisation network
