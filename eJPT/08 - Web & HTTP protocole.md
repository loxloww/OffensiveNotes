Intro to web app security testing
common web app threats
web app architecture
web app techno
HTTP protocole Fundamentals
HTTP requests & responses
HTTPS

#### Web app security testing

###### Fundamentals intro

web site = more simple static/client 
web app = more dynamic, provide user with advanced hability (login, database etc)
both accessible over the internet via web browser

client-Server arch
requests < - >responses

= Cross platform, platform/OS independant
statelessness : communication protocol used = HTTP = stateless. the app must manage it s sessions itself 

web app security = aim to protect CIA triad
mitigating risk of unauth access, data breaches, services disruptions

Security practices :
- Auth/Authorization : robsust auth mechanism / authorization controlsto grant apprioriate acces priv
- input validation : proper input sanitization to prevent SQLi / XSS
- Secure communication : TLS/SSL, protect data in transit (cf MITM)
- Secure coding practices : minimize the implements of vulns during the dev phase (DevSecOps)
- Regular Security Updates : app and underlying librairies up to date
- Least privs principle
- WAF : filter / monitor HTTP requests, block malicious traffic + know attack pattern
- Session management : prevent session hijacking 

###### Web app security testing

web app security testing :
- process of eval / assessing security aspects to identify vulns, weaknesses and potential sec risks
- involve conducting various test/assessments to test the app resistance against threats
- main goal : uncover security flaws before their exploitation 
- enhance security posture
bug bounty programs is a good choice 

web app security testing include :
- Vuln scanning for known threats : sqli, XSS, insecure conf etc
- penetration testing : pentration testing is a subset of security testing
- Code review & static analysis
- Auth/authorization testing : evaluate the mecanisms and access controls
- Input validation and output encoding testing
- Session management testing : verify how the app handles token to prevent session-related attacks
- API security testing : assessing the APIs security 

key point between web app security testing and web app penetration testing :
- scope
- objective : identity weaknesses vs validate vulns + assess the organization's ability to detect / respond
- Methodology : manual/auto vs mainly manual
- exploitation : does not involve vs does

###### Common web app threats & risks

Threat vs risk
threat = any potential source of harm / potential danger
risk = potential loss of harm resulting from a threat exploting a vuln / potential impact

threat/risk :
- XSS
- SQLi
- CSRF : tricked auth users into performing action
- Security misconfiguration
- Sensitive Data Exposure
- Brute force / creds stuffing attacks
- File upload vuln
- Dos / Ddos
- SSRF
- Inadequate access controls
- Using components with known vulns
- Broken access control





#### Web app arch & components

###### architecture & components
Client - server model
Client : user interface /front end / sends requests
Server : web app back end / processes client requests / communicates wtih db / reponds

web application = web server + database

components :
- UI
- client side techno : HTML, CSS, JS
- Server side techno : PHP
- DB 
- Application logic
- Web servers : apache, nginx, IIS
- Application Servers

client side processing : work done on client side, pre filtering/data validation to save server ressource or for more fluide animation/UX
server-side processing : backend, data processing (sensitive task : password checking, interaction with db etc) server side language : php, python, Java, ruby

data flow : communication done by HTTP protocole :  request - response

###### web app technologies

web server : apache, nginx
app server : business logic
db server : mysql, mssql, postgresql
server-side scripting language : PHP, Python, Java, Ruby

Data interchange

process of sharing data between different computer
enable interoperability and data sharing between diverse system, platform and techno
involves conversion of data from one format to another making it compatible with receiving system
ensure data interpretation and it's correct use by the recipient regardless of the differences in their data structures, programming languages, OS

facilitate through API : allow different software systems to interact and exchange data 
JSON : data interchnage format
XML
type API : REST : HTTP methods
SOAP : protocol for exchanging structured information, us, xml

secuirty technlogy :
auth/authorizaton : cookie
Encryption : SSL/TLS - encrypt data transmitted between client and server
CDN
Third party lib/framework



#### HTTP/S protocole

###### HTTP fundamentals

HTTP = Hypertext transfer protocol
stateless protocol - no handshake
over TCP
specifically design for communication between web browser and web server
Resource uniquely identified with URL/URI
2 version : HTTP1.0 and HTTP1.1

clinet / server exchange messages -> HTTP requests and responses
HEADERS
MESSAGE BODY

###### HTTP request

HTTP request composition :
request line :1st line of HTTP request and contains :
- HTTP methods : GET,POST,PUT,DELETE
- URL Uniform resource locator : address of resource
- HTTP Version
request headers : provide additional infos about request :
- User-agent
- Host : hostname of the server
- Accept = media types the client can handle in response (HTML, JSON, etc)
- Authorization : creds for auth if required (not in every request)
- cookie : info stored on client side and send to server on each request
request body (optional) : some HTTP methods use request body (POST, PUT)

exemple :

| GET / HTTP/1.1                                            |
| --------------------------------------------------------- |
| Host: www.google.com                                      |
| User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv: 36.0) |
| Gecko/20100101 Firefox/36.0\|                             |
| Accept: text/html, application/xhtml+xml                  |
| Accept-Encoding: gzip, deflate                            |
| Connection : keep-alive # only here if it's HTTP1.1       |
HTTP1.1 take advantage of TCP, because HTTP is stateless but one of main advantage of HTTP1.1 is the connection can be maintained and this is enable thanks to TCP handshake


###### HTTP responses

composition :
response header
- status line : HTTP version, HTTP status code, relative meaning (OK, NOT FOUND, etc)
- Content-type :media type /format (txt/html, application/json,..)
- content-length : size of response body in bytes
- set-cookie : cookie used by client side
- cache-control : directive for caching behavior (ex : it static page = HTML/CSS, server can precise to juste cache and dont ask for update version)
response body :
- content, exemple for GET-> markup (HTML)
###### HTTP methods

HTTP status code :
200 OK : successful
302 Found : redirection
400 BAd request : error in request
401 Unauthorized : auth required, client must provide valid creds
403 Forbidden : do not have permission
404 Not found : resource not found
500 internal server error : server encountered an error

```bash

curl -v http://192.191.151.3/

curl -v -I http://192.191.151.3/ #use head method

curl -v -X OPTIONS http://192.191.151.3/ #get what methods we can used

#use burpsuite and repeater module


```

#### Website crawling / spidering

Crawling : process of navigating / around around the web app, follow links, submit form/logging in
=> objective : map out / catalog the web app

is passive -> engagement done via publicly accessible

tool : we can use Burp suite's passive crawler for mapping

Spidering : process of automatically discovering new ressources (URL) on the web app
lists target URLs called seed, and recursively go through
spidering is quite loud, considered active info gathering technique

For spidering tool : OWASP ZAP's spider 