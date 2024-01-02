These are a collection of scripts, with the nmap ones being automations of the process I used during PWK/PEN-200 for the labs and exam.

The general approach is:
1) A quick scan of top ports for low hanging fruit to immediately begin further enumeration.
2) A full scan to find all open ports.
3) A service scan of all confirmed open ports. This is for deep diving into services.

During the labs and exam I performed these scans manually, but I think using a script to plugin the IPs would yield faster results.

`nmap2_thread_scanner.py` - This version uses the improved nmapthon2 library and makes better use of threading and asynchronous scanning.
`nmap_thread_scanner.py` - Nmap / nmapthon scanner with threads.
`nmap_scanner.py` - Nmap scanner that uses nmapthon.


Sample use and output:

```
┌──(darkstar㉿kali)-[~/Code]
└─$ python3 nmap2_thread_scanner.py -H 127.0.0.1,192.168.192.12     


============== Top Ports Scan ================
Nmap done at Mon Jan  1 14:45:31 2024; 1 IP address (1 host up) scanned in 0.06 seconds

host: ['localhost'] - 127.0.0.1
ports:
-----
 [*] tcp/22        open         (ssh)   
 [*] tcp/80        open         (http)   
 [*] tcp/139       open         (netbios-ssn)   
 [*] tcp/445       open         (microsoft-ds)   
 [*] tcp/5432      open         (postgresql)   
==============================================


============== All Ports Scan ================
Nmap done at Mon Jan  1 14:45:33 2024; 1 IP address (1 host up) scanned in 1.45 seconds

host: ['localhost'] - 127.0.0.1
ports:
-----
 [*] tcp/22        open         (ssh)   
 [*] tcp/80        open         (http)   
 [*] tcp/139       open         (netbios-ssn)   
 [*] tcp/445       open         (microsoft-ds)   
 [*] tcp/5432      open         (postgresql)   
 [*] tcp/5433      open         (pyrrho)   
==============================================


============== Top Ports Scan ================
Nmap done at Mon Jan  1 14:45:40 2024; 1 IP address (1 host up) scanned in 8.53 seconds

host: [] - 192.168.192.12
ports:
-----
 [*] tcp/80        open         (http)   
 [*] tcp/3128      open         (squid-http)   
 [*] tcp/3389      open         (ms-wbt-server)   
==============================================


============== Service Scan ================
Nmap done at Mon Jan  1 14:45:45 2024; 1 IP address (1 host up) scanned in 12.51 seconds

host: ['localhost'] - 127.0.0.1
ports:
-----
 [*] tcp/22        open         (ssh) OpenSSH 9.3p1 Debian 1 protocol 2.0
 [*] tcp/80        open         (http) Apache httpd 2.4.57 (Debian)
 [*] tcp/139       open         (netbios-ssn) Samba smbd 4.6.2 
 [*] tcp/445       open         (netbios-ssn) Samba smbd 4.6.2 
 [*] tcp/5432      open         (postgresql) PostgreSQL DB 9.6.0 or later 
==============================================


============== All Ports Scan ================
Nmap done at Mon Jan  1 14:50:45 2024; 1 IP address (1 host up) scanned in 313.97 seconds

host: [] - 192.168.192.12
ports:
-----
 [*] tcp/80        open         (http)   
 [*] tcp/3128      open         (squid-http)   
 [*] tcp/3389      open         (ms-wbt-server)   
 [*] tcp/7680      open         (pando-pub)   
==============================================


============== Service Scan ================
Nmap done at Mon Jan  1 14:51:27 2024; 1 IP address (1 host up) scanned in 41.96 seconds

host: [] - 192.168.192.12
ports:
-----
 [*] tcp/80        open         (http) Microsoft IIS httpd 10.0 
 [*] tcp/3128      open         (http-proxy) Squid http proxy 3.5.28 
 [*] tcp/3389      open         (ms-wbt-server) Microsoft Terminal Services  
==============================================
```

