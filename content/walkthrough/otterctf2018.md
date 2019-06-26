---
author: "Maki"
title: "OtterCTF 2018"
slug: "otterctf2018"
date: 2018-12-24
description: "CTF created by Asaf Eitani about forensic, reverse and network task."
---

<center>
	<img src="/img/writeups/otterctf2018/OtterCTF.png" width="50%" height="50%" >
	Picture from OtterCTF, awesome logo! :D
</center>

In this short article, I will present some challenges of __OtterCTF__. I will begin with a memory dump challenge suite, it contains a little ransomware. This scenario is really interesting for people who like playing with some forensic stuff. At the end of this article, I'll talk about network task too.

# Memory dump

The memory dump to analyze can be found at this address: https://mega.nz/#!sh8wmCIL!b4tpech4wzc3QQ6YgQ2uZnOmctRZ2duQxDqxbkWYipQ

## 1 - What the password?

<center>
![](/img/writeups/otterctf2018/statement_mem1.png)
</center>

The first thing to do with a memory dump: determine which OS is it and which version of the OS. Volatility needs those information to properly parse the memory:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem imageinfo

Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/opt/usr_land/OtterCTF.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c430a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c44d00L
                KPCR for CPU 1 : 0xfffff880009ef000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2018-08-04 19:34:22 UTC+0000
     Image local date and time : 2018-08-04 22:34:22 +0300
```

Before continuing, I'm used to redirecting volatility plugins output into files. It will be faster if I need to check information in the future. I call them with the following syntax:

> p\<plugin name>

For example: for `pstree` it becomes `ppstree`

Let's get started. Finding a user password in a memory dump, there is not a lot of possibilities:

* Cracking NTLM hashes
* Find the password stored into processes
* Find the password stored in a file (the legendary password.txt on the desktop)

### Cracking NTLM hashes

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 hashdump

Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Rick:1000:aad3b435b51404eeaad3b435b51404ee:518172d012f97d3a8fcc089615283940:::
```

With this, I have tried to break `Rick`'s NTLM hash on a website like crackstation. After two or three attempts I decided to try the second option: find the password into process memory.

### Process, process, my wonderful process

When I spoke about a process, it can be `notepad.exe` with a piece of text file in memory for example. Or, it can be the Windows "strongbox": `lsass.exe`.

`Mimikatz` is a famous tool used by pentesters and (unfortunately) by malwares. This tool takes advantages of some `lsass` weaknesses (and many others) to find clear text password in memory.

Volatility plugin has been made:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 mimikatz

Volatility Foundation Volatility Framework 2.6.1
Module   User             Domain           Password                                
-------- ---------------- ---------------- ----------------------------------------
wdigest  Rick             WIN-LO6FAF3DTFE  MortyIsReallyAnOtter                    
wdigest  WIN-LO6FAF3DTFE$ WORKGROUP
```

Great, the password has been found, so we got the flag.

### Flag

> CTF{MortyIsReallyAnOtter}

## 2 - General Info

<center>
![](/img/writeups/otterctf2018/statement_mem2.png)
</center>

Now, we're looking for 2 flags: computer's IP and computer's name.

### Computer name

Computer's name is really easy to find because mimikatz plugins used previously brought it out: WIN-LO6FAF3DTFE.

So the flag is:

> CTF{WIN-LO6FAF3DTFE} 

### Computer IP

Computer's IP address will not be much more complicated to find. By default, volatility can list all actives network connections with `netscan` plugin. This feature allows us to have a `netstat` view at memory acquisition.

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 netscan > pnetscan

$ cat pnetscan

Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x7d60f010         UDPv4    0.0.0.0:1900                   *:*                                   2836     BitTorrent.exe 2018-08-04 19:27:17 UTC+0000
0x7d62b3f0         UDPv4    192.168.202.131:6771           *:*                                   2836     BitTorrent.exe 2018-08-04 19:27:22 UTC+0000
0x7d62f4c0         UDPv4    127.0.0.1:62307                *:*                                   2836     BitTorrent.exe 2018-08-04 19:27:17 UTC+0000
0x7d62f920         UDPv4    192.168.202.131:62306          *:*                                   2836     BitTorrent.exe 2018-08-04 19:27:17 UTC+0000
0x7d6424c0         UDPv4    0.0.0.0:50762                  *:*                                   4076     chrome.exe     2018-08-04 19:33:37 UTC+0000
0x7d6b4250         UDPv6    ::1:1900                       *:*                                   164      svchost.exe    2018-08-04 19:28:42 UTC+0000
0x7d6e3230         UDPv4    127.0.0.1:6771                 *:*                                   2836     BitTorrent.exe 2018-08-04 19:27:22 UTC+0000
0x7d6ed650         UDPv4    0.0.0.0:5355                   *:*                                   620      svchost.exe    2018-08-04 19:34:22 UTC+0000
0x7d71c8a0         UDPv4    0.0.0.0:0                      *:*                                   868      svchost.exe    2018-08-04 19:34:22 UTC+0000
0x7d71c8a0         UDPv6    :::0                           *:*                                   868      svchost.exe    2018-08-04 19:34:22 UTC+0000
0x7d74a390         UDPv4    127.0.0.1:52847                *:*                                   2624     bittorrentie.e 2018-08-04 19:27:24 UTC+0000
0x7d7602c0         UDPv4    127.0.0.1:52846                *:*                                   2308     bittorrentie.e 2018-08-04 19:27:24 UTC+0000
[...]
```

The most frequent source IP in the output is: 192.168.202.131. Good news, it's the flag:

> CTF{192.168.202.131}

## 3 - Play time

<center>
![](/img/writeups/otterctf2018/statement_mem3.png)
</center>

Again, two flags to find. This time, let's start to resolve the first flag: game name.

### Game name

If __Rick__ plays to something, his process should run:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 pstree > ppstree

$ cat ppstree
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa801b27e060:explorer.exe                     2728   2696     33    854 2018-08-04 19:27:04 UTC+0000
. 0xfffffa801b486b30:Rick And Morty                  3820   2728      4    185 2018-08-04 19:32:55 UTC+0000
.. 0xfffffa801a4c5b30:vmware-tray.ex                 3720   3820      8    147 2018-08-04 19:33:02 UTC+0000
. 0xfffffa801b2f02e0:WebCompanion.e                  2844   2728      0 ------ 2018-08-04 19:27:07 UTC+0000
. 0xfffffa801a4e3870:chrome.exe                      4076   2728     44   1160 2018-08-04 19:29:30 UTC+0000
.. 0xfffffa801a4eab30:chrome.exe                     4084   4076      8     86 2018-08-04 19:29:30 UTC+0000
.. 0xfffffa801a5ef1f0:chrome.exe                     1796   4076     15    170 2018-08-04 19:33:41 UTC+0000
.. 0xfffffa801aa00a90:chrome.exe                     3924   4076     16    228 2018-08-04 19:29:51 UTC+0000
.. 0xfffffa801a635240:chrome.exe                     3648   4076     16    207 2018-08-04 19:33:38 UTC+0000
.. 0xfffffa801a502b30:chrome.exe                      576   4076      2     58 2018-08-04 19:29:31 UTC+0000
.. 0xfffffa801a4f7b30:chrome.exe                     1808   4076     13    229 2018-08-04 19:29:32 UTC+0000
.. 0xfffffa801a7f98f0:chrome.exe                     2748   4076     15    181 2018-08-04 19:31:15 UTC+0000
. 0xfffffa801b5cb740:LunarMS.exe                      708   2728     18    346 2018-08-04 19:27:39 UTC+0000
. 0xfffffa801b1cdb30:vmtoolsd.exe                    2804   2728      6    190 2018-08-04 19:27:06 UTC+0000
. 0xfffffa801b290b30:BitTorrent.exe                  2836   2728     24    471 2018-08-04 19:27:07 UTC+0000
.. 0xfffffa801b4c9b30:bittorrentie.e                 2624   2836     13    316 2018-08-04 19:27:21 UTC+0000
.. 0xfffffa801b4a7b30:bittorrentie.e                 2308   2836     15    337 2018-08-04 19:27:19 UTC+0000
 0xfffffa8018d44740:System                              4      0     95    411 2018-08-04 19:26:03 UTC+0000
. 0xfffffa801947e4d0:smss.exe                         260      4      2     30 2018-08-04 19:26:03 UTC+0000
 0xfffffa801a2ed060:wininit.exe                       396    336      3     78 2018-08-04 19:26:11 UTC+0000
. 0xfffffa801ab377c0:services.exe                     492    396     11    242 2018-08-04 19:26:12 UTC+0000
.. 0xfffffa801afe7800:svchost.exe                    1948    492      6     96 2018-08-04 19:26:42 UTC+0000
.. 0xfffffa801ae92920:vmtoolsd.exe                   1428    492      9    313 2018-08-04 19:26:27 UTC+0000
... 0xfffffa801a572b30:cmd.exe                       3916   1428      0 ------ 2018-08-04 19:34:22 UTC+0000
.. 0xfffffa801ae0f630:VGAuthService.                 1356    492      3     85 2018-08-04 19:26:25 UTC+0000
.. 0xfffffa801abbdb30:vmacthlp.exe                    668    492      3     56 2018-08-04 19:26:16 UTC+0000
.. 0xfffffa801aad1060:Lavasoft.WCAss                 3496    492     14    473 2018-08-04 19:33:49 UTC+0000
.. 0xfffffa801a6af9f0:svchost.exe                     164    492     12    147 2018-08-04 19:28:42 UTC+0000
.. 0xfffffa801ac2e9e0:svchost.exe                     808    492     22    508 2018-08-04 19:26:18 UTC+0000
... 0xfffffa801ac753a0:audiodg.exe                    960    808      7    151 2018-08-04 19:26:19 UTC+0000
.. 0xfffffa801ae7f630:dllhost.exe                    1324    492     15    207 2018-08-04 19:26:42 UTC+0000
.. 0xfffffa801a6c2700:mscorsvw.exe                   3124    492      7     77 2018-08-04 19:28:43 UTC+0000
.. 0xfffffa801b232060:sppsvc.exe                     2500    492      4    149 2018-08-04 19:26:58 UTC+0000
.. 0xfffffa801abebb30:svchost.exe                     712    492      8    301 2018-08-04 19:26:17 UTC+0000
.. 0xfffffa801ad718a0:svchost.exe                    1164    492     18    312 2018-08-04 19:26:23 UTC+0000
.. 0xfffffa801ac31b30:svchost.exe                     844    492     17    396 2018-08-04 19:26:18 UTC+0000
... 0xfffffa801b1fab30:dwm.exe                       2704    844      4     97 2018-08-04 19:27:04 UTC+0000
.. 0xfffffa801988c2d0:PresentationFo                  724    492      6    148 2018-08-04 19:27:52 UTC+0000
.. 0xfffffa801b603610:mscorsvw.exe                    412    492      7     86 2018-08-04 19:28:42 UTC+0000
.. 0xfffffa8018e3c890:svchost.exe                     604    492     11    376 2018-08-04 19:26:16 UTC+0000
... 0xfffffa8019124b30:WmiPrvSE.exe                  1800    604      9    222 2018-08-04 19:26:39 UTC+0000
... 0xfffffa801b112060:WmiPrvSE.exe                  2136    604     12    324 2018-08-04 19:26:51 UTC+0000
.. 0xfffffa801ad5ab30:spoolsv.exe                    1120    492     14    346 2018-08-04 19:26:22 UTC+0000
.. 0xfffffa801ac4db30:svchost.exe                     868    492     45   1114 2018-08-04 19:26:18 UTC+0000
.. 0xfffffa801a6e4b30:svchost.exe                    3196    492     14    352 2018-08-04 19:28:44 UTC+0000
.. 0xfffffa801acd37e0:svchost.exe                     620    492     19    415 2018-08-04 19:26:21 UTC+0000
.. 0xfffffa801b1e9b30:taskhost.exe                   2344    492      8    193 2018-08-04 19:26:57 UTC+0000
.. 0xfffffa801ac97060:svchost.exe                    1012    492     12    554 2018-08-04 19:26:20 UTC+0000
.. 0xfffffa801b3aab30:SearchIndexer.                 3064    492     11    610 2018-08-04 19:27:14 UTC+0000
.. 0xfffffa801aff3b30:msdtc.exe                      1436    492     14    155 2018-08-04 19:26:43 UTC+0000
. 0xfffffa801ab3f060:lsass.exe                        500    396      7    610 2018-08-04 19:26:12 UTC+0000
. 0xfffffa801ab461a0:lsm.exe                          508    396     10    148 2018-08-04 19:26:12 UTC+0000
 0xfffffa801a0c8380:csrss.exe                         348    336      9    563 2018-08-04 19:26:10 UTC+0000
. 0xfffffa801a6643d0:conhost.exe                     2420    348      0     30 2018-08-04 19:34:22 UTC+0000
 0xfffffa80198d3b30:csrss.exe                         388    380     11    460 2018-08-04 19:26:11 UTC+0000
 0xfffffa801aaf4060:winlogon.exe                      432    380      3    113 2018-08-04 19:26:11 UTC+0000
 0xfffffa801b18f060:WebCompanionIn                   3880   1484     15    522 2018-08-04 19:33:07 UTC+0000
. 0xfffffa801aa72b30:sc.exe                          3504   3880      0 ------ 2018-08-04 19:33:48 UTC+0000
. 0xfffffa801aeb6890:sc.exe                           452   3880      0 ------ 2018-08-04 19:33:48 UTC+0000
. 0xfffffa801a6268b0:WebCompanion.e                  3856   3880     15    386 2018-08-04 19:34:05 UTC+0000
. 0xfffffa801b08f060:sc.exe                          3208   3880      0 ------ 2018-08-04 19:33:47 UTC+0000
. 0xfffffa801ac01060:sc.exe                          2028   3880      0 ------ 2018-08-04 19:33:49 UTC+0000
 0xfffffa801b1fd960:notepad.exe                      3304   3132      2     79 2018-08-04 19:34:10 UTC+0000
```

Here are suspicious processes:

* "Rick and Morty"
* vmware-tray.exe
* WebCompanion.exe
* LunarMS.exe

After some internet research, __LunarMS__ appears to be the best candidate. Good!

> CTF{LunarMS}

### Game IP

Now I got the process name, find the associated IP will be easy. Indeed, `netscan` plugin used previously is also showing IP address associated to processes.

```bash
$ cat pnetscan | grep LunarMS
0x7d6124d0         TCPv4    192.168.202.131:49530          77.102.199.102:7575  CLOSED           708      LunarMS.exe    
0x7e413a40         TCPv4    -:0                            -:0                  CLOSED           708      LunarMS.exe    
0x7e521b50         TCPv4    -:0                            -:0                  CLOSED           708      LunarMS.exe
```

The only IP address comes out:

> CTF{77.102.199.102}

## 4 - Name Game

<center>
![](/img/writeups/otterctf2018/statement_mem4.png)
</center>

We know the game, then we know its PID. We got a string, I will use it as search index: __Lunar-3__.

A volatility plugin that I like a lot is `yarascan`, it's like a grep, but better for a memory dump. It's possible to look for patterns with regular expression or just looking for standard strings. For this challenge, I will only look for standard strings in the game process:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 yarascan --yara-rules="Lunar-3" -p 708

Volatility Foundation Volatility Framework 2.6.1
Rule: r1
Owner: Process LunarMS.exe Pid 708
0x5a0c1070  4c 75 6e 61 72 2d 33 00 00 7a 33 00 00 00 00 00   Lunar-3..z3.....
0x5a0c1080  00 1d 00 00 00 01 00 00 00 0b 00 00 00 0b 00 00   ................
0x5a0c1090  00 30 74 74 33 72 38 72 33 33 7a 33 00 00 00 00   .0tt3r8r33z3....
0x5a0c10a0  00 00 1d 00 00 00 01 00 00 00 0d 00 00 00 0d 00   ................
0x5a0c10b0  00 00 53 6f 75 6e 64 2f 55 49 2e 69 6d 67 2f 00   ..Sound/UI.img/.
0x5a0c10c0  00 00 00 1d 00 00 00 01 00 00 00 0c 00 00 00 0c   ................
0x5a0c10d0  00 00 00 42 74 4d 6f 75 73 65 43 6c 69 63 6b 00   ...BtMouseClick.
0x5a0c10e0  00 00 00 00 1d 00 00 00 01 00 00 00 07 00 00 00   ................
0x5a0c10f0  07 00 00 00 4c 75 6e 61 72 2d 34 00 00 00 00 00   ....Lunar-4.....
0x5a0c1100  00 00 00 00 00 1d 00 00 00 01 00 00 00 07 00 00   ................
0x5a0c1110  00 07 00 00 00 4c 75 6e 61 72 2d 31 00 00 00 00   .....Lunar-1....
0x5a0c1120  00 00 00 00 00 00 1d 00 00 00 01 00 00 00 07 00   ................
0x5a0c1130  00 00 07 00 00 00 4c 75 6e 61 72 2d 32 00 00 7a   ......Lunar-2..z
0x5a0c1140  00 00 00 00 00 00 00 1d 00 00 00 01 00 00 00 08   ................
0x5a0c1150  00 00 00 08 00 00 00 53 63 72 6f 6c 6c 55 70 00   .......ScrollUp.
0x5a0c1160  00 00 00 00 00 00 00 00 1d 00 00 00 01 00 00 00   ................
```

The leet speak string looks like a flag ;)

> CTF{0tt3r8r33z3}

## 5 - Name Game 2

<center>
![](/img/writeups/otterctf2018/statement_mem5.png)
</center>

In this case, I will use custom yara rules. The statement does not give strings, just a pattern: __0x64 0x??{6-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2}__

To find this pattern in memory, I just have to do a custom rule, here is my `otterrule.yar` file:

```yml
rule OtterCTF
{
	meta:
		desc = "OtterCTF"
		weight = 10
	strings:
		$a = {?? [6-8] 40 06 [18] 5a 0c 00 00}
	condition:
		$a
}
```

Still filtering on the same PID, just add our rule file to the filter:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 yarascan -y usr_land/otterrule.ya -p 708

Volatility Foundation Volatility Framework 2.6.1
Rule: OtterCTF
Owner: Process LunarMS.exe Pid 708
0x5ab4dfa7  08 44 64 00 00 00 00 00 00 40 06 00 00 b4 e5 af   .Dd......@......
0x5ab4dfb7  00 01 00 00 00 00 00 00 00 b0 e5 af 00 5a 0c 00   .............Z..
0x5ab4dfc7  00 4d 30 72 74 79 4c 30 4c 00 00 00 00 00 00 00   .M0rtyL0L.......
0x5ab4dfd7  21 4e 00 00 55 75 00 00 00 00 00 00 00 00 00 00   !N..Uu..........
0x5ab4dfe7  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x5ab4dff7  b4 10 95 6f d5 cd 66 36 66 36 b4 ab ee fa a4 73   ...o..f6f6.....s
0x5ab4e007  9f 70 f2 ab 6e ba 3a c4 3f c4 3c ac ee 25 ac d9   .p..n.:.?.<..%..
0x5ab4e017  a8 d9 60 ac 6e a0 d6 25 d2 25 a8 ab ee ee e1 aa   ..`.n..%.%......
0x5ab4e027  d2 a2 29 ac 2e 9b d1 5e f4 57 d8 ab 2e 27 86 01   ..)....^.W...'..
0x5ab4e037  7c 07 87 ab ee 0a e8 5f 12 59 d7 ab 6e 31 96 49   |......_.Y..n1.I
0x5ab4e047  96 49 cb ab ee 9e dd e6 dd e6 6a ac 2e 2c 12 bd   .I........j..,..
0x5ab4e057  3e 25 1f 03 6d 29 87 9d 69 26 f8 4a f8 4a cb ab   >%..m)..i&.J.J..
0x5ab4e067  6e ad 60 35 ef a2 01 c2 38 65 2c d8 fa cd e4 f8   n.`5....8e,.....
0x5ab4e077  90 31 c7 87 8c 21 0e 70 e6 6d 78 20 af 00 00 00   .1...!.p.mx.....
0x5ab4e087  00 00 00 00 00 00 00 00 00 00 00 00 00 00 5e 81   ..............^.
0x5ab4e097  ee 8f 7c 6a 4e 74 06 86 f8 0d 06 00 00 00 00 00   ..|jNt..........
[...]
```

Great, it works well!

> CTF{M0rtyL0L}

## 6 - Silly Rick

<center>
![](/img/writeups/otterctf2018/statement_mem6.png)
</center>

This challenge will use a standard volatility plugin: `clipboard`. This plugin will get the clipboard content at dump time:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 clipboard

Volatility Foundation Volatility Framework 2.6.1
Session    WindowStation Format                         Handle Object             Data                                              
---------- ------------- ------------------ ------------------ ------------------ --------------------------------------------------
         1 WinSta0       CF_UNICODETEXT                0x602e3 0xfffff900c1ad93f0 M@il_Pr0vid0rs                                    
         1 WinSta0       CF_TEXT                          0x10 ------------------                                                   
         1 WinSta0       0x150133L              0x200000000000 ------------------                                                   
         1 WinSta0       CF_TEXT                           0x1 ------------------                                                   
         1 ------------- ------------------           0x150133 0xfffff900c1c1adc0
```

EZ Win :D

> CTF{M@il_Pr0vid0rs}

## 7 - Hide and Seek

<center>
![](/img/writeups/otterctf2018/statement_mem7.png)
</center>

It's starting to get interesting: malware. For this challenge, it's better not to go wrong.

### A needle in a haystack

If we get processes tree, we can notify some strange things:

* A "Rick and Morty" process, that has a child process ;
* Lavasoft process ;
* BitTorrent processes ;
* WebCompanion ;
* Notepad.exe which hasn't got parent process.

Remember, a malware can have any name. It's better to look at the parents/child processes.

### Malware, is that you?

I'm going to start with my first hypothesis: the `Rick and Morty` process and his child, `vmware-tray.exe`.

The first step, extract binaries:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 procdump -p 3820 -D .

Volatility Foundation Volatility Framework 2.6.1
Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa801b486b30 0x0000000000400000 Rick And Morty       OK: executable.3820.exe

$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 procdump -p 3720 -D .

Volatility Foundation Volatility Framework 2.6.1
Process(V)         ImageBase          Name                 Result
------------------ ------------------ -------------------- ------
0xfffffa801a4c5b30 0x0000000000ec0000 vmware-tray.ex       OK: executable.3720.exe

$ mv executable.3820.exe rickandmorty.exe
$ mv executable.3720.exe vmware-tray.exe
```

Now a little visit on virustotal, to see the score of those two rogues. First, `rickandmorty.exe`:

<center>
![](/img/writeups/otterctf2018/part7_1.png)
</center>

Well, 4/68 it's not really huge, probably a false positive. What Virustotal says about `vmware-tray.exe`:

<center>
![](/img/writeups/otterctf2018/part7_2.png)
</center>

Great! Better results! It smells the malware :D

And it is:

> CTF{vmware-tray.exe}

## 8 - Path to glory

<center>
![](/img/writeups/otterctf2018/statement_mem8.png)
</center>

According to running processes, I suppose the awful habits of Rick, are the illegal downloads on BitTorrent

Let's try to find what he downloaded:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 filescan > pfilescan

$ cat pfilescan | grep -i torrent 
[...]
0x000000007d63dbc0     10      0 R--r-d \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe
0x000000007d8813c0      2      0 RW-rwd \Device\HarddiskVolume1\Users\Rick\Downloads\Rick And Morty season 1 download.exe.torrent
0x000000007da56240      2      0 RW-rwd \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe
0x000000007dae9350      2      0 RWD--- \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\Rick And Morty season 1 download.exe.1.torrent
0x000000007dcbf6f0      2      0 RW-rwd \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\Rick And Morty season 1 download.exe.1.torrent
0x000000007e710070      8      0 R--rwd \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe
[...]
```

There is a bunch of suspicious files. I first tried to extract `Rick And Morty season 1 download.exe` file but nothing really relevant inside for our problem:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007e710070 -D .

Volatility Foundation Volatility Framework 2.6.1
ImageSectionObject 0x7e710070   None   \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe
DataSectionObject 0x7e710070   None   \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe
```

Let's do the same operation on the __torrent__ file:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007dae9350 -D .

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x7dae9350   None   \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\Rick And Morty season 1 download.exe.1.torrent

$ strings file.None.0xfffffa801b42c9e0.dat
d8:announce44:udp://tracker.openbittorrent.com:80/announce13:announce-listll44:udp://tracker.openbittorrent.com:80/announceel42:udp://tracker.opentrackr.org:1337/announceee10:created by17:BitTorrent/7.10.313:creation datei1533150595e8:encoding5:UTF-84:infod6:lengthi456670e4:name36:Rick And Morty season 1 download.exe12:piece lengthi16384e6:pieces560:\I
!PC<^X
B.k_Rk
0<;O87o
!4^"
3hq,
&iW1|
K68:o
w~Q~YT
$$o9p
bwF:u
e7:website19:M3an_T0rren7_4_R!cke
```

Yay, it works!

> CTF{M3an_T0rren7_4_R!ck}

## 9 - Path to glory 2

<center>
![](/img/writeups/otterctf2018/statement_mem9.png)
</center>

Honestly, with a good friend, we just guessed this flag, it's insane.

He sent me this message: "Hey bro, try to find the string 'Th3' inside memory!"

Ok, but we can add more filter to be more efficient. The torrent file doesn't come by a magic trick. Rick downloaded it with his favorite browser: Chrome.

Then I search the string "Th3" into Chrome processes:

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 yarascan --yara-rules="Th3" -p 3924

[...]
Volatility Foundation Volatility Framework 2.6.1
Rule: r1
Owner: Process chrome.exe Pid 3924
0x6203ba714dd  5f 54 68 33 5f 57 65 61 6b 33 73 37 5f 4c 69 6e   _Th3_Weak3s7_Lin
0x6203ba714ed  6b 5f 49 6e 5f 54 68 33 5f 43 68 40 69 6e 59 65   k_In_Th3_Ch@inYe
0x6203ba714fd  61 72 00 00 00 06 20 3b a7 0f 50 51 46 e2 0d 2f   ar.....;..PQF../
0x6203ba7150d  2f 73 65 63 2d 73 2e 75 69 63 64 6e 2e 63 6f 6d   /sec-s.uicdn.com
0x6203ba7151d  2f 6e 61 76 2d 63 64 6e 2f 68 6f 6d 65 2f 70 72   /nav-cdn/home/pr
0x6203ba7152d  65 6c 6f 61 64 65 72 2e 67 69 66 00 00 06 20 3b   eloader.gif....;
0x6203ba7153d  a7 16 18 00 00 00 02 6e 00 61 00 76 00 69 00 67   .......n.a.v.i.g
0x6203ba7154d  00 61 00 74 00 6f 00 72 00 2d 00 6c 00 78 00 61   .a.t.o.r.-.l.x.a
0x6203ba7155d  00 2e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f   ...m.a.i.l...c.o
0x6203ba7156d  00 6d 00 01 00 00 00 16 00 00 00 00 00 00 62 6e   .m............bn
0x6203ba7157d  00 61 00 76 00 69 00 67 00 61 00 74 00 6f 00 72   .a.v.i.g.a.t.o.r
0x6203ba7158d  00 2d 00 6c 00 78 00 61 00 2e 00 6d 00 61 00 69   .-.l.x.a...m.a.i
0x6203ba7159d  00 6c 00 2e 00 63 00 6f 00 6d 00 04 00 00 00 2a   .l...c.o.m.....*
0x6203ba715ad  00 00 00 4f ac c4 0e 73 69 6d 70 6c 65 2d 69 63   ...O...simple-ic
0x6203ba715bd  6f 6e 5f 74 6f 6f 6c 62 61 72 2d 63 68 61 6e 67   on_toolbar-chang
0x6203ba715cd  65 2d 76 69 65 77 2d 68 6f 72 69 7a 6f 6e 74 61   e-view-horizonta
[...]
```

Ok, I got a piece of something, maybe of the flag:

> \_Th3_Weak3s7_Link_In_Th3_Ch@inYear

Let's extract memory from process 3924 and see what happens. To look into memory dump, I'm using a good old `strings` and `grep` / `less` command.

```bash
$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 memdump -p 3924 -D .

Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing chrome.exe [  3924] to 3924.dmp

$ strings 3924.dmp| grep Weak3s7_Link_In
Hum@n_I5_Th3_Weak3s7_Link_In_Th3_Ch@inYear
[...]
```

And the flag is:

> CTF{Hum@n_I5_Th3_Weak3s7_Link_In_Th3_Ch@in}

## 10 - Bit 4 Bit

<center>
![](/img/writeups/otterctf2018/statement_mem10.png)
</center>

If all scenario steps are followed, finding the wallet will be easy. The malware is known: `vmware-tray.exe`. We suspect that the wallet is embedded in the malicious binary:

```bash
$ strings -e l vmware-tray.exe               
[...]
label2
Your Payment has failed, The funs have been sent back to your wallet. Please send it again
Error
1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M
Send 0.16 to the address below.
I paid, Now give me back my files.
Form3
hidden_tear.Properties.Resources
Bitcoin_Accepted_Here-4800px
[...]
```

The flag is:

> CTF{1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M}

## 11 - Graphic's for the Weak

<center>
![](/img/writeups/otterctf2018/statement_mem11.png)
</center>

Like the previous challenge, we already identified the malware. So if the malware deal with a picture, there are two possibilities:

* The picture is embedded in the malware
* The malware will download the picture

There is an easy way to check the first hypothesis, use a carving software like `binwalk`, `foremost` or whatever.

```bash
$ binwalk vmware-tray.exe

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
9178          0x23DA          Copyright string: "CopyrightAttribute"
116288        0x1C640         PNG image, 4800 x 1454, 8-bit/color RGBA, non-interlaced
116416        0x1C6C0         Zlib compressed data, compressed
344098        0x54022         PNG image, 800 x 600, 8-bit colormap, non-interlaced
344511        0x541BF         Zlib compressed data, best compression
420575        0x66ADF         XML document, version: "1.0"
423178        0x6750A         Unix path: /schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
```

We can see two PNG files, let's try to extract them with `foremost`. I'm using foremost instead of binwalk to extract data because files extracted by foremost are much cleaner:

```bash
$ foremost vmware-tray.exe   
Processing: vmware-tray.exe
|*|

$ file output/png/00000672.png
output/png/00000672.png: PNG image data, 800 x 600, 8-bit colormap, non-interlaced
```

<center>
![](/img/writeups/otterctf2018/part11_1.png)
</center>

> CTF{S0_Just_M0v3_Socy}

## 12 - Recovery

<center>
![](/img/writeups/otterctf2018/statement_mem12.png)
</center>

I didn't manage to solve those two last challenges during the CTF time. But there are very interesting, I had a lot of fun solving them.

To find the encryption key, I have to reverse the malware. I want to find out how the key is generated and how the key is sent to the command and control server. Fortunately, the malware was developed with .NET language:

```bash
$ file vmware-tray.exe        
vmware-tray.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

.NET languages can be decompiled easily with tools like ILSPy. The less I'm seeing assembly better I am! :D

I quickly identified the function `SendPassword`.

<center>
![](/img/writeups/otterctf2018/part12_1.png)
</center>

Now that I've been achieving to find how the key is sent, I can search the pattern in the memory dump:

```bash
$ strings -e l  OtterCTF.vmem| grep "WIN-LO6FAF3DTFE-Rick "
WIN-LO6FAF3DTFE-Rick aDOBofVYUNVnmp7
```

> CTF{aDOBofVYUNVnmp7}

## 13 - Closure

While I was looking for the method that sent the key to the command and control server, I saw a name that caught my attention: `HiddenTears`.

HiddenTears is ransomware available on GitHub since 2015. Some little jerks use this GitHub to do new strains. But it means HiddenTears decrypter is available on the internet, even on the GitHub.

Decrypter: https://github.com/goliate/hidden-tear/tree/master/hidden-tear-decrypter

Firstly, get the file which contains the flag:

```bash
$ cat pfilescan | grep -i flag

0x000000007d61b070     16      0 RW-rw- \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\Microsoft\Windows\Recent\Flag.txt.WINDOWS.lnk
0x000000007e410890     16      0 R--r-- \Device\HarddiskVolume1\Users\Rick\Desktop\Flag.txt

$ vol.py --plugins=plug_vol/ -f usr_land/OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007e410890 -D . 

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x7e410890   None   \Device\HarddiskVolume1\Users\Rick\Desktop\Flag.txt
```

So, now we got a decryption key, an encrypted file, and a decrypter. It sounds good ;)

... Or not, there is a little problem in the "Flag.txt" file that has been extracted:

```bash
$ hexdump -C  Flag.txt 

00000000  7b e6 24 56 9e 5c 0f ef  8e 43 28 f7 e4 c5 83 ff  |{.$V.\...C(.....|
00000010  6c 31 d7 e6 1c da ea 54  cf 72 dd d6 ec 7e b0 7b  |l1.....T.r...~.{|
00000020  c6 8d d0 a8 cc c2 ce 6e  3e ee 03 47 c1 0b b3 e8  |.......n>..G....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001000
```

There is a little mistake about padding, is there a bunch of zero at the end of the file. It probably happens during file extraction from memory.

When the file is lightened of its 0 and renamed with '.locked' extension, it's decryption time:

<center>
![](/img/writeups/otterctf2018/part13_1.gif)
</center>

> CTF{Im_Th@\_B3S7_RicK_0f_Th3m_4ll}

---

# Network

There are 4 network challenges during this CTF, I only solved 3 of them, here is how.

## Birdman's Data

<center>
![](/img/writeups/otterctf2018/statement_net1.png)
</center>

### State of the art

The PCAP file is not really big, I decided to open it using Wireshark. There are few things to notice:

* Data in UDP protocol
* HTTP packets to `txtwizard.net`

<center>
![](/img/writeups/otterctf2018/net1_1.png)
</center>

There nothing interesting in UDP traffic, data does not represent much.

On the other hand, HTTP traffic is very interesting.

### "Crypto" time

There is an interesting request:

```raw
POST /crypto/AES/encrypt/CBC/PKCS5 HTTP/1.1
Host: www.txtwizard.net
Connection: keep-alive
Content-Length: 4297
Accept: application/json, text/javascript, */*; q=0.01
Origin: http://www.txtwizard.net
```

Oh, AES CBC! We're missing the encrypted data, key and IV... Just scroll a little bit ;)

<center>
![](/img/writeups/otterctf2018/net1_2.png)
</center>

After URL decoding data, I got the key and IV, at the end we got:

```raw
Key: XfCtxvD1yFZbxQ/+ULhAcA==
IV : sEhrZxQpnNnINixu3KQ1Tg==
Cipher text: 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
```

Quick look on: http://www.txtwizard.net/crypto

<center>
![](/img/writeups/otterctf2018/net1_3.png)
</center>

Here is the decoded data:

```raw
Chance Something's wrong, I can feel it (Six minutes, Slim Shady, you're on) Just a feeling I've got, like something's about
To happen, but I don't know what If that means, what I think it means, we're in trouble, big trouble, And if he is as bananas as you say, I'm not taking any chances You were just what the doctor ordered I'm beginning to
Feel like a Rap God, Rap God All my people from the front to the back nod, back nod Now who thinks their arms are long
{
Enough to slap box, slap box? They said I rap like a robot, so call
me Rapbot But for me to rap like a computer must be
in my genes I got a laptop in my back pocket My pen'll go off when I half-c*** it Got a fat knot from that rap profit Made a living and a killing off it Ever since Bill Clinton was still in office With Monica Lewinsky feeling on his
Nut-sack I'm an MC still as honest But as rude and indecent as all hell syllables, killaholic (Kill 'em all with) This slickety, gibbedy, hibbedy hip hop You don't really wanna get into a pissing match with this rappidy rap Packing a Mac in the back of the Ac, pack backpack rap, yep, yackidy-yac The
exact same time I attempt these lyrical acrobat stunts while I'm practicing That I'll still be able to break a
Motherf***in' table Over the back of a couple of
_
Faggots and crack it in half
Only
Realized it was ironic I was signed to Aftermath after the fact How could I not blow? All I do is drop F-bombs, feel my wrath of attack Rappers are having a rough time period, here's a Maxipad It's actually disastrously bad For the wack while I'm masterfully constructing this masterpiece as I'm beginning to feel
_
Like a Rap God, Rap God All my people from the front to the back nod, back nod Now who thinks their arms are long enough to slap box, slap box? Let me show you maintaining this s*** ain't that hard, that hard Everybody want the key and the secret to rap
immortality like I have got Well, to be truthful the blueprint's simply rage and youthful exuberance Everybody loves to root
for a nuisance Hit the
Earth like an asteroid, did nothing but shoot for the moon since MC's
_
get taken to school with this music Cause I use it as a vehicle to bust a rhyme Now I lead a new school full of students Me? I'm a product of Rakim, Lakim Shabazz, 2Pac N- -W.A, Cube, hey, Doc, Ren, Yella,
Eazy, thank you, they got Slim Inspired
enough to one day grow up, blow up and be in a position To meet Run DMC and induct them into the motherf***in' Rock n' Roll Hall of Fame Even though I walk in the church and burst in a ball of flames Only Hall of Fame I be inducted in is the alcohol of fame On the wall of shame You fags think it's all a game 'til I walk a flock of flames Off of planking, tell me what in the f*** are you thinking? Little gay looking boy So gay I can barely say it with a straight face looking boy You witnessing a massacre Like you watching a church gathering take place looking boy Oy vey, that boy's gay, that's all they say looking boy You get a thumbs up, pat on the back And a way to go from your label everyday looking boy Hey, looking boy, what you say looking boy? I got a "hell yeah" from Dre looking boy I'mma work for everything I have Never ask nobody for s***, get outta my face looking boy Basically boy you're never gonna be capable To keep up with the same pace looking boy 'Cause I'm beginning to feel like a Rap God, Rap God All my people from the front to the back nod, back nod The way I'm racing around the track, call me Nascar, Nascar Dale Earnhardt of the trailer park, the White Trash God Kneel before General
zorb
}
```

### Flag

Can you see the flag? Just pick the first character of each line:

> CTF{EmiNeM_FOR_LifE_gEez}

## Look at me

<center>
![](/img/writeups/otterctf2018/statement_net2.png)
</center>

I did this challenge after the CTF ending.

<center>
![](/img/writeups/otterctf2018/net2_3.png)
</center>

Wacom CTL 471 is a graphical tablet.

Based on those piece of information, I looked on the internet a CTF writeup. I finally found a writeup of "Tom and Jerry" challenge from BITSCTF: https://blogs.tunelko.com/2017/02/05/bitsctf-tom-and-jerry-50-points/

### Data extraction

Frames containing the most interesting data got the following syntax:

> 02:f1:d9:22:1c:25:4d:03:2b:00

Here is parsing of this frame:

* 02:f1 -> Header
* 50:1d -> X
* 72:1a -> Y
* 00:00 -> Pressure
* 2b:00 -> Suffix

It's possible to extract all frames with the following `tshark` command:

```bash
$ tshark -r lookatme.pcapng -Y '((usb.transfer_type == 0x01) && (frame.len == 37))' -Tfields -e usb.capdata > capdata
```

The first condition `usb.transfer_type` is used to filter the data on sending packets, not the response. It's like filtering on `echo request` for ICMP data. The second statement filter on data length.

### Data decoding

As mentioned in previous writeups, it's necessary to consider all axis, X, Y, and Z. Parsing data is possible with a little `awk` command, shamefully stolen from the BITSCTF writeup:

```bash
$ awk -F: '{x=$3$4;y=$5$6}{z=$7}$1=="02"{print x,y,z}' capdata > hex_value
```

And decoding data with a python script, still stolen from the previous write-up:

```python
#!/usr/bin/python
from pwn import *

f = open('data_plot','w')
 
for i in open('hex2').readlines():
    ii = i.strip().split(' ')
    x = int(ii[0], 16)
    y = int(ii[1], 16)
    z = int(ii[2], 16)
 
    if z > 0:
      f.write("{0} {1}\n".format(u16(struct.pack(">H", x)), u16(struct.pack(">H", y))))
```

With the last statement I ensure that data contains pressure, it prevents from some garbage during decoding. After that, just use `gnuplot` to visualize the data:

```bash
$ gnuplot
$ plot "data_plot"
```

<center>
![](/img/writeups/otterctf2018/net2_1.png)
</center>

### Flag

If I edit the picture a bit, it gives me:

<center>
![](/img/writeups/otterctf2018/net2_2.png)
</center>

> CTF{0TR_U58}

## Otter Leak

<center>
![](/img/writeups/otterctf2018/statement_net3.png)
</center>

For this challenge, I was really lucky. When I opened the PCAP file in my Wireshark I immediately notice some data sent through SMBv2. I configured one column of my Wireshark to display data transferred: `data.data`:

<center>
![](/img/writeups/otterctf2018/net3_1.png)
</center>

### Extraction and decoding time

Let's use `tshark`:

```bash
$ tshark -r OtterLeak.pcap -Y 'smb2 && data.data' -Tfields -e data.data | tr -d ' \n' | xxd -r -p
=0iLu4iLg4iLu4SLg4iLu0CIu0CIu4CIu0iLg0SLu4iLg4iLu0SLg0CIt0SLg4CIu4iLu4CIu0iLg0SLt0SLg0SL
```

It looks to be upside down base64, by putting it back in the right place, I will try to decode it:

```bash
$ cat rev_b64| rev | base64 -d
-- ----- .-. ..... . --- - --... ...-- .-. .. -. -... -.... ....-
```

Great, morse code. I should be on the right path. `dcode` website offers morse decoder:

<center>
![](/img/writeups/otterctf2018/net3_2.png)
</center>

### Flag

> CTF{M0R5EOT73RINB64}

---

To conclude this little paper, the OtterCTF was an amazing CTF for forensic lovers. Honestly, I really liked it!
If you have any question about this article, feel free to contact me on twitter @Maki_chaz. 
Thanks for reading, and merry Christmas guys :) 

<center>
![](https://media.giphy.com/media/fjyGsdRkYqb3j1WODz/giphy.gif)
</center>