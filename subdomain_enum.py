#!/usr/bin/env python3
"""
WebPwn - Subdomain Enumerator v3
Sources : subfinder, assetfinder, tldfinder, crt.sh, SecurityTrails
         (amass removed — too slow for interactive use)
Filter  : HTTP status check (200, 301, 302, 403, 404)
"""

import argparse
import json
import os
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
SECURITYTRAILS_API_KEY = "VJd33IWB_81Nc4jSo7nncS2uPeqJLnYC"

USER_AGENT   = "WebPwn-SubEnum/3.0"
HTTP_TIMEOUT = 5
CLI_TIMEOUT  = 60        # max seconds to wait for each CLI tool
MAX_WORKERS  = 30        # concurrent HTTP checkers

ALIVE_CODES  = {200, 301, 302, 403, 404}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def clean_subdomains(lines: list, domain: str) -> set:
    result = set()
    for line in lines:
        line = line.strip().lower()
        if not line:
            continue
        if line.startswith("*."):
            line = line[2:]
        if line == domain or line.endswith("." + domain):
            result.add(line)
    return result


def run_cli(cmd: str, label: str, timeout: int = CLI_TIMEOUT) -> list:
    """
    Run a CLI tool with a hard timeout.
    Prints a live spinner so you can see it is still working.
    """
    done_flag = threading.Event()

    def _spinner():
        frames = ["|", "/", "-", "\\"]
        i = 0
        while not done_flag.is_set():
            print(f"\r    [{frames[i % 4]}] {label} running...", end="", flush=True)
            done_flag.wait(0.3)
            i += 1
        print(f"\r    [✓] {label} done              ", flush=True)

    t = threading.Thread(target=_spinner, daemon=True)
    t.start()

    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        lines = proc.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"\r    [!] {label} timed out after {timeout}s — partial results used", flush=True)
        lines = []
    except Exception as e:
        print(f"\r    [!] {label} error: {e}", flush=True)
        lines = []
    finally:
        done_flag.set()
        t.join()

    return lines


# ─────────────────────────────────────────
# ENUMERATION SOURCES
# ─────────────────────────────────────────
def source_subfinder(domain: str) -> set:
    lines = run_cli(
        f"subfinder -d {domain} -all -silent",
        "subfinder"
    )
    found = clean_subdomains(lines, domain)
    print(f"    → {len(found)} subdomains")
    return found


def source_assetfinder(domain: str) -> set:
    lines = run_cli(
        f"assetfinder --subs-only {domain}",
        "assetfinder"
    )
    found = clean_subdomains(lines, domain)
    print(f"    → {len(found)} subdomains")
    return found


def source_tldfinder(domain: str) -> set:
    lines = run_cli(
        f"tldfinder -d {domain}",
        "tldfinder",
        timeout=30
    )
    found = clean_subdomains(lines, domain)
    print(f"    → {len(found)} subdomains")
    return found


def source_crtsh(domain: str) -> set:
    print(f"    [~] crt.sh querying...", end="", flush=True)
    subdomains: set = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            for item in r.json():
                for name in item.get("name_value", "").split("\n"):
                    name = name.strip().lower().replace("*.", "")
                    if name == domain or name.endswith("." + domain):
                        subdomains.add(name)
        print(f"\r    [✓] crt.sh done → {len(subdomains)} subdomains          ")
    except Exception as e:
        print(f"\r    [!] crt.sh error: {e}                                    ")
    return subdomains


def source_securitytrails(domain: str) -> set:
    print(f"    [~] SecurityTrails querying...", end="", flush=True)
    subdomains: set = set()

    if not SECURITYTRAILS_API_KEY:
        print("\r    [!] No SecurityTrails key — skipping              ")
        return subdomains

    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": SECURITYTRAILS_API_KEY, "User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            for sub in r.json().get("subdomains", []):
                subdomains.add(f"{sub.strip().lower()}.{domain}")
            print(f"\r    [✓] SecurityTrails done → {len(subdomains)} subdomains     ")
        else:
            print(f"\r    [!] SecurityTrails HTTP {r.status_code}                    ")
    except Exception as e:
        print(f"\r    [!] SecurityTrails error: {e}                          ")

    return subdomains


# ─────────────────────────────────────────
# HTTP STATUS FILTER
# ─────────────────────────────────────────
def check_status(host: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{host}",
                headers={"User-Agent": USER_AGENT},
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            if r.status_code in ALIVE_CODES:
                return {
                    "host":   host,
                    "url":    r.url,
                    "status": r.status_code,
                }
        except Exception:
            continue
    return None


def filter_by_status(subdomains: set) -> list:
    total  = len(subdomains)
    alive  = []
    done   = 0
    lock   = threading.Lock()

    print(f"\n[Phase 2] HTTP Status Filter — checking {total} subdomains")
    print(f"          Codes kept: {sorted(ALIVE_CODES)}\n")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_status, h): h for h in subdomains}

        for future in as_completed(futures):
            result = future.result()
            with lock:
                done += 1
                if result:
                    alive.append(result)
                    print(f"  [HTTP {result['status']}] {result['host']}")
                # Progress line every 25 checks
                if done % 25 == 0 or done == total:
                    print(f"  Progress: {done}/{total} checked — {len(alive)} alive", flush=True)

    alive.sort(key=lambda x: (x["status"], x["host"]))
    return alive


# ─────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────
def save_results(domain: str, all_subs: set, alive: list) -> tuple:
    outdir = f"subenum-{domain}"
    os.makedirs(outdir, exist_ok=True)

    # all subdomains
    all_file = os.path.join(outdir, "all-subs.txt")
    with open(all_file, "w", encoding="utf-8") as f:
        f.write(f"# Target : {domain}\n# Total  : {len(all_subs)}\n\n")
        for s in sorted(all_subs):
            f.write(s + "\n")

    # alive only
    alive_file = os.path.join(outdir, "alive-subs.txt")
    with open(alive_file, "w", encoding="utf-8") as f:
        f.write(f"# Target : {domain}\n# Alive  : {len(alive)}\n\n")
        for e in alive:
            f.write(f"[{e['status']}] {e['host']}  →  {e['url']}\n")

    # JSON report
    safe      = domain.replace(".", "_")
    json_file = os.path.join(outdir, f"{safe}_report.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump({
            "tool":        "WebPwn Subdomain Enumerator",
            "target":      domain,
            "generated":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_found": len(all_subs),
            "total_alive": len(alive),
            "alive_codes": sorted(ALIVE_CODES),
            "all_subs":    sorted(all_subs),
            "alive":       alive,
        }, f, indent=2)

    return all_file, alive_file, json_file


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="WebPwn Subdomain Enumerator with HTTP Status Filter"
    )
    parser.add_argument("-d", "--domain",    required=True)
    parser.add_argument("--no-filter",       action="store_true",
                        help="Skip HTTP status check")
    parser.add_argument("--cli-timeout",     type=int, default=CLI_TIMEOUT,
                        help=f"Seconds before killing a CLI tool (default {CLI_TIMEOUT})")
    args = parser.parse_args()

    domain = args.domain.strip().lower()

    print(f"\n{'='*52}")
    print(f"  WebPwn Subdomain Enumerator")
    print(f"  Target  : {domain}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*52}\n")

    # ── Phase 1: Enumerate ──────────────────────────────
    print("[Phase 1] Subdomain Enumeration\n")

    all_subs: set = set()

    # CLI tools run in parallel with spinner feedback
    cli_jobs = [
        (source_subfinder,   "subfinder"),
        (source_assetfinder, "assetfinder"),
        (source_tldfinder,   "tldfinder"),
    ]

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fn, domain): name for fn, name in cli_jobs}
        for future in as_completed(futures):
            try:
                all_subs.update(future.result())
            except Exception:
                pass

    # API sources (fast, sequential)
    all_subs.update(source_crtsh(domain))
    all_subs.update(source_securitytrails(domain))

    print(f"\n[+] Total unique subdomains : {len(all_subs)}")

    # ── Phase 2: HTTP filter ────────────────────────────
    alive: list = []
    if not args.no_filter and all_subs:
        alive = filter_by_status(all_subs)

    # ── Save ────────────────────────────────────────────
    all_file, alive_file, json_file = save_results(domain, all_subs, alive)

    # ── Summary ─────────────────────────────────────────
    print(f"\n{'='*52}")
    print(f"[+] DONE")
    print(f"{'='*52}")
    print(f"  Total subdomains found : {len(all_subs)}")
    print(f"  Alive after filtering  : {len(alive)}")
    print(f"\n  Files saved:")
    print(f"    {all_file}")
    print(f"    {alive_file}")
    print(f"    {json_file}")

    if alive:
        print(f"\n  Status breakdown:")
        breakdown: dict = {}
        for e in alive:
            breakdown[e["status"]] = breakdown.get(e["status"], 0) + 1
        for code in sorted(breakdown):
            print(f"    HTTP {code} : {breakdown[code]}")

    print()


if __name__ == "__main__":
    main()

#how to run it 
#Fast + Good results (recommended) ----> py subdomain_enum.py -d amazon.com
#Bigger result (still fast) ----> py subdomain_enum.py -d amazon.com --deep
#Only real resolving domains ----> py subdomain_enum.py -d amazon.com --resolve
