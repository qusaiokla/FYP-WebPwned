import argparse
import json
import os
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = "WebPwn-OSINT/1.1 Authorized-Security-Research"
TIMEOUT = 10

COMMON_SUBDOMAINS = [
    "www", "mail", "dev", "test", "staging", "api", "admin",
    "portal", "vpn", "blog", "shop", "cdn", "app", "login",
    "support", "docs", "static", "assets", "m", "mobile"
]


def load_config(path):
    config = {}

    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            config.update(json.load(f))

    config["shodan_api_key"] = os.getenv(
        "SHODAN_API_KEY",
        config.get("shodan_api_key", "")
    )

    return config


def normalize_domain(domain):
    domain = domain.strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc

    return domain.strip("/")


def is_in_scope_hostname(host, domain):
    if not host:
        return False

    host = host.lower().strip()
    host = host.split(":")[0]
    host = host.replace("*.", "")

    return host == domain or host.endswith("." + domain)


def is_in_scope_url(url, domain):
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        return is_in_scope_hostname(host, domain)
    except Exception:
        return False


def clean_url(url):
    parsed = urlparse(url)

    cleaned = parsed._replace(
        query="",
        fragment=""
    )

    return cleaned.geturl()


def extract_emails(text, domain):
    pattern = rf"[a-zA-Z0-9_.+-]+@{re.escape(domain)}"
    return set(re.findall(pattern, text, re.IGNORECASE))


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def fetch_url(url):
    try:
        return requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=True
        )
    except requests.RequestException:
        return None


def source_crtsh(domain):
    print("[+] Querying crt.sh")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = fetch_url(url)

    subdomains = set()

    if not response or response.status_code != 200:
        return subdomains

    try:
        data = response.json()

        for item in data:
            names = item.get("name_value", "").split("\n")

            for name in names:
                name = name.lower().strip().replace("*.", "")

                if is_in_scope_hostname(name, domain):
                    subdomains.add(name)

    except Exception:
        pass

    return subdomains


def source_certspotter(domain):
    print("[+] Querying CertSpotter")

    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )

    response = fetch_url(url)
    subdomains = set()

    if not response or response.status_code != 200:
        return subdomains

    try:
        data = response.json()

        for cert in data:
            for name in cert.get("dns_names", []):
                name = name.lower().replace("*.", "")

                if is_in_scope_hostname(name, domain):
                    subdomains.add(name)

    except Exception:
        pass

    return subdomains


def source_wayback(domain):
    print("[+] Querying Wayback Machine")

    url = (
        f"https://web.archive.org/cdx?"
        f"url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    )

    response = fetch_url(url)

    urls = set()
    subdomains = set()

    if not response or response.status_code != 200:
        return urls, subdomains

    try:
        data = response.json()

        for row in data[1:]:
            original_url = row[0]

            if not is_in_scope_url(original_url, domain):
                continue

            cleaned = clean_url(original_url)
            urls.add(cleaned)

            host = urlparse(original_url).netloc.lower().split(":")[0]

            if is_in_scope_hostname(host, domain):
                subdomains.add(host)

    except Exception:
        pass

    return urls, subdomains


def source_hackertarget(domain):
    print("[+] Querying HackerTarget")

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = fetch_url(url)

    subdomains = set()
    ips = set()

    if not response or response.status_code != 200:
        return subdomains, ips

    for line in response.text.splitlines():
        if "," not in line:
            continue

        host, ip = line.split(",", 1)
        host = host.strip().lower()
        ip = ip.strip()

        if is_in_scope_hostname(host, domain):
            subdomains.add(host)

            if ip:
                ips.add(ip)

    return subdomains, ips


def source_urlscan(domain):
    print("[+] Querying urlscan.io")

    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    response = fetch_url(url)

    urls = set()
    subdomains = set()

    if not response or response.status_code != 200:
        return urls, subdomains

    try:
        data = response.json()

        for result in data.get("results", []):
            page = result.get("page", {})

            result_url = page.get("url")
            domain_name = page.get("domain")

            if result_url and is_in_scope_url(result_url, domain):
                urls.add(clean_url(result_url))

            if domain_name and is_in_scope_hostname(domain_name, domain):
                subdomains.add(domain_name.lower())

    except Exception:
        pass

    return urls, subdomains


def source_alienvault(domain):
    print("[+] Querying AlienVault OTX")

    url = (
        f"https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{domain}/passive_dns"
    )

    response = fetch_url(url)
    subdomains = set()

    if not response or response.status_code != 200:
        return subdomains

    try:
        data = response.json()

        for item in data.get("passive_dns", []):
            hostname = item.get("hostname", "").lower()

            if is_in_scope_hostname(hostname, domain):
                subdomains.add(hostname)

    except Exception:
        pass

    return subdomains


def source_threatminer(domain):
    print("[+] Querying ThreatMiner")

    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    response = fetch_url(url)

    subdomains = set()

    if not response or response.status_code != 200:
        return subdomains

    try:
        data = response.json()

        for item in data.get("results", []):
            host = str(item).lower().strip()

            if is_in_scope_hostname(host, domain):
                subdomains.add(host)

    except Exception:
        pass

    return subdomains


def source_website(domain):
    print("[+] Checking public website metadata")

    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    found_urls = set()
    emails = set()
    names = set()

    for url in urls_to_try:
        response = fetch_url(url)

        if not response or response.status_code >= 400:
            continue

        if is_in_scope_url(response.url, domain):
            found_urls.add(clean_url(response.url))

        emails.update(extract_emails(response.text, domain))

        soup = BeautifulSoup(response.text, "html.parser")

        title = soup.find("title")
        if title and title.text.strip():
            names.add(title.text.strip())

        for link in soup.find_all("a", href=True):
            href = link["href"]

            if href.startswith("http") and is_in_scope_url(href, domain):
                found_urls.add(clean_url(href))

        break

    return found_urls, emails, names


def source_securitytxt(domain):
    print("[+] Checking security.txt")

    urls = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt"
    ]

    found_urls = set()
    emails = set()

    for url in urls:
        response = fetch_url(url)

        if not response or response.status_code != 200:
            continue

        found_urls.add(url)
        emails.update(extract_emails(response.text, domain))

    return found_urls, emails


def source_shodan(domain, api_key):
    print("[+] Querying Shodan")

    ips = set()
    subdomains = set()

    if not api_key:
        print("[-] Shodan API key missing. Skipping.")
        return subdomains, ips

    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    response = fetch_url(url)

    if not response or response.status_code != 200:
        return subdomains, ips

    try:
        data = response.json()

        for item in data.get("subdomains", []):
            host = f"{item}.{domain}"

            if is_in_scope_hostname(host, domain):
                subdomains.add(host)

                ip = resolve_ip(host)
                if ip:
                    ips.add(ip)

    except Exception:
        pass

    return subdomains, ips


def dns_bruteforce(domain):
    print("[+] Running small DNS brute force")

    found = set()

    for word in COMMON_SUBDOMAINS:
        host = f"{word}.{domain}"
        ip = resolve_ip(host)

        if ip:
            found.add(host)

    return found


def check_live_hosts(subdomains):
    print("[+] Checking live HTTP/HTTPS hosts")

    live = set()

    for host in subdomains:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            response = fetch_url(url)

            if response and response.status_code < 500:
                live.add(clean_url(response.url))
                break

    return live


def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_markdown(filename, data):
    lines = []

    lines.append(f"# WebPwn OSINT Report: {data['target']}")
    lines.append("")
    lines.append(f"Generated: {data['generated_at']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    sections = [
        ("Subdomains", "subdomains"),
        ("IP Addresses", "ips"),
        ("Emails", "emails"),
        ("URLs", "urls"),
        ("Names / Metadata Hints", "names"),
        ("Live Hosts", "live_hosts"),
    ]

    for title, key in sections:
        lines.append(f"## {title}")

        items = data.get(key, [])

        if items:
            for item in items:
                lines.append(f"- `{item}`")
        else:
            lines.append("- None found")

        lines.append("")

    lines.append("## Sources Used")
    for source in data.get("sources_used", []):
        lines.append(f"- `{source}`")

    lines.append("")
    lines.append("## Notes")
    lines.append("- This tool is intended for authorized OSINT reconnaissance only.")
    lines.append("- Passive sources are used by default.")
    lines.append("- DNS brute force and live host checking are optional.")
    lines.append("- Strict domain filtering is applied to reduce unrelated data.")
    lines.append("- Results should still be manually validated.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run(domain, sources, output, config_path, brute, live_check):
    domain = normalize_domain(domain)
    config = load_config(config_path)

    results = {
        "target": domain,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": set(),
        "ips": set(),
        "emails": set(),
        "urls": set(),
        "names": set(),
        "live_hosts": set(),
        "sources_used": sources,
    }

    if "all" in sources or "crtsh" in sources:
        results["subdomains"].update(source_crtsh(domain))

    if "all" in sources or "certspotter" in sources:
        results["subdomains"].update(source_certspotter(domain))

    if "all" in sources or "wayback" in sources:
        urls, subs = source_wayback(domain)
        results["urls"].update(urls)
        results["subdomains"].update(subs)

    if "all" in sources or "hackertarget" in sources:
        subs, ips = source_hackertarget(domain)
        results["subdomains"].update(subs)
        results["ips"].update(ips)

    if "all" in sources or "urlscan" in sources:
        urls, subs = source_urlscan(domain)
        results["urls"].update(urls)
        results["subdomains"].update(subs)

    if "all" in sources or "alienvault" in sources:
        results["subdomains"].update(source_alienvault(domain))

    if "all" in sources or "threatminer" in sources:
        results["subdomains"].update(source_threatminer(domain))

    if "all" in sources or "website" in sources:
        urls, emails, names = source_website(domain)
        results["urls"].update(urls)
        results["emails"].update(emails)
        results["names"].update(names)

    if "all" in sources or "securitytxt" in sources:
        urls, emails = source_securitytxt(domain)
        results["urls"].update(urls)
        results["emails"].update(emails)

    if "all" in sources or "shodan" in sources:
        subs, ips = source_shodan(domain, config.get("shodan_api_key"))
        results["subdomains"].update(subs)
        results["ips"].update(ips)

    if brute:
        results["subdomains"].update(dns_bruteforce(domain))

    for host in list(results["subdomains"]):
        ip = resolve_ip(host)

        if ip:
            results["ips"].add(ip)

    if live_check:
        results["live_hosts"].update(check_live_hosts(results["subdomains"]))

    final_data = {
        key: sorted(value) if isinstance(value, set) else value
        for key, value in results.items()
    }

    base = domain.replace(".", "_")

    if output in ["json", "both"]:
        save_json(f"{base}_osint.json", final_data)
        print(f"[+] Saved JSON report: {base}_osint.json")

    if output in ["md", "both"]:
        save_markdown(f"{base}_osint.md", final_data)
        print(f"[+] Saved Markdown report: {base}_osint.md")


def main():
    parser = argparse.ArgumentParser(
        description="WebPwn OSINT Recon Tool"
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Target domain, example: example.com"
    )

    parser.add_argument(
        "-s",
        "--sources",
        nargs="+",
        default=["all"],
        choices=[
            "all",
            "crtsh",
            "certspotter",
            "wayback",
            "hackertarget",
            "urlscan",
            "alienvault",
            "threatminer",
            "website",
            "securitytxt",
            "shodan"
        ],
        help="Sources to query"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="both",
        choices=["json", "md", "both"],
        help="Output format"
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="Path to API config JSON file"
    )

    parser.add_argument(
        "--brute",
        action="store_true",
        help="Enable small DNS brute force"
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Check which hosts respond over HTTP/HTTPS"
    )

    args = parser.parse_args()

    run(
        domain=args.domain,
        sources=args.sources,
        output=args.output,
        config_path=args.config,
        brute=args.brute,
        live_check=args.live
    )


if __name__ == "__main__":
    main()
