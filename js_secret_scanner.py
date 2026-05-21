import argparse
import json
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import warnings
from bs4 import XMLParsedAsHTMLWarning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

USER_AGENT = "WebPwn-JS-Scanner/1.4"
TIMEOUT = 3
MAX_SIZE = 2 * 1024 * 1024
MAX_WORKERS = 10
MAX_FINDINGS_PER_FILE = 300
MAX_RECURSIVE_DEPTH = 2


IGNORED_JS_KEYWORDS = [
    "jquery",
    "bootstrap",
    "polyfill",
    "cookie",
    "consent",
    "analytics",
    "gtm",
    "googletagmanager",
    "google-analytics",
    "hotjar",
    "vendor",
    "runtime",
    "recaptcha",
    "datadog",
    "sentry",
    "newrelic",
]


PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{20,}",
    "Stripe Public Key": r"pk_live_[0-9a-zA-Z]{20,}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{30,}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9\-]{20,}",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9_\-.=]{25,}",
    "API Key Assignment": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Access Token Assignment": r"(?i)(access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-.]{16,}['\"]",
    "Secret Assignment": r"(?i)(secret|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
    "Password Assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}",

    "Absolute URL": r"https?://[^\s\"'<>\\]+",
    "Relative URL / Path": r"['\"](\/[A-Za-z0-9_\-\/.]+(?:\?[A-Za-z0-9_\-=&%.]+)?)['\"]",
    "API Endpoint": r"['\"](\/api\/[A-Za-z0-9_\-\/?=&%.]+)['\"]",
    "API Route": r"['\"](\/?(api|v1|v2|v3|graphql|auth|oauth|login|admin|user|account|payment|checkout|session|token)[A-Za-z0-9_\-\/?=&%.]*)['\"]",
    "Admin Path": r"['\"](\/admin[A-Za-z0-9_\-\/?=&%.]*)['\"]",
    "Sensitive File Path": r"['\"]([A-Za-z0-9_\-\/.]+?\.(env|bak|old|sql|zip|tar|gz|config|xml|json|yaml|yml|ini|log))['\"]",

    "S3 Bucket URL": r"https?://[a-zA-Z0-9.\-_]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com[^\s\"'<>\\]*",
    "S3 Website URL": r"https?://[a-zA-Z0-9.\-_]+\.s3-website[.-][a-z0-9-]+\.amazonaws\.com[^\s\"'<>\\]*",
    "S3 Path Style URL": r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/[a-zA-Z0-9.\-_]+[^\s\"'<>\\]*",
    "Possible S3 Bucket Name": r"(?i)(bucket|s3Bucket|s3_bucket|bucketName)\s*[:=]\s*['\"]?([a-z0-9.\-_]{3,63})['\"]?",
    "CloudFront URL": r"https?://[a-zA-Z0-9]+\.cloudfront\.net[^\s\"'<>\\]*",
    "Firebase URL": r"https?://[a-zA-Z0-9\-]+\.firebaseio\.com[^\s\"'<>\\]*",
    "Google Storage Bucket": r"https?://storage\.googleapis\.com\/[a-zA-Z0-9.\-_]+[^\s\"'<>\\]*",
    "Azure Blob Storage": r"https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net[^\s\"'<>\\]*",

    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Local Storage": r"localStorage\.(getItem|setItem)",
    "Session Storage": r"sessionStorage\.(getItem|setItem)",
    "Dangerous eval": r"\beval\s*\(",
    "document.write": r"document\.write\s*\(",
    "innerHTML": r"\.innerHTML\s*=",
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
}


def build_headers(cookie=None):
    headers = {"User-Agent": USER_AGENT}

    if cookie:
        headers["Cookie"] = cookie

    return headers


def fetch_url(url, cookie=None):
    try:
        response = requests.get(
            url,
            headers=build_headers(cookie),
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,
            verify=False
        )

        content_length = response.headers.get("Content-Length")

        if content_length and int(content_length) > MAX_SIZE:
            return None, "File too large"

        text = response.text

        if len(text.encode("utf-8", errors="ignore")) > MAX_SIZE:
            return None, "File too large"

        return response, None

    except Exception as error:
        return None, str(error)


def is_ignored_js(js_url):
    lowered = js_url.lower()

    for keyword in IGNORED_JS_KEYWORDS:
        if keyword in lowered:
            return True

    return False


def normalize_url(url):
    return url.split("#")[0].strip()


def discover_js_from_text(text, base_url):
    js_files = set()

    regex_patterns = [
        r'https?://[^"\']+?\.js(?:\?[^"\']*)?',
        r'["\']([^"\']+?\.js(?:\?[^"\']*)?)["\']'
    ]

    for pattern in regex_patterns:
        matches = re.findall(pattern, text)

        for match in matches:
            if isinstance(match, tuple):
                match = match[0]

            full_url = normalize_url(urljoin(base_url, match))

            if full_url.startswith("http") and ".js" in full_url:
                js_files.add(full_url)

    return js_files


def discover_js_files(page_url, cookie=None):
    response, error = fetch_url(page_url, cookie)

    if error or not response:
        return [], error

    js_files = set()
    html = response.text

    soup = BeautifulSoup(html, "html.parser")

    for script in soup.find_all("script"):
        src = script.get("src") or script.get("data-src")

        if src:
            full_url = normalize_url(urljoin(response.url, src))

            if full_url.startswith("http") and ".js" in full_url:
                js_files.add(full_url)

    js_files.update(discover_js_from_text(html, response.url))

    return sorted(js_files), None


def load_targets_from_file(path):
    targets = []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("http://") or line.startswith("https://"):
                targets.append(line)
            else:
                targets.append("https://" + line)

    return targets


def get_line_number(content, start_index):
    return content[:start_index].count("\n") + 1


def clean_match_text(text):
    text = text.strip()

    if len(text) > 250:
        text = text[:250] + "..."

    return text


def scan_content(content):
    findings = []
    seen = set()

    for category, pattern in PATTERNS.items():
        try:
            for match in re.finditer(pattern, content):
                matched_text = clean_match_text(match.group(0))
                unique_key = f"{category}:{matched_text}"

                if unique_key in seen:
                    continue

                seen.add(unique_key)

                line_number = get_line_number(content, match.start())

                findings.append({
                    "category": category,
                    "line": line_number,
                    "match": matched_text
                })

                if len(findings) >= MAX_FINDINGS_PER_FILE:
                    return findings

        except re.error:
            continue

    return findings


def scan_js_file(js_url, cookie=None, include_vendor=False):
    result = {
        "js_url": js_url,
        "status": None,
        "error": None,
        "ignored": False,
        "nested_js_files": [],
        "findings": []
    }

    if not include_vendor and is_ignored_js(js_url):
        result["ignored"] = True
        result["error"] = "Ignored vendor/library JS"
        return result

    response, error = fetch_url(js_url, cookie)

    if error or not response:
        result["error"] = error
        return result

    result["status"] = response.status_code

    if response.status_code >= 400:
        result["error"] = f"HTTP {response.status_code}"
        return result

    content_type = response.headers.get("Content-Type", "").lower()

    if "javascript" not in content_type and ".js" not in js_url.lower():
        result["error"] = "Not a JavaScript file"
        return result

    result["findings"] = scan_content(response.text)
    result["nested_js_files"] = sorted(discover_js_from_text(response.text, js_url))

    return result


def expand_nested_js(initial_js_files, cookie=None, include_vendor=False, depth=MAX_RECURSIVE_DEPTH):
    all_js_files = set(initial_js_files)
    checked = set()
    current_level = set(initial_js_files)

    for level in range(depth):
        print(f"[+] Checking JS inside JS files - depth {level + 1}")

        next_level = set()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(scan_js_file, js_url, cookie, include_vendor): js_url
                for js_url in current_level
                if js_url not in checked
            }

            for future in as_completed(future_map):
                js_url = future_map[future]
                checked.add(js_url)

                try:
                    result = future.result()

                    for nested_js in result.get("nested_js_files", []):
                        if nested_js not in all_js_files:
                            all_js_files.add(nested_js)
                            next_level.add(nested_js)

                except Exception:
                    continue

        if not next_level:
            break

        current_level = next_level

    return all_js_files


def build_finding_summary(results):
    summary = {}

    for item in results:
        for finding in item.get("findings", []):
            category = finding.get("category", "Unknown")
            summary[category] = summary.get(category, 0) + 1

    return dict(sorted(summary.items()))


def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def save_summary(filename, data):
    summary_file = filename.replace(".json", "_summary.txt")

    with open(summary_file, "w", encoding="utf-8") as file:
        file.write("WebPwn JavaScript Secret Scanner Summary\n")
        file.write("=" * 45 + "\n\n")
        file.write(f"Generated: {data['generated_at']}\n")
        file.write(f"Targets: {data['total_targets']}\n")
        file.write(f"JS Files Discovered: {data['total_js_files']}\n")
        file.write(f"JS Files Scanned: {data['scanned_js_files']}\n")
        file.write(f"Ignored JS Files: {data['ignored_js_files']}\n")
        file.write(f"Total Findings: {data['total_findings']}\n\n")

        file.write("Finding Summary\n")
        file.write("-" * 20 + "\n")

        if data.get("finding_summary"):
            for category, count in data["finding_summary"].items():
                file.write(f"{category}: {count}\n")
        else:
            file.write("No findings found\n")

        file.write("\nDetailed Findings\n")
        file.write("-" * 20 + "\n")

        for item in data["results"]:
            if item["findings"]:
                file.write(f"\n{item['js_url']}\n")
                file.write("-" * len(item["js_url"]) + "\n")

                for finding in item["findings"]:
                    file.write(
                        f"[{finding['category']}] "
                        f"Line {finding['line']}: "
                        f"{finding['match']}\n"
                    )

    return summary_file


def main():
    parser = argparse.ArgumentParser(
        description="WebPwn JavaScript Secret Scanner"
    )

    parser.add_argument("-u", "--url", help="Single website URL to crawl")
    parser.add_argument("-l", "--list", help="File containing domains, URLs, or JS URLs")
    parser.add_argument("--cookie", help="Optional cookie for authorized authenticated testing")
    parser.add_argument("-o", "--output", default="js_scan_results.json", help="Output JSON filename")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Number of concurrent workers")
    parser.add_argument("--include-vendor", action="store_true", help="Include vendor/CDN/library JavaScript files")
    parser.add_argument("--recursive", action="store_true", help="Scan JS files found inside other JS files")
    parser.add_argument("--depth", type=int, default=MAX_RECURSIVE_DEPTH, help="Recursive JS discovery depth")

    args = parser.parse_args()

    targets = []

    if args.url:
        targets.append(args.url)

    if args.list:
        targets.extend(load_targets_from_file(args.list))

    if not targets:
        print("[-] Provide -u URL or -l file")
        return

    discovered_js = set()

    print(f"[+] Targets loaded: {len(targets)}")
    print("[+] Discovering JavaScript files...")

    for target in targets:
        if target.lower().endswith(".js") or ".js?" in target.lower():
            discovered_js.add(target)
            continue

        print(f"[+] Crawling: {target}")
        js_files, error = discover_js_files(target, args.cookie)

        if error:
            print(f"[-] {target}: {error}")
            continue

        for js_url in js_files:
            discovered_js.add(js_url)

    if not discovered_js:
        print("[-] No JavaScript files found.")
        return

    if args.recursive:
        discovered_js = expand_nested_js(
            discovered_js,
            cookie=args.cookie,
            include_vendor=args.include_vendor,
            depth=args.depth
        )

    print(f"[+] Total JS files discovered: {len(discovered_js)}")
    print("[+] Scanning JS files...")

    results = {
        "tool": "WebPwn JavaScript Secret Scanner",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": len(targets),
        "total_js_files": len(discovered_js),
        "scanned_js_files": 0,
        "ignored_js_files": 0,
        "total_findings": 0,
        "finding_summary": {},
        "limits": {
            "max_file_size_mb": MAX_SIZE // (1024 * 1024),
            "max_findings_per_file": MAX_FINDINGS_PER_FILE,
            "vendor_filter_enabled": not args.include_vendor,
            "recursive_enabled": args.recursive,
            "recursive_depth": args.depth
        },
        "results": []
    }

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(
                scan_js_file,
                js_url,
                args.cookie,
                args.include_vendor
            ): js_url
            for js_url in discovered_js
        }

        for future in as_completed(future_map):
            js_url = future_map[future]

            try:
                result = future.result()
                results["results"].append(result)

                if result["ignored"]:
                    results["ignored_js_files"] += 1
                elif not result["error"]:
                    results["scanned_js_files"] += 1

                results["total_findings"] += len(result["findings"])

                print(
                    f"[+] Scanned: {js_url} | "
                    f"Findings: {len(result['findings'])} | "
                    f"Nested JS: {len(result.get('nested_js_files', []))} | "
                    f"Ignored: {result['ignored']}"
                )

            except Exception as error:
                results["results"].append({
                    "js_url": js_url,
                    "status": None,
                    "error": str(error),
                    "ignored": False,
                    "nested_js_files": [],
                    "findings": []
                })

    results["finding_summary"] = build_finding_summary(results["results"])

    save_json(args.output, results)
    summary = save_summary(args.output, results)

    print("[+] Done.")
    print(f"[+] Total JS files discovered: {results['total_js_files']}")
    print(f"[+] JS files scanned: {results['scanned_js_files']}")
    print(f"[+] Ignored JS files: {results['ignored_js_files']}")
    print(f"[+] Total findings: {results['total_findings']}")

    print("[+] Finding Summary:")
    if results["finding_summary"]:
        for category, count in results["finding_summary"].items():
            print(f"    {category}: {count}")
    else:
        print("    No findings found")

    print(f"[+] JSON saved to: {args.output}")
    print(f"[+] Summary saved to: {summary}")


if __name__ == "__main__":
    main()


#python3 js_secret_scanner.py -l test -o results/scan.json --workers 20
#python3 js_secret_scanner.py -l test -o results/scan.json --workers 20 --recursive --depth 2
