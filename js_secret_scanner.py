#!/usr/bin/env python3
"""
WebPwn - JavaScript Secret Scanner v3
- Recursive JS scanning: JS files found inside JS files are scanned too
- Full parent chain tracked: page → js → nested_js → deep_js
- Output grouped: source page → JS file (with depth level) → findings
- No findings cap
- Better JS discovery (webpack, dynamic imports, inline scripts)
"""

import argparse
import json
import re
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
USER_AGENT          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
TIMEOUT             = 10
MAX_SIZE            = 5 * 1024 * 1024
MAX_WORKERS         = 10
MAX_RECURSIVE_DEPTH = 3        # default depth for JS-inside-JS

IGNORED_JS_KEYWORDS = [
    "jquery", "bootstrap", "polyfill", "cookie", "consent",
    "analytics", "gtm", "googletagmanager", "google-analytics",
    "hotjar", "vendor", "recaptcha", "datadog", "sentry",
    "newrelic", "lodash", "moment", "react.min", "react-dom.min",
    "vue.min", "angular.min",
]

# ─────────────────────────────────────────
# PATTERNS
# ─────────────────────────────────────────
PATTERNS = {
    "Google API Key":           r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key":           r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":           r"(?i)aws.{0,20}secret.{0,20}['\"][0-9A-Za-z/+]{40}['\"]",
    "JWT Token":                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Stripe Secret Key":        r"sk_live_[0-9a-zA-Z]{20,}",
    "Stripe Public Key":        r"pk_live_[0-9a-zA-Z]{20,}",
    "GitHub Token":             r"gh[pousr]_[A-Za-z0-9_]{30,}",
    "Slack Token":              r"xox[baprs]-[A-Za-z0-9\-]{20,}",
    "Twilio Key":               r"SK[0-9a-fA-F]{32}",
    "SendGrid Key":             r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}",
    "Mailgun Key":              r"key-[0-9a-zA-Z]{32}",
    "Bearer Token":             r"Bearer\s+[A-Za-z0-9_\-.=]{25,}",
    "Private Key Header":       r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "API Key Assignment":       r"(?i)(api[_-]?key|apikey|x-api-key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Access Token Assignment":  r"(?i)(access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-.]{16,}['\"]",
    "Secret Assignment":        r"(?i)(secret|client_secret|app_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
    "Password Assignment":      r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Auth Header Assignment":   r"(?i)(authorization|auth)\s*[:=]\s*['\"][A-Za-z0-9_\-. ]{10,}['\"]",
    "S3 Bucket URL":            r"https?://[a-zA-Z0-9.\-_]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com[^\s\"'<>\\]*",
    "S3 Path Style URL":        r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/[a-zA-Z0-9.\-_]+[^\s\"'<>\\]*",
    "S3 Bucket Name":           r"(?i)(bucket|s3Bucket|s3_bucket|bucketName)\s*[:=]\s*['\"]?([a-z0-9.\-_]{3,63})['\"]?",
    "CloudFront URL":           r"https?://[a-zA-Z0-9]+\.cloudfront\.net[^\s\"'<>\\]*",
    "Firebase URL":             r"https?://[a-zA-Z0-9\-]+\.firebaseio\.com[^\s\"'<>\\]*",
    "Firebase Config":          r"(?i)firebaseConfig\s*=\s*\{[^}]{30,}\}",
    "Google Storage":           r"https?://storage\.googleapis\.com\/[a-zA-Z0-9.\-_]+[^\s\"'<>\\]*",
    "Azure Blob":               r"https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net[^\s\"'<>\\]*",
    "Absolute URL":             r"https?://[^\s\"'<>\\]{10,}",
    "API Endpoint":             r"['\"](\/api\/[A-Za-z0-9_\-\/?=&%.]+)['\"]",
    "API Route":                r"['\"](\/?(api|v1|v2|v3|v4|graphql|auth|oauth|login|admin|user|account|payment|checkout|session|token|internal|private|debug)[A-Za-z0-9_\-\/?=&%.]*)['\"]",
    "Admin Path":               r"['\"](\/admin[A-Za-z0-9_\-\/?=&%.]*)['\"]",
    "Sensitive File Path":      r"['\"]([A-Za-z0-9_\-\/.]+?\.(env|bak|old|sql|zip|tar|gz|config|xml|json|yaml|yml|ini|log|pem|key|p12|pfx))['\"]",
    "GraphQL Endpoint":         r"['\"](\/?(graphql|gql)[A-Za-z0-9_\-\/?=&%.]*)['\"]",
    "Dangerous eval":           r"\beval\s*\(",
    "document.write":           r"document\.write\s*\(",
    "innerHTML":                r"\.innerHTML\s*=",
    "outerHTML":                r"\.outerHTML\s*=",
    "insertAdjacentHTML":       r"\.insertAdjacentHTML\s*\(",
    "dangerouslySetInnerHTML":  r"dangerouslySetInnerHTML",
    "location.href assign":     r"location\.href\s*=\s*[^=]",
    "window.open":              r"window\.open\s*\(",
    "Local Storage":            r"localStorage\.(getItem|setItem)",
    "Session Storage":          r"sessionStorage\.(getItem|setItem)",
    "Cookie Access":            r"document\.cookie",
    "Email":                    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "IP Address":               r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "Debug Flag":               r"(?i)(debug|verbose|isDev|isDebug)\s*[:=]\s*(true|1|\"true\")",
    "Source Map":               r"\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)",
}


# ─────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────
def build_headers(cookie=None):
    h = {"User-Agent": USER_AGENT}
    if cookie:
        h["Cookie"] = cookie
    return h


def fetch_url(url, cookie=None):
    try:
        r = requests.get(
            url,
            headers=build_headers(cookie),
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,
            verify=False,
        )
        content_length = r.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_SIZE:
            return None, "File too large"
        text = r.text
        if len(text.encode("utf-8", errors="ignore")) > MAX_SIZE:
            return None, "File too large"
        return r, None
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────
# JS DISCOVERY
# ─────────────────────────────────────────
def is_ignored_js(js_url: str) -> bool:
    lowered = js_url.lower()
    return any(kw in lowered for kw in IGNORED_JS_KEYWORDS)


def normalize_url(url: str) -> str:
    return url.split("#")[0].strip()


def extract_js_urls_from_text(text: str, base_url: str) -> set:
    """
    Extract every possible JS URL from any text content.
    Covers: absolute URLs, relative paths, dynamic imports,
    webpack chunks, src assignments, JSON config values.
    """
    js_files = set()

    patterns = [
        # Absolute URLs ending in .js
        r'https?://[^\s"\'<>\\]+?\.js(?:\?[^\s"\'<>\\]*)?',
        # Quoted relative paths ending in .js
        r'["\']([^"\'<>\s]+?\.js(?:\?[^"\']*)?)["\']',
        # Dynamic import() / require()
        r'(?:import|require)\s*\(\s*["\']([^"\']+?\.js(?:\?[^"\']*)?)["\']',
        # Webpack chunks: "chunk-abc123.js" or "0.abc123.js"
        r'["\']([a-zA-Z0-9_\-./]+?(?:chunk|bundle|vendor)[a-zA-Z0-9_\-./]*\.js)["\']',
        # src: "/static/file.js"
        r'src\s*:\s*["\']([^"\']+?\.js(?:\?[^"\']*)?)["\']',
        # scriptURL = "..."
        r'(?:scriptURL|scriptSrc|jsFile|jsPath)\s*[=:]\s*["\']([^"\']+?\.js)["\']',
    ]

    for pat in patterns:
        for match in re.findall(pat, text):
            if isinstance(match, tuple):
                match = match[0]
            if not match:
                continue
            full = normalize_url(urljoin(base_url, match))
            if full.startswith("http") and ".js" in full:
                js_files.add(full)

    return js_files


def discover_js_from_page(page_url: str, cookie=None) -> tuple:
    """
    Crawl an HTML page and return:
    - external JS file URLs
    - inline script contents
    """
    r, error = fetch_url(page_url, cookie)
    if error or not r:
        return [], [], error

    js_files = set()
    inline_scripts = []
    html = r.text
    base = r.url

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all("script"):
        src = (tag.get("src") or tag.get("data-src")
               or tag.get("data-lazy-src") or tag.get("data-url"))
        if src:
            full = normalize_url(urljoin(base, src))
            if full.startswith("http") and ".js" in full:
                js_files.add(full)
        else:
            content = tag.string
            if content and len(content.strip()) > 50:
                inline_scripts.append(content)

    # <link rel="preload" as="script">
    for tag in soup.find_all("link"):
        rel = tag.get("rel", [])
        if "preload" in rel and tag.get("as") == "script":
            href = tag.get("href")
            if href:
                full = normalize_url(urljoin(base, href))
                if full.startswith("http"):
                    js_files.add(full)

    # Regex sweep over the full HTML too
    js_files.update(extract_js_urls_from_text(html, base))

    return sorted(js_files), inline_scripts, None


# ─────────────────────────────────────────
# SCANNING
# ─────────────────────────────────────────
def get_line_number(content: str, idx: int) -> int:
    return content[:idx].count("\n") + 1


def clean_match(text: str) -> str:
    text = text.strip()
    return text[:300] + "..." if len(text) > 300 else text


def scan_content(content: str) -> list:
    findings = []
    seen = set()
    for category, pattern in PATTERNS.items():
        try:
            for match in re.finditer(pattern, content):
                matched_text = clean_match(match.group(0))
                key = f"{category}:{matched_text}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "category": category,
                    "line":     get_line_number(content, match.start()),
                    "match":    matched_text,
                })
        except re.error:
            continue
    return findings


def scan_single_js(js_url: str, cookie=None, include_vendor=False) -> dict:
    """
    Fetch and scan one JS file.
    Returns findings + any new JS URLs found inside it.
    """
    result = {
        "js_url":          js_url,
        "status":          None,
        "error":           None,
        "ignored":         False,
        "size_bytes":      0,
        "js_inside":       [],   # JS URLs discovered inside this file
        "findings":        [],
    }

    if not include_vendor and is_ignored_js(js_url):
        result["ignored"] = True
        result["error"]   = "Ignored vendor/library JS"
        return result

    r, error = fetch_url(js_url, cookie)
    if error or not r:
        result["error"] = error
        return result

    result["status"] = r.status_code

    if r.status_code >= 400:
        result["error"] = f"HTTP {r.status_code}"
        return result

    content_type = r.headers.get("Content-Type", "").lower()
    is_js_url    = ".js" in js_url.lower().split("?")[0]
    is_js_type   = "javascript" in content_type or "ecmascript" in content_type

    if not is_js_url and not is_js_type:
        result["error"] = "Not a JavaScript file"
        return result

    text = r.text
    result["size_bytes"] = len(text.encode("utf-8", errors="ignore"))
    result["findings"]   = scan_content(text)

    # Extract JS URLs found INSIDE this JS file
    result["js_inside"]  = sorted(extract_js_urls_from_text(text, js_url))

    return result


# ─────────────────────────────────────────
# RECURSIVE ENGINE
# ─────────────────────────────────────────
def recursive_scan(
    initial_js: set,
    target_map: dict,
    cookie=None,
    include_vendor=False,
    max_depth=MAX_RECURSIVE_DEPTH,
    workers=MAX_WORKERS,
) -> list:
    """
    Scan JS files and recursively follow JS-inside-JS links.

    Returns list of result dicts, each with extra fields:
      - depth       : how deep this JS was found (0 = from HTML page)
      - parent_js   : which JS file contained this one (None if from HTML)
      - source_page : original HTML page target
    """
    all_results  = []
    scanned_urls = set()

    # Queue: list of (js_url, depth, parent_js)
    queue = [(url, 0, None) for url in initial_js]

    current_depth = 0

    while queue:
        # Separate current depth items from deeper ones
        current_batch = [(u, d, p) for u, d, p in queue if d == current_depth]
        queue         = [(u, d, p) for u, d, p in queue if d != current_depth]

        if not current_batch:
            current_depth += 1
            if current_depth > max_depth:
                break
            continue

        depth_label = f"Depth {current_depth}" if current_depth > 0 else "Page JS"
        print(f"\n  [{'~' * (current_depth + 1)}] Scanning {len(current_batch)} JS files "
              f"({depth_label})...")

        to_scan = [(u, d, p) for u, d, p in current_batch if u not in scanned_urls]
        for u, _, _ in to_scan:
            scanned_urls.add(u)

        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {
                ex.submit(scan_single_js, u, cookie, include_vendor): (u, d, p)
                for u, d, p in to_scan
            }

            for future in as_completed(future_map):
                js_url, depth, parent_js = future_map[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "js_url": js_url, "status": None, "error": str(e),
                        "ignored": False, "size_bytes": 0,
                        "js_inside": [], "findings": [],
                    }

                # Attach metadata
                result["depth"]       = depth
                result["parent_js"]   = parent_js
                result["source_page"] = target_map.get(js_url, "unknown")

                all_results.append(result)

                findings_count = len(result["findings"])
                size_kb        = result.get("size_bytes", 0) // 1024
                status_str     = result.get("status") or result.get("error") or "ignored"
                indent         = "    " + "  " * depth

                if result["ignored"]:
                    pass  # silent
                elif findings_count > 0:
                    print(f"{indent}[!] {js_url}")
                    print(f"{indent}    Status: {status_str} | "
                          f"Size: {size_kb}KB | Findings: {findings_count}")
                    for f in result["findings"][:3]:
                        print(f"{indent}    → [{f['category']}] "
                              f"Line {f['line']}: {f['match'][:70]}...")
                    if findings_count > 3:
                        print(f"{indent}    → ... and {findings_count - 3} more")
                else:
                    print(f"{indent}[✓] {js_url} "
                          f"({status_str}, {size_kb}KB, 0 findings)")

                # Queue nested JS for next depth level
                if current_depth < max_depth:
                    for nested_url in result.get("js_inside", []):
                        if nested_url not in scanned_urls:
                            # Map nested JS back to same source page
                            if nested_url not in target_map:
                                target_map[nested_url] = target_map.get(js_url, "unknown")
                            queue.append((nested_url, depth + 1, js_url))

        current_depth += 1
        if current_depth > max_depth:
            break

    return all_results


# ─────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────
def load_targets_from_file(path: str) -> list:
    targets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("http"):
                line = "https://" + line
            targets.append(line)
    return targets


def get_hostname(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def build_grouped(results: list) -> dict:
    """
    Group as:
      { source_page: [ result_dict, ... ] }
    sorted by source page then depth
    """
    grouped = defaultdict(list)
    for r in results:
        grouped[r.get("source_page", "unknown")].append(r)
    # Sort each group by depth then url
    for page in grouped:
        grouped[page].sort(key=lambda x: (x.get("depth", 0), x["js_url"]))
    return dict(grouped)


def build_summary_counts(results: list) -> dict:
    summary = {}
    for item in results:
        for f in item.get("findings", []):
            cat = f.get("category", "Unknown")
            summary[cat] = summary.get(cat, 0) + 1
    return dict(sorted(summary.items()))


def save_json(filename: str, data: dict):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_report(filename: str, data: dict) -> str:
    """
    Human-readable grouped report.

    Format:
    ════════════════════════════════
      account.vueling.com
    ════════════════════════════════
      [Depth 0 - from page]
        JS: https://.../main.js  (200, 142KB, 3 findings)
          [API Key]  Line 12: apiKey="ABC..."
          [JWT]      Line 45: eyJhbGci...

      [Depth 1 - found inside main.js]
        JS: https://.../chunk.js  (200, 88KB, 1 finding)
          [Password] Line 7: password="secret"
    """
    out = filename.replace(".json", "_report.txt")

    with open(out, "w", encoding="utf-8") as f:
        f.write("WebPwn JavaScript Secret Scanner v3\n")
        f.write("=" * 52 + "\n\n")
        f.write(f"Generated  : {data['generated_at']}\n")
        f.write(f"Targets    : {data['total_targets']}\n")
        f.write(f"JS Found   : {data['total_js_files']}\n")
        f.write(f"JS Scanned : {data['scanned_js_files']}\n")
        f.write(f"Ignored    : {data['ignored_js_files']}\n")
        f.write(f"Max Depth  : {data['max_depth']}\n")
        f.write(f"Findings   : {data['total_findings']}\n\n")

        f.write("FINDING SUMMARY\n")
        f.write("-" * 30 + "\n")
        for cat, count in data.get("finding_summary", {}).items():
            f.write(f"  {cat}: {count}\n")

        f.write("\n\n" + "=" * 52 + "\n")
        f.write("DETAILED FINDINGS (grouped by source)\n")
        f.write("=" * 52 + "\n")

        grouped = data.get("grouped", {})

        for source_page, items in sorted(grouped.items()):
            # Only show sources that have findings
            has_findings = any(len(r.get("findings", [])) > 0 for r in items)
            if not has_findings:
                continue

            host        = get_hostname(source_page)
            total_found = sum(len(r.get("findings", [])) for r in items)

            f.write(f"\n\n{'═' * 52}\n")
            f.write(f"  {host}\n")
            f.write(f"  {source_page}\n")
            f.write(f"  Total findings: {total_found}\n")
            f.write(f"{'═' * 52}\n")

            # Group by depth within this source
            by_depth = defaultdict(list)
            for r in items:
                by_depth[r.get("depth", 0)].append(r)

            for depth in sorted(by_depth.keys()):
                depth_items = by_depth[depth]
                has_any     = any(len(r.get("findings", [])) > 0 for r in depth_items)
                if not has_any:
                    continue

                if depth == 0:
                    label = "Depth 0 — JS from HTML page"
                else:
                    label = f"Depth {depth} — JS found inside JS (level {depth})"

                f.write(f"\n  [{label}]\n")

                for r in depth_items:
                    findings = r.get("findings", [])
                    if not findings:
                        continue

                    size_kb    = r.get("size_bytes", 0) // 1024
                    parent_str = f"  ← inside: {r['parent_js']}" if r.get("parent_js") else ""

                    f.write(f"\n    JS : {r['js_url']}\n")
                    if parent_str:
                        f.write(f"         {parent_str}\n")
                    f.write(f"         Status: {r.get('status')} | "
                            f"Size: {size_kb}KB | "
                            f"Findings: {len(findings)}\n")
                    f.write(f"    {'─' * 46}\n")

                    for finding in findings:
                        f.write(
                            f"      [{finding['category']}] "
                            f"Line {finding['line']}: "
                            f"{finding['match']}\n"
                        )

        # Inline scripts
        if data.get("inline_findings"):
            f.write(f"\n\n{'═' * 52}\n")
            f.write("  INLINE <script> BLOCKS\n")
            f.write(f"{'═' * 52}\n")
            for entry in data["inline_findings"]:
                if not entry["findings"]:
                    continue
                f.write(f"\n  Source: {entry['source']} (inline #{entry['index']})\n")
                f.write(f"  {'─' * 46}\n")
                for finding in entry["findings"]:
                    f.write(
                        f"    [{finding['category']}] "
                        f"Line {finding['line']}: "
                        f"{finding['match']}\n"
                    )

    return out


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WebPwn JavaScript Secret Scanner v3")
    parser.add_argument("-u", "--url",           help="Single target URL")
    parser.add_argument("-l", "--list",          help="File of URLs/domains")
    parser.add_argument("--cookie",              help="Cookie for authenticated scanning")
    parser.add_argument("-o", "--output",        default="js_scan_results.json")
    parser.add_argument("--workers",  type=int,  default=MAX_WORKERS)
    parser.add_argument("--include-vendor",      action="store_true",
                        help="Include vendor/CDN JS files")
    parser.add_argument("--depth",    type=int,  default=MAX_RECURSIVE_DEPTH,
                        help=f"Max depth for JS-inside-JS scanning (default {MAX_RECURSIVE_DEPTH})")
    args = parser.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        targets.extend(load_targets_from_file(args.list))
    if not targets:
        print("[-] Provide -u URL or -l file")
        return

    print(f"\n{'='*54}")
    print(f"  WebPwn JavaScript Secret Scanner v3")
    print(f"  Targets   : {len(targets)}")
    print(f"  JS Depth  : {args.depth} levels deep into JS-inside-JS")
    print(f"{'='*54}\n")

    # ── Phase 1: Discover JS from HTML pages ────────────
    print("[Phase 1] Crawling pages for JS files...\n")

    initial_js    = set()
    target_map    = {}
    inline_findings = []

    for target in targets:
        if target.lower().endswith(".js") or ".js?" in target.lower():
            initial_js.add(target)
            target_map[target] = target
            continue

        print(f"  [~] {target}")
        js_files, inline_scripts, error = discover_js_from_page(target, args.cookie)

        if error:
            print(f"  [!] Error: {error}")
            continue

        print(f"  [✓] {len(js_files)} JS files | "
              f"{len(inline_scripts)} inline scripts")

        for js_url in js_files:
            initial_js.add(js_url)
            if js_url not in target_map:
                target_map[js_url] = target

        for i, script in enumerate(inline_scripts):
            findings = scan_content(script)
            if findings:
                inline_findings.append({
                    "source":   target,
                    "index":    i + 1,
                    "findings": findings,
                })

    if not initial_js:
        print("\n[-] No JS files found.")
        return

    print(f"\n[+] Total initial JS files : {len(initial_js)}")

    # ── Phase 2: Recursive scan ─────────────────────────
    print(f"\n[Phase 2] Scanning JS files (depth 0 → {args.depth})...\n")

    all_results = recursive_scan(
        initial_js   = initial_js,
        target_map   = target_map,
        cookie       = args.cookie,
        include_vendor = args.include_vendor,
        max_depth    = args.depth,
        workers      = args.workers,
    )

    # ── Build output ────────────────────────────────────
    scanned  = sum(1 for r in all_results if not r["ignored"] and not r.get("error"))
    ignored  = sum(1 for r in all_results if r["ignored"])
    grouped  = build_grouped(all_results)
    summary  = build_summary_counts(all_results)
    total_f  = sum(v for v in summary.values())

    # Depth stats
    depth_counts = {}
    for r in all_results:
        d = r.get("depth", 0)
        depth_counts[d] = depth_counts.get(d, 0) + 1

    output_data = {
        "tool":             "WebPwn JavaScript Secret Scanner",
        "version":          "3.0",
        "generated_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets":    len(targets),
        "total_js_files":   len(all_results),
        "scanned_js_files": scanned,
        "ignored_js_files": ignored,
        "max_depth":        args.depth,
        "depth_counts":     depth_counts,
        "total_findings":   total_f,
        "finding_summary":  summary,
        "grouped":          {k: v for k, v in grouped.items()},
        "inline_findings":  inline_findings,
        "all_results":      all_results,
    }

    save_json(args.output, output_data)
    report_file = save_report(args.output, output_data)

    # ── Final summary ───────────────────────────────────
    print(f"\n{'='*54}")
    print(f"[+] DONE")
    print(f"{'='*54}")
    print(f"  JS files scanned    : {scanned}")
    print(f"  Ignored (vendor)    : {ignored}")
    print(f"  Inline findings     : {len(inline_findings)}")
    print(f"  Total findings      : {total_f}")

    print(f"\n  JS by depth:")
    for d in sorted(depth_counts):
        label = "from HTML page" if d == 0 else f"inside JS level {d}"
        print(f"    Depth {d} ({label}): {depth_counts[d]} files")

    if summary:
        print(f"\n  Finding breakdown:")
        for cat, count in summary.items():
            print(f"    {cat}: {count}")

    print(f"\n  Output files:")
    print(f"    JSON   : {args.output}")
    print(f"    Report : {report_file}")
    print()


if __name__ == "__main__":
    main()

# Default — scans 3 levels deep into JS-inside-JS
py js_secret_scanner.py -u https://vueling.com

# Go deeper (5 levels)
py js_secret_scanner.py -u https://vueling.com --depth 5

# Scan all alive subdomains
py js_secret_scanner.py -l subenum-vueling.com/alive-subs.txt --depth 3
