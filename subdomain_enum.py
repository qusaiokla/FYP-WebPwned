import argparse
import subprocess
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True
        )
        return result.stdout.splitlines()
    except:
        return []


def clean_subdomains(lines, domain):
    subs = set()

    for line in lines:
        line = line.strip().lower()

        if not line:
            continue

        if line.startswith("*."):
            line = line[2:]

        if line == domain or line.endswith("." + domain):
            subs.add(line)

    return subs


def resolve_host(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False


# 🔹 FAST SOURCES
def subfinder(domain):
    print("[+] subfinder")
    return clean_subdomains(
        run_command(f"subfinder -d {domain} -all -recursive -silent"),
        domain
    )


def assetfinder(domain):
    print("[+] assetfinder")
    return clean_subdomains(
        run_command(f"assetfinder --subs-only {domain}"),
        domain
    )


def amass_fast(domain):
    print("[+] amass (fast)")
    return clean_subdomains(
        run_command(f"amass enum -passive -d {domain} -norecursive -noalts"),
        domain
    )


def tldfinder(domain):
    print("[+] tldfinder")
    return clean_subdomains(
        run_command(f"tldfinder -d {domain}"),
        domain
    )


# 🔹 OPTIONAL (slower)
def amass_deep(domain):
    print("[+] amass (deep)")
    return clean_subdomains(
        run_command(f"amass enum -passive -d {domain}"),
        domain
    )


def save(domain, subs):
    filename = f"{domain}_subdomains.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# {domain}\n")
        f.write(f"# Total: {len(subs)}\n\n")

        for s in sorted(subs):
            f.write(s + "\n")

    return filename


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--resolve", action="store_true")

    args = parser.parse_args()
    domain = args.domain

    print(f"[+] Target: {domain}")

    all_subs = set()

    # ⚡ RUN IN PARALLEL
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(subfinder, domain),
            executor.submit(assetfinder, domain),
            executor.submit(amass_fast, domain),
            executor.submit(tldfinder, domain),
        ]

        for f in futures:
            all_subs.update(f.result())

    # optional deep
    if args.deep:
        all_subs.update(amass_deep(domain))

    # optional resolve filter
    if args.resolve:
        print("[+] filtering live hosts...")
        all_subs = {s for s in all_subs if resolve_host(s)}

    file = save(domain, all_subs)

    print(f"[+] DONE → {len(all_subs)} subdomains")
    print(f"[+] saved → {file}")


if __name__ == "__main__":
    main()


#how to run it 
#Fast + Good results (recommended) ----> py subdomain_enum.py -d amazon.com
#Bigger result (still fast) ----> py subdomain_enum.py -d amazon.com --deep
#Only real resolving domains ----> py subdomain_enum.py -d amazon.com --resolve
