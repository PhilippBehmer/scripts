import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

def fuzz_vhosts(base_domain, wordlist, depth, max_depth, target_ip, port,
                min_size, max_size, exact_size, exclude_size,
                timeout=3, max_workers=10):
    if depth > max_depth:
        return []

    hits = []
    print(f"\n[+] Depth {depth} - Fuzzing {base_domain}")

    total = len(wordlist)
    completed = 0

    def check_subdomain(word):
        nonlocal completed
        subdomain = f"{word}.{base_domain}"
        try:
            headers = {"Host": subdomain}
            url = f"http://{target_ip}:{port}"
            response = requests.get(url, headers=headers, timeout=timeout)
            size = len(response.content)

            if response.status_code == 200:
                if exact_size is not None and size != exact_size:
                    result = None
                elif exclude_size is not None and size == exclude_size:
                    result = None
                elif (min_size is None or size >= min_size) and (max_size is None or size <= max_size):
                    result = subdomain
                else:
                    result = None
            else:
                result = None
        except requests.RequestException:
            result = None

        completed += 1
        percent = (completed / total) * 100
        sys.stdout.write(f"\r[+] Progress: {completed}/{total} ({percent:.1f}%)")
        sys.stdout.flush()

        if result:
            print(f"\n[✓] Found: {result} (Status: 200, Size: {size})")
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_subdomain, word): word for word in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hits.append(result)

    # Recurse
    for hit in hits:
        hits += fuzz_vhosts(hit, wordlist, depth + 1, max_depth, target_ip, port,
                            min_size, max_size, exact_size, exclude_size, timeout, max_workers)

    return hits

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursive VHost Fuzzer with multithreading and progress status")
    parser.add_argument("target_ip", help="Target IP address (e.g. 10.10.10.10)")
    parser.add_argument("base_domain", help="Base domain (e.g. target.htb)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--depth", type=int, default=2, help="Max recursion depth (default: 2)")
    parser.add_argument("--min-size", type=int, default=None, help="Minimum response size to include")
    parser.add_argument("--max-size", type=int, default=None, help="Maximum response size to include")
    parser.add_argument("--exact-size", type=int, default=None, help="Only include responses with this exact size")
    parser.add_argument("--exclude-size", type=int, default=None, help="Exclude responses with this exact size")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    args = parser.parse_args()

    with open(args.wordlist, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    print(f"[*] Starting recursive vhost fuzzing on {args.base_domain}:{args.port} ({args.target_ip}) with {args.threads} threads")
    found_hosts = fuzz_vhosts(
        args.base_domain, words, depth=1, max_depth=args.depth,
        target_ip=args.target_ip, port=args.port,
        min_size=args.min_size, max_size=args.max_size,
        exact_size=args.exact_size, exclude_size=args.exclude_size,
        max_workers=args.threads
    )

    print("\n[✓] Fuzzing complete. Valid vhosts found:")
    for host in sorted(set(found_hosts)):
        print(f" - {host}")
