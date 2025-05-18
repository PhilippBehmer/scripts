# scripts

## recursive-vhost-fuzzing.py

This script performs recursive fuzzing of virtual hosts (VHosts) on a target server. It uses a wordlist to generate subdomains, sends HTTP(S) requests with the corresponding Host header, and checks the responses based on status code and response size. Valid VHosts found are recursively fuzzed again to discover nested subdomains. The script supports multithreading for faster scans and offers various filtering options.

### How it works

1. **Subdomain Generation:**  
   For each word in the wordlist, a subdomain is generated (e.g., `word.target.htb`).

2. **Request Sending:**  
   The script sends HTTP or HTTPS requests to the target IP and port, setting the Host header to the generated subdomain.

3. **Response Filtering:**  
   Only responses matching the specified status codes and size filters are considered valid.

4. **Recursion:**  
   Each valid subdomain found is used as a new base domain for further fuzzing, up to the specified recursion depth.

5. **Multithreading:**  
   Multiple requests are sent in parallel to speed up the process.

### Usage

```bash
python3 recursive-vhost-fuzzing.py <target_ip> <base_domain> <wordlist> [--port PORT] [--depth DEPTH] [--min-size BYTES] [--max-size BYTES] [--exact-size BYTES] [--exclude-size BYTES] [--threads THREADS] [--https] [--status-codes CODES]
```

### Example

```bash
python3 recursive-vhost-fuzzing.py 10.10.10.10 target.htb wordlist.txt --port 80 --depth 2 --threads 20 --https --status-codes 200,302
```

**Parameters:**
- `<target_ip>`: Target IP address (e.g., 10.10.10.10)
- `<base_domain>`: Base domain (e.g., target.htb)
- `<wordlist>`: Path to the wordlist file
- `--port`: Target port (default: 80)
- `--depth`: Maximum recursion depth (default: 2)
- `--min-size`: Minimum response size in bytes
- `--max-size`: Maximum response size in bytes
- `--exact-size`: Only include responses with this exact size
- `--exclude-size`: Exclude responses with this exact size
- `--threads`: Number of parallel threads (default: 10)
- `--https`: Use HTTPS instead of HTTP
- `--status-codes`: Comma-separated list of valid status codes (default: 200)
