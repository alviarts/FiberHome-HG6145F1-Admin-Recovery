import requests, random
from Crypto.Cipher import AES

BASE = "http://192.168.1.1"
KEY_FH_CBC = bytes([i + 0x6f for i in range(16)])

def fhencrypt(pwd):
    c = AES.new(KEY_FH_CBC, AES.MODE_CBC, KEY_FH_CBC)
    r = pwd.encode()
    p = 16 - (len(r) % 16)
    return c.encrypt(r + bytes([p] * p)).hex().upper()

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0"
s.get(BASE+"/fh", timeout=10)
sid = s.get(BASE+"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=1", timeout=10).json()["sessionid"]
r = s.post(BASE+"/cgi-bin/ajax",
    data=f"username=admin&loginpd={fhencrypt('admin@789')}&port=0&sessionid={sid}&ajaxmethod=do_login",
    headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
print(f"Login with admin@789: {r.json()}")

sid = s.get(BASE+f"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_={random.random()}", timeout=10).json()["sessionid"]
r = s.post(BASE+"/cgi-bin/ajax",
    data=f"ajaxmethod=admin_management&sessionid={sid}&username=admin&old_password={fhencrypt('admin@789')}&new_password={fhencrypt('admin123')}",
    headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
print(f"Revert: {r.text[:200]}")

sid = s.get(BASE+f"/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_={random.random()}", timeout=10).json()["sessionid"]
r = s.post(BASE+"/cgi-bin/ajax",
    data=f"username=admin&loginpd={fhencrypt('admin123')}&port=0&sessionid={sid}&ajaxmethod=do_login",
    headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=10)
print(f"Verify admin123: {r.json()}")
