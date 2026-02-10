# simulate_traffic.py
import requests, random, time
BASE="http://127.0.0.1:8080"
UA = "Mozilla/5.0 (compatible; DemoBot/1.0)"
session = requests.Session()
session.headers.update({"User-Agent": UA})

benign_paths = ["/","/home","/about","/contact","/login"]
sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT null--"]
xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']

# Low risk: Unusual but not malicious - long paths, many params, no attack tokens
low_risk_paths = ["/very/long/path/that/might/be/suspicious/but/not/malicious", "/search", "/api/data"]
low_risk_queries = ["?param1=value1&param2=value2&param3=value3&param4=value4&param5=value5", "?q=some+long+query+string+without+malice"]

# Medium risk: Partial attack indicators - some SQL/XSS keywords but not full payloads
medium_risk_sqli = ["select * from users", "union all select", "drop table if exists"]
medium_risk_xss = ["javascript:void(0)", "onload=alert", "<img src=invalid>"]

def send_benign(n=50):
    for i in range(n):
        p = random.choice(benign_paths)
        try:
            session.get(BASE + p, timeout=2)
        except Exception:
            pass
        time.sleep(0.05)

def send_low_risk(n=20):
    for i in range(n):
        p = random.choice(low_risk_paths)
        q = random.choice(low_risk_queries)
        try:
            session.get(BASE + p + q, timeout=2)
        except Exception:
            pass
        time.sleep(0.05)

def send_medium_risk(n=10):
    for i in range(n):
        if random.choice([True, False]):
            # Medium SQLi-like
            p = random.choice(medium_risk_sqli)
            try:
                session.post(BASE + "/login", data={"username":p, "password":"pass"}, timeout=2)
            except Exception:
                pass
        else:
            # Medium XSS-like
            p = random.choice(medium_risk_xss)
            try:
                session.get(BASE + "/?q=" + requests.utils.quote(p), timeout=2)
            except Exception:
                pass
        time.sleep(0.05)

def send_sqli():
    for p in sqli_payloads:
        try:
            session.post(BASE + "/login", data={"username":p, "password":"pass"}, timeout=2)
        except Exception:
            pass
        time.sleep(0.05)

def send_xss():
    for p in xss_payloads:
        try:
            session.get(BASE + "/?q=" + requests.utils.quote(p), timeout=2)
        except Exception:
            pass
        time.sleep(0.05)

if __name__ == "__main__":
    send_benign(30)
    send_low_risk(20)
    send_medium_risk(10)
    send_sqli()
    send_xss()
    print("Done sending simulated traffic")
