#!/usr/bin/env python3
"""
FortiGate captive-portal auto-login (NIT Goa).
Run visibly:   python autologin.py      (console shows every check)
Run hidden:    pythonw autologin.py     (read autologin.log instead)
"""
import os, re, sys, time, socket, logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urljoin
import requests, urllib3

urllib3.disable_warnings()

# ======================= CONFIG =======================
USERNAME = os.environ.get("AUTOLOGIN_USER", "your_id")
PASSWORD = os.environ.get("AUTOLOGIN_PASS", "your_password")

CHECK_INTERVAL   = 3      # s between checks while online (fast check only)
FULL_CHECK_EVERY = 60     # s between full multi-method cross-checks while online
REQ_TIMEOUT      = 5      # s per probe request
RETRY_BASE       = 10     # s wait after first failed login (doubles each time)
RETRY_MAX        = 90     # s cap for backoff on errors
MAX_REJECTIONS   = 3      # portal rejects in a row -> cooldown (protects account lockout)
COOLDOWN         = 900    # s pause after MAX_REJECTIONS
UNKNOWN_BEFORE_BLIND = 3  # consecutive UNKNOWN checks before a blind login attempt
NO_NET_BEFORE_BLIND  = 6  # consecutive NO_NETWORK checks (~30 s) before a blind login attempt
NO_NET_DELAY     = 5      # s between checks while there is no network
ONLINE_LOG_EVERY = 60     # s: while stably online, write to file at most this often
HEARTBEAT_EVERY  = 600    # s: periodic summary line
USE_SYSTEM_PROXY = False  # False = ignore Windows/VPN proxy settings for probes
LOCK_PORT        = 47653  # local port used to stop two copies running at once

# Detection endpoints
PRIMARY_URL = "http://connectivitycheck.gstatic.com/generate_204"
MSFT_URL    = "http://www.msftconnecttest.com/connecttest.txt"
FIREFOX_URL = "http://detectportal.firefox.com/success.txt"
IP_PROBE    = "http://1.1.1.1"
HTTPS_URL   = "https://www.google.com/generate_204"
TCP_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53)]

# Used to find the login page (tried in order)
LOGIN_PROBES = ["http://www.msftconnecttest.com/redirect", "http://1.1.1.1",
                "http://neverssl.com", PRIMARY_URL]
# Last resort: gateways seen on campus (only used if no probe leads to the login form)
KNOWN_GATEWAYS = ["192.168.92.1", "192.168.96.1", "192.168.100.1", "192.168.108.1"]
PORTAL_PORT = 1000
# ======================================================

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE, "autologin.log")

log = logging.getLogger("autologin")


def setup_logging():
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.INFO)          # file: important events
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stdout is not None:         # under pythonw there is no console
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)     # console: every single check
        ch.setFormatter(fmt)
        log.addHandler(ch)


S = requests.Session()
S.trust_env = USE_SYSTEM_PROXY
S.headers["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 Chrome/120 Safari/537.36")


class Result:
    def __init__(self, name, verdict, detail, secs, portal_url=None):
        self.name, self.verdict, self.detail = name, verdict, detail
        self.secs, self.portal_url = secs, portal_url

    def line(self):
        return f"    {self.name:<14} -> {self.verdict.upper():<7} {self.detail} ({self.secs:.2f}s)"


def short_err(e):
    return f"{type(e).__name__}: {str(e)[:90]}"


# ---------------- portal link extraction ----------------
FGT_ABS = re.compile(r"""(https?://[^\s"'<>()\\]+?/fgtauth\?[0-9A-Za-z]+)""", re.I)
FGT_REL = re.compile(r"""["'(=\s](/?fgtauth\?[0-9A-Za-z]+)""", re.I)

def extract_portal_url(base_url, headers, body):
    """Find the fgtauth link in a Location header or inside a redirect stub page
    (meta refresh, JavaScript window.location, plain link). Returns an absolute URL or None."""
    loc = headers.get("Location", "") if headers else ""
    if "fgtauth" in loc:
        return urljoin(base_url, loc)
    text = (body or "").replace("\\/", "/").replace("&amp;", "&")
    m = FGT_ABS.search(text)
    if m:
        return m.group(1)
    m = FGT_REL.search(text)
    if m:
        return urljoin(base_url, m.group(1))
    return None


# ---------------- detection methods ----------------
def http_check(name, url, is_online):
    t = time.time()
    try:
        r = S.get(url, timeout=REQ_TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        return Result(name, "error", short_err(e), time.time() - t)
    dt = time.time() - t
    body = r.text[:20000] if r.content else ""
    purl = extract_portal_url(url, r.headers, body)
    if purl or 'name="magic"' in body or "fgtauth" in body:
        return Result(name, "portal", f"HTTP {r.status_code}, portal redirect/page detected", dt, purl)
    if is_online(r):
        return Result(name, "online", f"HTTP {r.status_code}", dt)
    return Result(name, "other", f"HTTP {r.status_code}, unexpected response", dt)


def m_primary():
    return http_check("gstatic_204", PRIMARY_URL, lambda r: r.status_code == 204)

def m_msft():
    return http_check("msft_test", MSFT_URL,
                      lambda r: r.status_code == 200 and r.text.strip() == "Microsoft Connect Test")

def m_firefox():
    return http_check("firefox_test", FIREFOX_URL,
                      lambda r: r.status_code == 200 and r.text.strip() == "success")

def m_ip_probe():
    # when logged in, 1.1.1.1 redirects to Cloudflare; when logged out, to fgtauth
    return http_check("ip_probe", IP_PROBE,
                      lambda r: r.status_code in (301, 302, 307, 308) and
                      ("one.one.one.one" in r.headers.get("Location", "") or
                       "1.1.1.1" in r.headers.get("Location", "")))

def m_https():
    t = time.time()
    try:
        r = S.get(HTTPS_URL, timeout=REQ_TIMEOUT, allow_redirects=False)
        v = "online" if r.status_code == 204 else "other"
        return Result("https_204", v, f"HTTP {r.status_code}", time.time() - t)
    except requests.RequestException as e:
        return Result("https_204", "error", short_err(e), time.time() - t)

def m_tcp():
    # weak hint only: never decides the status by itself
    t = time.time()
    for host, port in TCP_TARGETS:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return Result("tcp_connect", "weak", f"connected to {host}:{port}", time.time() - t)
        except OSError:
            continue
    return Result("tcp_connect", "error", "no TCP route to any target", time.time() - t)


FAST = [m_primary]
FULL = [m_primary, m_msft, m_firefox, m_ip_probe, m_https, m_tcp]


def run_checks(methods):
    out = []
    for m in methods:
        try:
            out.append(m())
        except Exception as e:  # a buggy check must never kill the loop
            out.append(Result(m.__name__, "error", f"check crashed: {short_err(e)}", 0))
    return out


def decide(results):
    """Returns (status, portal_url, note). Status: ONLINE / PORTAL / NO_NETWORK / UNKNOWN."""
    portal = [r for r in results if r.verdict == "portal"]
    online = [r for r in results if r.verdict == "online"]
    if portal:
        url = next((r.portal_url for r in portal if r.portal_url), None)
        note = "CONFLICT: some checks say online, portal redirect seen; trusting the redirect" if online else ""
        return "PORTAL", url, note
    if online:
        return "ONLINE", None, ""
    strong = [r for r in results if r.verdict != "weak"]
    if strong and all(r.verdict == "error" for r in strong):
        return "NO_NETWORK", None, ""
    return "UNKNOWN", None, ""


# ---------------- login ----------------
def strip_html(html):
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()

def save(name, text):
    try:
        with open(os.path.join(BASE, name), "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        log.warning(f"could not save {name}: {e}")

def hidden_fields(html):
    fields = {}
    for tag in re.findall(r'<input[^>]*type="hidden"[^>]*>', html, re.I):
        n = re.search(r'name="([^"]*)"', tag)
        v = re.search(r'value="([^"]*)"', tag)
        if n and n.group(1):
            fields[n.group(1)] = v.group(1) if v else ""
    return fields

def fetch_login_form(url, depth=0):
    """GET url. If it is the login form, return it. If it is a redirect stub that points
    at the fgtauth page, follow that link (up to 2 hops). Otherwise return None."""
    r = S.get(url, timeout=8, verify=False)
    if 'name="magic"' in r.text:
        log.info(f"  login form found at {r.url}")
        return r
    save("probe_response.html",
         f"<!-- {url} -> {r.url} | HTTP {r.status_code} | headers: {dict(r.headers)} -->\n{r.text}")
    link = extract_portal_url(r.url, r.headers, r.text)
    if link and link != url and depth < 2:
        log.info(f"  {url} gave a redirect page (HTTP {r.status_code}); following portal link {link}")
        return fetch_login_form(link, depth + 1)
    log.info(f"  {url}: no login form and no portal link (HTTP {r.status_code}, "
             f"{len(r.text)} bytes, landed on {r.url[:80]}); saved probe_response.html")
    return None

def find_portal_page(hint_url):
    candidates = ([hint_url] if hint_url else []) + LOGIN_PROBES
    seen = set()
    for u in candidates:
        if u in seen:
            continue
        seen.add(u)
        try:
            page = fetch_login_form(u)
        except requests.RequestException as e:
            log.info(f"  portal lookup via {u}: {short_err(e)}")
            continue
        if page is not None:
            return page
    log.info("  trying known campus gateways directly (last resort)")
    for gw in KNOWN_GATEWAYS:
        for path in ("", "fgtauth"):
            u = f"http://{gw}:{PORTAL_PORT}/{path}"
            try:
                r = S.get(u, timeout=2, verify=False)
                if 'name="magic"' in r.text:
                    log.info(f"  login form found directly at {u}")
                    return r
            except requests.RequestException:
                break  # gateway unreachable, skip its other path
    return None

def do_login(hint_url):
    """Returns ('ok'|'rejected'|'error', message)."""
    page = find_portal_page(hint_url)
    if page is None:
        return "error", ("could not reach a portal login form (see probe_response.html "
                         "for what the firewall actually returned)")
    html = page.text
    save("portal_page.html", f"<!-- {page.url} -->\n{html}")
    m = re.search(r'<form[^>]*action="([^"]*)"', html, re.I)
    post_url = urljoin(page.url, m.group(1)) if m and m.group(1) else page.url.split("?")[0]
    data = hidden_fields(html)
    if "magic" not in data:
        return "error", "login form has no 'magic' token"
    fields = sorted(data) + ["username", "password"]
    data["username"], data["password"] = USERNAME, PASSWORD
    log.info(f"  submitting login to {post_url} as '{USERNAME}' (fields: {fields})")
    try:
        resp = S.post(post_url, data=data, timeout=10, verify=False)
    except requests.RequestException as e:
        return "error", f"POST failed: {short_err(e)}"
    save("post_response.html", resp.text)
    snippet = strip_html(resp.text)[:200]
    log.info(f"  portal replied HTTP {resp.status_code}, {len(resp.text)} bytes. Text: \"{snippet}\"")

    for i in range(1, 5):
        time.sleep(2)
        status = decide(run_checks(FULL))[0]
        log.info(f"  verify {i}/4: status = {status}")
        if status == "ONLINE":
            return "ok", "internet confirmed after login"
    return "rejected", f"still not online after login. Portal said: \"{snippet}\""


# ---------------- main loop ----------------
def fmt_dur(s):
    s = int(s)
    return f"{s//3600}h{(s%3600)//60:02d}m{s%60:02d}s" if s >= 3600 else f"{s//60}m{s%60:02d}s"

def main():
    setup_logging()
    lock = socket.socket()
    try:
        lock.bind(("127.0.0.1", LOCK_PORT))
    except OSError:
        log.error("another copy of autologin is already running. Exiting.")
        return
    if USERNAME == "your_id" or PASSWORD == "your_password":
        log.critical("credentials not set. Set AUTOLOGIN_USER / AUTOLOGIN_PASS or edit the script.")
        return

    log.info("=" * 60)
    log.info(f"autologin started | user={USERNAME} | python {sys.version.split()[0]} | log={LOG_FILE}")
    log.info(f"interval={CHECK_INTERVAL}s full-check-every={FULL_CHECK_EVERY}s proxy={USE_SYSTEM_PROXY}")

    state = None
    n = logins = 0
    rejections = errors = blind_streak = 0
    next_login_at = 0.0
    offline_since = None
    last_full = last_online_filelog = 0.0
    last_heartbeat = time.time()
    started = time.time()

    while True:
        delay = CHECK_INTERVAL
        try:
            n += 1
            now = time.time()
            results = run_checks(FAST)
            status, purl, note = decide(results)
            kind = "fast"
            if status != "ONLINE" or now - last_full >= FULL_CHECK_EVERY:
                if status != "ONLINE":
                    log.info(f"CHECK #{n}: fast check says {status}; running full multi-method check...")
                results = run_checks(FULL)
                status, purl, note = decide(results)
                kind, last_full = "full", time.time()

            changed = status != state
            quiet = (status == "ONLINE" and not changed and
                     now - last_online_filelog < ONLINE_LOG_EVERY)
            lvl = logging.DEBUG if quiet else logging.INFO
            if status == "ONLINE" and not quiet:
                last_online_filelog = now
            log.log(lvl, f"CHECK #{n} [{kind}]: {status}")
            for r in results:
                log.log(lvl, r.line())
            if note:
                log.warning(note)

            if changed:
                log.warning(f"STATE CHANGE: {state or 'START'} -> {status}")
                if status != "ONLINE" and offline_since is None:
                    offline_since = now
            state = status

            if status == "ONLINE":
                blind_streak = 0
                if offline_since is not None:
                    log.warning(f"Back online. Outage lasted {fmt_dur(now - offline_since)}.")
                    offline_since = None
                    rejections = errors = 0
                    next_login_at = 0.0

            elif status in ("PORTAL", "UNKNOWN", "NO_NETWORK"):
                if status == "PORTAL":
                    blind_streak, ready = 0, True
                else:
                    blind_streak += 1
                    need = UNKNOWN_BEFORE_BLIND if status == "UNKNOWN" else NO_NET_BEFORE_BLIND
                    ready = blind_streak >= need
                    why = ("no clear online or portal signal" if status == "UNKNOWN"
                           else "no network reachable (cable/adapter down, or firewall resetting connections)")
                    log.warning(f"Status {status} ({blind_streak}/{need}): {why}.")
                    delay = NO_NET_DELAY

                if ready and time.time() >= next_login_at:
                    how = "portal detected" if status == "PORTAL" else "blind fallback"
                    log.warning(f"LOGIN ATTEMPT ({how})")
                    t0 = time.time()
                    outcome, msg = do_login(purl)
                    if outcome == "ok":
                        logins += 1
                        rejections = errors = 0
                        log.warning(f"LOGIN OK in {time.time() - t0:.1f}s: {msg}")
                        state = "ONLINE"
                        last_full = time.time()
                    elif outcome == "rejected":
                        rejections += 1
                        if rejections >= MAX_REJECTIONS:
                            log.critical(f"LOGIN REJECTED {rejections}x in a row: {msg}. "
                                         f"Check username/password. Pausing {fmt_dur(COOLDOWN)} "
                                         "to avoid locking your account.")
                            next_login_at = time.time() + COOLDOWN
                            rejections = 0
                        else:
                            wait = min(RETRY_BASE * 2 ** (rejections - 1), RETRY_MAX)
                            log.error(f"LOGIN REJECTED ({rejections}/{MAX_REJECTIONS}): {msg}. Retry in {wait}s")
                            next_login_at = time.time() + wait
                    else:
                        errors += 1
                        wait = min(RETRY_BASE * 2 ** (errors - 1), RETRY_MAX)
                        log.error(f"LOGIN ERROR (#{errors}): {msg}. Retry in {wait}s")
                        next_login_at = time.time() + wait
                elif ready:
                    left = int(next_login_at - time.time())
                    log.info(f"  waiting {left}s before next login attempt (backoff/cooldown)")
                    delay = max(1, min(left, 30))
                else:
                    delay = NO_NET_DELAY if status == "NO_NETWORK" else 5

            if time.time() - last_heartbeat >= HEARTBEAT_EVERY:
                last_heartbeat = time.time()
                log.info(f"HEARTBEAT: status={state} checks={n} logins={logins} "
                         f"running={fmt_dur(time.time() - started)}")

        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("unexpected error in main loop (continuing)")
            delay = 10
        time.sleep(delay)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("stopped by user (Ctrl+C)")
    except Exception:
        log.exception("FATAL: script crashed")
        raise
