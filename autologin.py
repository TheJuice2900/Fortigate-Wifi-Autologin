#!/usr/bin/env python3
"""
Fortigate Login automates captive portal sign-in.
Install on college Wi-Fi with: python3 install_autologin.py
The installer saves credentials and enrolls the current Wi-Fi router.
AUTOLOGIN_USER and AUTOLOGIN_PASS can override the saved credentials.
Logs and portal diagnostics are saved in ~/Library/Logs/FortiGateAutoLogin.
"""
import os, re, sys, time, socket, logging
import subprocess
import json
from pathlib import Path
from html import unescape
from html.parser import HTMLParser
from logging.handlers import RotatingFileHandler
from urllib.parse import urljoin, urlsplit
import requests, urllib3

urllib3.disable_warnings()

# ======================= CONFIG =======================
CONFIG_FILE = Path.home() / "Library/Application Support/FortiGateAutoLogin/config.json"
CONFIG = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
USERNAME = os.environ.get("AUTOLOGIN_USER", CONFIG.get("username", "your_id"))
PASSWORD = os.environ.get("AUTOLOGIN_PASS", CONFIG.get("password", "your_password"))
CAMPUS_NETWORKS = CONFIG.get("networks", [])

CHECK_INTERVAL   = 2      # s between checks on an enrolled college network
FULL_CHECK_EVERY = 300    # s between full cross-checks while online
REQ_TIMEOUT      = 2      # s per probe request
RETRY_BASE       = 2      # s wait after first failed login (doubles each time)
RETRY_MAX        = 90     # s cap for backoff on errors
MAX_REJECTIONS   = 3      # portal rejects in a row -> cooldown (protects account lockout)
COOLDOWN         = 900    # s pause after MAX_REJECTIONS
UNKNOWN_BEFORE_BLIND = 3  # consecutive UNKNOWN checks before a blind login attempt
NO_NET_BEFORE_BLIND  = 6  # consecutive NO_NETWORK checks (~30 s) before a blind login attempt
NO_NET_DELAY     = 5      # s between checks while there is no network
WIFI_RECOVERY    = os.environ.get("AUTOLOGIN_WIFI_RECOVERY", "1" if CONFIG.get("wifi_recovery") else "0") == "1"
WIFI_RECOVERY_COOLDOWN = 180  # s between attempts to cycle the Wi-Fi radio
NETWORKSETUP = "/usr/sbin/networksetup"
ONLINE_LOG_EVERY = 60     # s: while stably online, write to file at most this often
HEARTBEAT_EVERY  = 600    # s: periodic summary line
USE_SYSTEM_PROXY = False  # False = ignore system/VPN proxy settings for probes
LOCK_PORT        = 47653  # local port used to stop two copies running at once

# Detection endpoints
PRIMARY_URL = "http://connectivitycheck.gstatic.com/generate_204"
APPLE_URL   = "http://captive.apple.com/hotspot-detect.html"
MSFT_URL    = "http://www.msftconnecttest.com/connecttest.txt"
FIREFOX_URL = "http://detectportal.firefox.com/success.txt"
IP_PROBE    = "http://1.1.1.1"
HTTPS_URL   = "https://www.google.com/generate_204"
TCP_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53)]

# Used to find the login page (tried in order)
LOGIN_PROBES = [PRIMARY_URL, APPLE_URL, "http://www.msftconnecttest.com/redirect",
                "http://1.1.1.1", "http://neverssl.com"]
# Campus authentication hosts allowed to receive credentials and used for fallback discovery.
KNOWN_GATEWAYS = ["192.168.92.1", "192.168.96.1", "192.168.100.1", "192.168.108.1"]
PORTAL_ENDPOINTS = [("http", 1000), ("https", 1003)]
# ======================================================

BASE = os.path.expanduser("~/Library/Logs/FortiGateAutoLogin")
LOG_FILE = os.path.join(BASE, "autologin.log")

log = logging.getLogger("autologin")


def setup_logging():
    os.makedirs(BASE, mode=0o700, exist_ok=True)
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.INFO)          # file: important events
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stdout is not None and sys.stdout.isatty():
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)     # console: every single check
        ch.setFormatter(fmt)
        log.addHandler(ch)


S = requests.Session()
S.trust_env = USE_SYSTEM_PROXY
S.headers["User-Agent"] = "FortiGateAutoLogin/1.0"


class Result:
    def __init__(self, name, verdict, detail, secs, portal_url=None):
        self.name, self.verdict, self.detail = name, verdict, detail
        self.secs, self.portal_url = secs, portal_url

    def line(self):
        return f"    {self.name:<14} -> {self.verdict.upper():<7} {self.detail} ({self.secs:.2f}s)"


def short_err(e):
    return f"{type(e).__name__}: {str(e)[:90]}"


# ---------------- portal link extraction ----------------
FGT_LINK = re.compile(
    r"""(?:https?://[^\s"'<>()\\]+?|//[^\s"'<>()\\]+?)?/fgtauth(?:\?[^\s"'<>();\\]*)?"""
    r"""|(?<=["'(=\s])fgtauth\?[^\s"'<>();\\]+""",
    re.I,
)


def web_url(base_url, target):
    try:
        url = urljoin(base_url, target)
        parsed = urlsplit(url)
        if parsed.scheme in ("http", "https") and parsed.hostname and parsed.username is None:
            return url
    except ValueError:
        pass
    return None

def extract_portal_url(base_url, headers, body):
    """Find the fgtauth link in a Location header or inside a redirect stub page
    (meta refresh, JavaScript window.location, plain link). Returns an absolute URL or None."""
    loc = headers.get("Location", "") if headers else ""
    if loc and "fgtauth" in loc.lower():
        return web_url(base_url, loc)
    match = FGT_LINK.search(unescape(body or "").replace("\\/", "/"))
    if match:
        return web_url(base_url, match.group())
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
    purl = r.url if login_form(body) else extract_portal_url(url, r.headers, body)
    if not purl and 300 <= r.status_code < 400 and r.headers.get("Location"):
        target = web_url(r.url, r.headers["Location"])
        if target and campus_portal(target):
            purl = target
    if purl:
        return Result(name, "portal", f"HTTP {r.status_code}, portal redirect/page detected", dt, purl)
    if is_online(r):
        return Result(name, "online", f"HTTP {r.status_code}", dt)
    return Result(name, "other", f"HTTP {r.status_code}, unexpected response", dt)


def m_primary():
    return http_check("gstatic_204", PRIMARY_URL, lambda r: r.status_code == 204)


def m_apple():
    # A captive network can allow this endpoint through. Use it only for discovery.
    return http_check("apple_test", APPLE_URL, lambda r: False)

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
FULL = [m_primary, m_apple, m_msft, m_firefox, m_ip_probe, m_https, m_tcp]


def run_checks(methods, stop_on_portal_url=False):
    out = []
    for m in methods:
        if not on_campus():
            break
        try:
            out.append(m())
        except Exception as e:  # a buggy check must never kill the loop
            out.append(Result(m.__name__, "error", f"check crashed: {short_err(e)}", 0))
        if stop_on_portal_url and out[-1].verdict == "portal" and out[-1].portal_url:
            break
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
def save(name, text):
    try:
        with open(os.path.join(BASE, name), "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        log.warning(f"could not save {name}: {e}")

class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.fields = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.fields = {}
            self.forms.append((attrs.get("action") or "", self.fields))
        elif tag == "input" and self.fields is not None:
            name = attrs.get("name")
            if name and "disabled" not in attrs and (attrs.get("type") or "").lower() == "hidden":
                self.fields[name] = attrs.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.fields = None


def login_form(html):
    parser = LoginFormParser()
    parser.feed(html)
    return next(((action, fields) for action, fields in parser.forms if fields.get("magic")), None)


def campus_portal(url):
    return urlsplit(url).hostname in KNOWN_GATEWAYS

def fetch_login_form(url, timeout=REQ_TIMEOUT):
    """Follow HTTP redirects and FortiGate redirect stubs with a bounded hop count."""
    seen = set()
    for _ in range(5):
        if not on_campus():
            return None
        if not url or url in seen:
            break
        seen.add(url)
        r = S.get(url, timeout=timeout, allow_redirects=False, verify=not campus_portal(url))
        location = r.headers.get("Location")
        if 300 <= r.status_code < 400 and location:
            url = web_url(r.url, location)
            continue
        form = login_form(r.text)
        if form:
            action, fields = form
            post_url = web_url(r.url, action or r.url)
            if post_url and campus_portal(post_url):
                log.info(f"  login form found for campus gateway {urlsplit(post_url).hostname}")
                return post_url, fields
            log.warning("  ignoring login form whose destination is outside KNOWN_GATEWAYS")
        if os.environ.get("AUTOLOGIN_DEBUG") == "1":
            save("probe_response.html", r.text)
        url = extract_portal_url(r.url, r.headers, r.text)
    return None

def find_portal_page(hint_url):
    candidates = ([hint_url] if hint_url else []) + LOGIN_PROBES
    seen = set()
    for u in candidates:
        if not on_campus():
            return None
        if u in seen:
            continue
        seen.add(u)
        try:
            page = fetch_login_form(u)
        except requests.RequestException as e:
            log.info(f"  portal lookup via {urlsplit(u).hostname}: {type(e).__name__}")
            continue
        if page is not None:
            return page
    log.info("  trying known campus gateways directly (last resort)")
    for gw in KNOWN_GATEWAYS:
        for scheme, port in PORTAL_ENDPOINTS:
            for path in ("", "fgtauth"):
                u = f"{scheme}://{gw}:{port}/{path}"
                try:
                    page = fetch_login_form(u, timeout=2)
                except requests.RequestException:
                    break  # skip the other path on this scheme and port
                if page is not None:
                    return page
    return None

def do_login(hint_url):
    """Returns ('ok'|'rejected'|'error', message)."""
    page = find_portal_page(hint_url)
    if page is None:
        return "error", "could not reach a campus portal login form"
    post_url, data = page
    if not on_campus():
        return "error", "college network changed before submission"
    data["username"], data["password"] = USERNAME, PASSWORD
    log.info(f"  submitting login to campus gateway {urlsplit(post_url).hostname}")
    try:
        resp = S.post(post_url, data=data, timeout=5, verify=False, allow_redirects=False)
    except requests.RequestException as e:
        return "error", f"POST failed: {short_err(e)}"
    log.info(f"  portal replied HTTP {resp.status_code}")

    for i in range(1, 5):
        if i > 1:
            time.sleep(0.5)
        if not on_campus():
            return "error", "college network changed during verification"
        results = run_checks([m_primary])
        status = decide(results)[0]
        if status != "ONLINE":
            status = decide(results + run_checks([m_https]))[0]
        log.info(f"  verify {i}/4: status = {status}")
        if status == "ONLINE":
            return "ok", "internet confirmed after login"
    if resp.status_code in (401, 403) or status == "PORTAL":
        return "rejected", "portal still requires authentication after login"
    return "error", f"login response HTTP {resp.status_code}, but internet access could not be verified"


# ---------------- main loop ----------------
def local_command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=3,
                          check=True, env=dict(os.environ, LC_ALL="C")).stdout


def wifi_identity():
    """Read the active Wi-Fi route and its currently resolved router MAC."""
    try:
        route = local_command("/sbin/route", "-n", "get", "default")
        interface = re.search(r"^\s*interface:\s*(en\d+)\s*$", route, re.M)
        gateway = re.search(r"^\s*gateway:\s*([0-9.]+)\s*$", route, re.M)
        if not interface or not gateway:
            return None
        arp = local_command("/usr/sbin/arp", "-n", gateway.group(1))
        match = re.search(r" at ([0-9a-fA-F:]+) on " + re.escape(interface.group(1)) + r"\b", arp)
        if not match:
            return None
        octets = match.group(1).split(":")
        if len(octets) != 6:
            return None
        mac = ":".join(f"{int(part, 16):02x}" for part in octets)
        return {"interface": interface.group(1), "gateway": gateway.group(1), "mac": mac}
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def on_campus():
    return bool(CAMPUS_NETWORKS) and wifi_identity() in CAMPUS_NETWORKS


def networksetup(*args):
    env = dict(os.environ, LC_ALL="C")
    env.pop("AUTOLOGIN_USER", None)
    env.pop("AUTOLOGIN_PASS", None)
    return subprocess.run(
        [NETWORKSETUP, *args], capture_output=True, text=True, timeout=8, check=True, env=env
    ).stdout


def recover_wifi():
    """Cycle an enabled macOS Wi-Fi interface so it can rejoin its saved network."""
    try:
        if not on_campus():
            return False
        ports = networksetup("-listallhardwareports")
        match = re.search(r"^Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: (en\d+)\s*$",
                          ports, re.MULTILINE)
        if not match:
            log.warning("Wi-Fi recovery skipped: no Wi-Fi interface found")
            return False
        device = match.group(1)
        power = networksetup("-getairportpower", device)
        if not power.strip().endswith(": On"):
            log.info("Wi-Fi recovery skipped: Wi-Fi power is off or unavailable")
            return False
        if not on_campus():
            return False
        log.warning("Wi-Fi recovery: cycling %s after consecutive network failures", device)
        try:
            networksetup("-setairportpower", device, "off")
            time.sleep(2)
        finally:
            networksetup("-setairportpower", device, "on")
        S.close()  # discard connections pooled before the interface was restarted
        log.info("Wi-Fi power restored; waiting for macOS to rejoin a saved network")
        return True
    except (OSError, subprocess.SubprocessError) as e:
        detail = getattr(e, "stderr", None) or getattr(e, "stdout", None) or str(e)
        log.warning("Wi-Fi recovery command failed: %s", detail.strip())
        return False


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
    if not CAMPUS_NETWORKS:
        log.critical("No college Wi-Fi enrolled. Run install_autologin.py while on college Wi-Fi.")
        return

    log.info("=" * 60)
    log.info(f"autologin started | user={USERNAME} | python {sys.version.split()[0]} | log={LOG_FILE}")
    log.info(f"interval={CHECK_INTERVAL}s full-check-every={FULL_CHECK_EVERY}s proxy={USE_SYSTEM_PROXY}")
    recover_on_no_network = WIFI_RECOVERY and sys.platform == "darwin"
    if recover_on_no_network:
        log.info("macOS Wi-Fi recovery enabled")

    state = None
    n = logins = 0
    rejections = errors = blind_streak = 0
    next_login_at = 0.0
    next_wifi_recovery_at = 0.0
    offline_since = None
    last_full = last_online_filelog = 0.0
    last_heartbeat = time.time()
    started = time.time()

    while True:
        delay = CHECK_INTERVAL
        try:
            if not on_campus():
                if state != "IDLE":
                    log.info("Idle: active route is outside the enrolled college Wi-Fi networks")
                    S.close()
                    S.cookies.clear()
                state = "IDLE"
                blind_streak = 0
                last_full = 0.0
                time.sleep(10)
                continue
            n += 1
            now = time.time()
            results = run_checks(FAST)
            status, purl, note = decide(results)
            kind = "fast"
            login_ready = time.time() >= next_login_at
            portal_ready = status == "PORTAL" and purl is not None and login_ready
            if not portal_ready and (status != "ONLINE" or now - last_full >= FULL_CHECK_EVERY):
                if status != "ONLINE":
                    log.info(f"CHECK #{n}: fast check says {status}; running full multi-method check...")
                results += run_checks(FULL[1:], stop_on_portal_url=login_ready)
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
                blind_streak = 0
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
                    if (status == "NO_NETWORK" and ready and recover_on_no_network
                            and time.monotonic() >= next_wifi_recovery_at):
                        next_wifi_recovery_at = time.monotonic() + WIFI_RECOVERY_COOLDOWN
                        if recover_wifi():
                            blind_streak = 0
                            time.sleep(NO_NET_DELAY)
                            continue

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
                        wait = min(RETRY_BASE * 2 ** min(errors - 1, 6), RETRY_MAX)
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
