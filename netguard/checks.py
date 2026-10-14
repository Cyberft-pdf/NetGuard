"""The home-network checks.

Every check returns a Result written for people who are not security experts:
a short summary of what we found and, when needed, what to do about it.
Checks only look - they never change settings and never try to log in to anything.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

GOOD, WARN, BAD, INFO = "good", "warning", "bad", "info"
IS_WINDOWS = sys.platform == "win32"
DATA_DIR = Path.home() / ".netguard"


@dataclass
class Result:
    status: str
    summary: str
    advice: str = ""
    details: list[str] = field(default_factory=list)
    id: str = ""
    title: str = ""


# ---------------------------------------------------------------- helpers

def _run(cmd: list[str], timeout: float = 20) -> str | None:
    flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: no console flashing
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout


def _powershell(script: str, timeout: float = 30) -> list | None:
    """Run a PowerShell snippet and return its output parsed from JSON, always as a list.

    PowerShell objects are used instead of netsh/netstat text because that text is
    translated into the Windows display language, while object properties are not.
    """
    if not IS_WINDOWS:
        return None
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                f"{script} | ConvertTo-Json -Compress -Depth 3"], timeout)
    if out is None:
        return None
    if not out.strip():
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return None
    return data if isinstance(data, list) else [data]


def _port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def local_ip() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))  # UDP connect sends nothing; it just picks the route
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_gateway() -> str | None:
    if IS_WINDOWS:
        rows = _powershell("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue"
                           " | Sort-Object RouteMetric | Select-Object -ExpandProperty NextHop")
        candidates = rows or []
    else:
        out = (_run(["ip", "route", "show", "default"]) or "") + (_run(["route", "-n", "get", "default"]) or "")
        candidates = re.findall(r"(?:default via|gateway:)\s+(\d+\.\d+\.\d+\.\d+)", out)
    for hop in candidates:
        if isinstance(hop, str) and hop != "0.0.0.0":
            return hop
    return None


# ---------------------------------------------------------------- parsers (pure, unit tested)

_WIFI_AUTH_RE = re.compile(r"(WPA3|WPA2|WPA|WEP)(-[\w-]+)?", re.IGNORECASE)


def parse_wifi(netsh_output: str) -> tuple[str | None, str | None]:
    """Parse `netsh wlan show interfaces`.

    Returns (network name, security) where security is "wpa3", "wpa2", "wpa", "wep" or "open",
    or (None, None) when not connected to Wi-Fi. Matches on values, not labels, because the
    labels are translated into the Windows display language.
    """
    ssid, security = None, None
    for line in netsh_output.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "SSID":
            ssid = value
        elif security is None and (m := _WIFI_AUTH_RE.fullmatch(value)):
            security = m.group(1).lower()
    if ssid is None:
        return None, None
    return ssid, security or "open"


_ARP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


def parse_arp(output: str, network: ipaddress.IPv4Network) -> dict[str, str]:
    """Parse `arp -a` (Windows, Linux or macOS) into {MAC: IP} for real devices on `network`."""
    devices = {}
    for line in output.splitlines():
        m = _ARP_RE.search(line)
        if not m:
            continue
        ip = ipaddress.ip_address(m.group(1))
        mac = ":".join(part.zfill(2) for part in re.split(r"[:-]", m.group(2))).upper()
        multicast = int(mac[:2], 16) & 1  # also covers FF:FF:FF:FF:FF:FF broadcast
        if (multicast or mac == "00:00:00:00:00:00" or ip not in network
                or ip in (network.network_address, network.broadcast_address)):
            continue
        devices[mac] = str(ip)
    return devices


def decode_av_state(product_state: int) -> tuple[bool, bool]:
    """Decode Windows Security Center productState into (turned on, up to date)."""
    return (product_state >> 12) & 0xF == 1, (product_state >> 4) & 0xF == 0


def overall_status(results: list[Result]) -> str:
    statuses = {r.status for r in results}
    for status in (BAD, WARN):
        if status in statuses:
            return status
    return GOOD


# ---------------------------------------------------------------- the checks

CHECKS = []


def check(check_id: str, title: str):
    def register(fn):
        CHECKS.append((check_id, title, fn))
        return fn
    return register


@check("internet", "Internet connection")
def check_internet(ctx) -> Result:
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        return Result(BAD, "Your computer can't look up website names, so the internet won't work properly.",
                      "Restart your router (unplug it for 30 seconds). If that doesn't help, call your internet provider.")
    if not _port_open("1.1.1.1", 443, timeout=3):
        return Result(WARN, "Website names work, but we couldn't reach the internet directly.",
                      "If websites open normally you can ignore this.")
    return Result(GOOD, "You're connected to the internet.")


@check("wifi", "Wi-Fi security")
def check_wifi(ctx) -> Result:
    if not IS_WINDOWS:
        return Result(INFO, "This check is only available on Windows.")
    ssid, security = parse_wifi(_run(["netsh", "wlan", "show", "interfaces"]) or "")
    if ssid is None:
        return Result(INFO, "This computer is connected by cable, not Wi-Fi, so we can't see your Wi-Fi settings.",
                      "Run NetGuard on a laptop connected to your Wi-Fi to check it.")
    name = f"Your Wi-Fi “{ssid}”"
    if security == "wpa3":
        return Result(GOOD, f"{name} uses WPA3, the newest and strongest Wi-Fi protection.")
    if security == "wpa2":
        return Result(GOOD, f"{name} uses WPA2 protection, which is good.",
                      "If your router offers “WPA2/WPA3” or “WPA3”, switching to it makes it even stronger. "
                      "Make sure the Wi-Fi password is at least 12 characters long.")
    if security in ("wep", "wpa"):
        return Result(BAD, f"{name} uses old protection ({security.upper()}) that can be broken in minutes.",
                      "Open your router settings, set Wi-Fi security to “WPA2” or “WPA3” and choose a new long password.")
    return Result(BAD, f"{name} appears to have no password. Anyone nearby can join it and see what you do.",
                  "Open your router settings, turn on “WPA2” or “WPA3” security and set a long password.")


@check("router", "Router settings")
def check_router(ctx) -> Result:
    gw = ctx["gateway"]
    if not gw:
        return Result(INFO, "We couldn't find your router.")
    ports = {p: _port_open(gw, p) for p in (21, 23, 80, 443, 8080)}
    details = [f"Your router's address is {gw}."]
    if ports[80] or ports[8080] or ports[443]:
        scheme = "https" if ports[443] else "http"
        details.append(f"Its settings page is probably at {scheme}://{gw}")
    if ports[23]:
        return Result(BAD, "Your router accepts Telnet, an old remote-control method that sends passwords without protection.",
                      "Turn off Telnet in the router settings and install the latest router update (firmware). "
                      "If you can't, ask your internet provider for a newer router.", details)
    if ports[21]:
        return Result(WARN, "Your router has FTP file sharing turned on (often used for a USB drive plugged into the router).",
                      "If you don't share files from a USB drive on the router, turn FTP off in the router settings.", details)
    return Result(GOOD, "Your router doesn't offer any risky old services to your home network.",
                  "Make sure you changed the router's admin password from the one printed on its sticker.", details)


@check("upnp", "Automatic port opening (UPnP)")
def check_upnp(ctx) -> Result:
    gw, me = ctx["gateway"], ctx["local_ip"]
    if not gw or not me:
        return Result(INFO, "We couldn't find your router.")
    message = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
               "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_header = None
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
        sock.settimeout(0.5)
        sock.sendto(message, ("239.255.255.250", 1900))
        sock.sendto(message, (gw, 1900))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and server_header is None:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if addr[0] == gw:
                m = re.search(r"^SERVER:\s*(.+)$", data.decode(errors="replace"), re.IGNORECASE | re.MULTILINE)
                server_header = m.group(1).strip() if m else ""
    except OSError:
        pass
    finally:
        sock.close()
    if server_header is None:
        return Result(GOOD, "Your router doesn't let devices open doors to the internet by themselves.")
    details = [f"Router reports: {server_header}"] if server_header else []
    return Result(WARN, "UPnP is turned on. It lets apps and gadgets open doors in your router to the internet "
                        "without asking you. Game consoles like it, but malware can misuse it too.",
                  "If nobody at home plays online games or has trouble with video calls, turn off “UPnP” in your router settings.",
                  details)


@check("devices", "Devices on your network")
def check_devices(ctx) -> Result:
    me = ctx["local_ip"]
    if not me:
        return Result(INFO, "We couldn't find your home network.")
    network = ipaddress.ip_network(f"{me}/24", strict=False)
    # A tiny packet to every address makes the computer learn which devices exist (fills the ARP table).
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(2):
        for host in network.hosts():
            try:
                sock.sendto(b"", (str(host), 9))
            except OSError:
                pass
        time.sleep(1.5)
    sock.close()
    found = parse_arp(_run(["arp", "-a"]) or "", network)

    with ThreadPoolExecutor(max_workers=32) as pool:
        lookups = {mac: pool.submit(socket.gethostbyaddr, ip) for mac, ip in found.items()}
        wait(lookups.values(), timeout=5)
    names = {mac: f.result()[0] for mac, f in lookups.items() if f.done() and not f.exception()}

    known_file = DATA_DIR / "devices.json"
    try:
        known = json.loads(known_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        known = None
    first_scan = known is None
    known = known or {}
    new = [mac for mac in found if mac not in known]
    for mac in found:
        known.setdefault(mac, {"first_seen": date.today().isoformat()})
        if mac in names:
            known[mac]["name"] = names[mac]
    try:
        DATA_DIR.mkdir(exist_ok=True)
        known_file.write_text(json.dumps(known, indent=2), encoding="utf-8")
    except OSError:
        pass

    def describe(mac):
        label = names.get(mac) or known.get(mac, {}).get("name") or "unnamed device"
        tags = [" (this computer)" if found[mac] == me else "", " (router)" if found[mac] == ctx["gateway"] else "",
                " — NEW" if mac in new and not first_scan else ""]
        return f"{found[mac]}  {label}  [{mac}]{''.join(tags)}"

    details = [describe(mac) for mac in sorted(found, key=lambda m: ipaddress.ip_address(found[m]))]
    count = len(found) + (0 if me in found.values() else 1)  # this computer is never in its own ARP table
    if first_scan:
        return Result(INFO, f"We found {count} devices. We'll remember them and tell you when a new one appears.",
                      "Look through the list. Phones, TVs, speakers and smart plugs all count as devices.", details)
    if new:
        return Result(WARN, f"{len(new)} new device(s) joined since your last check ({count} in total).",
                      "If you don't recognise a new device, change your Wi-Fi password so only people you trust can join.",
                      details)
    return Result(GOOD, f"We found {count} devices and none of them are new.", "", details)


@check("firewall", "Firewall on this computer")
def check_firewall(ctx) -> Result:
    rows = _powershell("Get-NetFirewallProfile | Select-Object Name, @{n='On';e={[string]$_.Enabled}}")
    if not rows:
        return Result(INFO, "This check is only available on Windows." if not IS_WINDOWS else "We couldn't read the firewall settings.")
    off = [r["Name"] for r in rows if r.get("On") != "True"]
    if off:
        return Result(BAD, f"The Windows firewall is turned off for: {', '.join(off)}.",
                      "Open Start → “Windows Security” → “Firewall & network protection” and turn it on for every network type.")
    return Result(GOOD, "The Windows firewall is turned on.")


@check("antivirus", "Virus protection")
def check_antivirus(ctx) -> Result:
    rows = _powershell("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop"
                       " | Select-Object displayName, productState")
    if not rows:
        return Result(INFO, "This check is only available on Windows." if not IS_WINDOWS else "We couldn't read the virus protection status.")
    products = [(r["displayName"], *decode_av_state(int(r["productState"]))) for r in rows]
    active = [p for p in products if p[1]]
    details = [f"{name}: {'on' if on else 'off'}, {'up to date' if fresh else 'OUT OF DATE'}" for name, on, fresh in products]
    if not active:
        return Result(BAD, "No virus protection is turned on.",
                      "Open Start → “Windows Security” → “Virus & threat protection” and turn it on.", details)
    if not any(fresh for _, _, fresh in active):
        return Result(WARN, f"{active[0][0]} is on but out of date.",
                      "Open your antivirus and click “Check for updates”.", details)
    return Result(GOOD, f"{active[0][0]} is on and up to date.", "", details)


@check("updates", "Windows updates")
def check_updates(ctx) -> Result:
    rows = _powershell(
        "@((Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn,"
        " (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate)"
        " | Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToString('yyyy-MM-dd') }", timeout=45)
    dates = [date.fromisoformat(d) for d in rows or [] if isinstance(d, str) and d > "2000"]
    if not dates:
        return Result(INFO, "This check is only available on Windows." if not IS_WINDOWS else "We couldn't tell when Windows was last updated.")
    days = (date.today() - max(dates)).days
    fix = "Open Start → “Settings” → “Windows Update”, click “Check for updates” and restart when asked."
    if days > 90:
        return Result(BAD, f"Windows hasn't installed updates for {days} days. Updates fix security holes.", fix)
    if days > 45:
        return Result(WARN, f"Windows was last updated {days} days ago.", fix)
    when = "today" if days == 0 else "yesterday" if days == 1 else f"{days} days ago"
    return Result(GOOD, f"Windows was updated recently ({when}).")


RISKY_LISTENERS = {3389: "Remote Desktop", 5900: "VNC remote control", 5800: "VNC remote control",
                   23: "Telnet", 21: "FTP file sharing"}


@check("remote", "Remote access to this computer")
def check_remote(ctx) -> Result:
    rows = _powershell("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort")
    if rows is None:
        return Result(INFO, "This check is only available on Windows." if not IS_WINDOWS else "We couldn't check this.")
    found = sorted({RISKY_LISTENERS[r["LocalPort"]] for r in rows
                    if r.get("LocalPort") in RISKY_LISTENERS and r.get("LocalAddress") not in ("127.0.0.1", "::1")})
    if found:
        return Result(WARN, f"Other devices can try to control this computer remotely ({', '.join(found)}).",
                      "If you don't use this, turn it off. For Remote Desktop: Start → “Settings” → “System” → “Remote Desktop” → Off.")
    return Result(GOOD, "Nobody can control this computer remotely.")


def run_all_checks() -> dict:
    ctx = {"local_ip": local_ip(), "gateway": default_gateway()}
    results = []
    with ThreadPoolExecutor(max_workers=len(CHECKS)) as pool:
        futures = [(cid, title, pool.submit(fn, ctx)) for cid, title, fn in CHECKS]
        for cid, title, future in futures:
            try:
                result = future.result()
            except Exception:  # one broken check must never break the whole report
                result = Result(INFO, "Something went wrong while running this check.")
            result.id, result.title = cid, title
            results.append(result)
    return {"overall": overall_status(results), "network": ctx, "results": [asdict(r) for r in results]}
