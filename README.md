# NetGuard

A simple safety check for your home network, made for people who aren't security experts.
Click one button and NetGuard tells you, in plain language, what's fine and what to fix.

NetGuard only **looks**. It never changes settings and never tries to log in to anything.

## How to use it

1. Install [Python](https://www.python.org/downloads/) (3.10 or newer). Nothing else is needed.
2. Double-click **`NetGuard.bat`** (or run `python -m netguard`).
3. Your browser opens. Click **Check my network**.

## What it checks

| Check | What it means |
|---|---|
| Internet connection | Can this computer reach the internet? |
| Wi-Fi security | Is your Wi-Fi protected with WPA2/WPA3, or old/no protection? |
| Router settings | Does the router run risky old services (Telnet, FTP)? |
| UPnP | Can devices open doors in your router without asking? |
| Devices on your network | Lists every device and warns when a **new** one appears |
| Firewall | Is the Windows firewall on? |
| Virus protection | Is antivirus on and up to date? |
| Windows updates | When was Windows last updated? |
| Remote access | Can other devices remotely control this computer? |

There's also a short checklist of things only you can check, like the router password.

Known devices are remembered in `~/.netguard/devices.json`.
The Wi-Fi, firewall, antivirus, updates and remote-access checks work on Windows only.

## For developers

```
python -m unittest
```
