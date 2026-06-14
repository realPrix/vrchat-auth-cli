#!/usr/bin/env python3
import argparse
import base64
import getpass
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

VRCHAT_API = "https://api.vrchat.cloud/api/1"
USER_AGENT = "Mozilla/5.0 vrchat-auth-cli"


def _headers(cookies=None):
    h = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return h


def _get_cookie(resp, name):
    val = resp.cookies.get(name)
    if val:
        return val
    raw = resp.headers.get("Set-Cookie", "")
    m = re.search(rf"{re.escape(name)}=([^;]+)", raw)
    return m.group(1) if m else None


def _jwt_expiry(token):
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    except Exception:
        return None


def do_login(username, password):
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        resp = requests.get(
            f"{VRCHAT_API}/auth/user",
            headers={**_headers(), "Authorization": f"Basic {creds}"},
            timeout=15,
        )
    except requests.RequestException as e:
        print(f"network error: {e}", file=sys.stderr)
        return None, None

    if resp.status_code == 401:
        print("wrong username or password", file=sys.stderr)
        return None, None
    if resp.status_code != 200:
        print(f"got {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return None, None

    auth = _get_cookie(resp, "auth")
    if not auth:
        print("no auth cookie in response", file=sys.stderr)
        return None, None
    return auth, resp.json()


def verify_2fa(auth_cookie, code, method):
    resp = requests.post(
        f"{VRCHAT_API}/auth/twofactorauth/{method}/verify",
        headers=_headers({"auth": auth_cookie}),
        json={"code": code.strip()},
        timeout=15,
    )
    if resp.status_code != 200:
        body = resp.json() if resp.content else {}
        msg = body.get("error", {}).get("message", resp.text[:200])
        print(f"2FA failed: {msg}", file=sys.stderr)
        return None
    return _get_cookie(resp, "twoFactorAuth") or ""


def login():
    print()
    username = input("username or email: ").strip()
    password = getpass.getpass("password: ")

    print("logging in...")
    auth, data = do_login(username, password)
    if not auth:
        return None, None

    methods = data.get("requiresTwoFactorAuth", [])
    if not methods:
        print("done (no 2FA)")
        return auth, None

    if "totp" in methods:
        method, prompt = "totp", "authenticator code: "
    elif "emailotp" in methods:
        method, prompt = "emailotp", "email OTP: "
    elif "otp" in methods:
        method, prompt = "otp", "recovery code: "
    else:
        print(f"unknown 2FA method: {methods}", file=sys.stderr)
        return None, None

    code = input(prompt).strip()
    tfa = verify_2fa(auth, code, method)
    if tfa is None:
        return None, None

    print("done")
    return auth, tfa


def write_env(path, auth, tfa):
    p = Path(path)
    lines = p.read_text().splitlines(keepends=True) if p.exists() else []

    def upsert(key, value):
        pattern = re.compile(rf"^{re.escape(key)}\s*=")
        nonlocal lines
        new_lines = []
        replaced = False
        for line in lines:
            if pattern.match(line):
                new_lines.append(f"{key}={value}\n")
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            new_lines.append(f"{key}={value}\n")
        lines[:] = new_lines

    upsert("VRCHAT_AUTH_COOKIE", auth)
    if tfa is not None:
        upsert("VRCHAT_TWO_FACTOR_AUTH", tfa)

    p.write_text("".join(lines))
    print(f"written to {p}")


def print_results(auth, tfa):
    print(f"\nVRCHAT_AUTH_COOKIE={auth}")
    if tfa:
        print(f"\nVRCHAT_TWO_FACTOR_AUTH={tfa}")
        exp = _jwt_expiry(tfa)
        if exp:
            print(f"\nexpires: {exp.strftime('%Y-%m-%d %H:%M UTC')}")
    print()


def main():
    parser = argparse.ArgumentParser(description="get vrchat auth tokens")
    parser.add_argument("--write-env", metavar="FILE", help="write tokens into a .env file")
    args = parser.parse_args()

    auth, tfa = login()
    if not auth:
        sys.exit(1)

    print_results(auth, tfa)

    if args.write_env:
        write_env(args.write_env, auth, tfa)


if __name__ == "__main__":
    main()
