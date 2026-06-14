#!/usr/bin/env python3
"""
vrchat-auth-cli
---------------
Interactive CLI to log into the VRChat API and retrieve your auth cookie
and 2FA token.  Supports TOTP, email OTP, and recovery codes.

Usage:
    python3 vrchat_auth.py                         # print tokens to stdout
    python3 vrchat_auth.py --write-env .env        # write / update a .env file
    python3 vrchat_auth.py --help
"""

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
USER_AGENT = "vrchat-auth-cli/1.0 (github.com/realPrix/vrchat-auth-cli)"


# ── helpers ────────────────────────────────────────────────────────────────────

def _headers(cookies: dict | None = None) -> dict:
    h = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return h


def _cookie_from_response(resp: requests.Response, name: str) -> str | None:
    val = resp.cookies.get(name)
    if val:
        return val
    raw = resp.headers.get("Set-Cookie", "")
    m = re.search(rf"{re.escape(name)}=([^;]+)", raw)
    return m.group(1) if m else None


def _decode_jwt_exp(token: str) -> datetime | None:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    except Exception:
        return None


# ── VRChat auth flow ────────────────────────────────────────────────────────────

def step1_login(username: str, password: str) -> tuple[str | None, dict | None]:
    """Basic-auth login. Returns (auth_cookie, response_body)."""
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    try:
        resp = requests.get(
            f"{VRCHAT_API}/auth/user",
            headers={**_headers(), "Authorization": f"Basic {creds}"},
            timeout=15,
        )
    except requests.RequestException as exc:
        print(f"  Network error: {exc}", file=sys.stderr)
        return None, None

    if resp.status_code == 401:
        print("  Wrong username or password.", file=sys.stderr)
        return None, None
    if resp.status_code != 200:
        print(f"  Unexpected response {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return None, None

    auth = _cookie_from_response(resp, "auth")
    if not auth:
        print("  No auth cookie in response.", file=sys.stderr)
        return None, None
    return auth, resp.json()


def step2_verify_2fa(auth_cookie: str, code: str, method: str) -> str | None:
    """Verify MFA code. Returns twoFactorAuth cookie on success."""
    resp = requests.post(
        f"{VRCHAT_API}/auth/twofactorauth/{method}/verify",
        headers=_headers({"auth": auth_cookie}),
        json={"code": code.strip()},
        timeout=15,
    )
    if resp.status_code != 200:
        body = resp.json() if resp.content else {}
        msg = body.get("error", {}).get("message", resp.text[:200])
        print(f"  2FA failed ({resp.status_code}): {msg}", file=sys.stderr)
        return None
    tfa = _cookie_from_response(resp, "twoFactorAuth")
    return tfa or ""


def interactive_login() -> tuple[str | None, str | None]:
    """Walk the user through login + 2FA. Returns (auth_cookie, twofa_cookie)."""
    print()
    username = input("  VRChat username or email: ").strip()
    password = getpass.getpass("  Password: ")

    print("  Logging in...")
    auth, data = step1_login(username, password)
    if not auth:
        return None, None

    methods = data.get("requiresTwoFactorAuth", [])
    if not methods:
        print("  Logged in (no 2FA on this account).")
        return auth, None

    print(f"  2FA required. Available methods: {', '.join(methods)}")

    if "totp" in methods:
        method, prompt = "totp", "  Authenticator app code (6 digits): "
    elif "emailotp" in methods:
        method, prompt = "emailotp", "  Email OTP (check your inbox): "
    elif "otp" in methods:
        method, prompt = "otp", "  Recovery code: "
    else:
        print(f"  Unknown 2FA method(s): {methods}", file=sys.stderr)
        return None, None

    code = input(prompt).strip()
    print("  Verifying 2FA...")
    tfa = step2_verify_2fa(auth, code, method)
    if tfa is None:
        return None, None

    print("  2FA verified.")
    return auth, tfa


# ── .env writer ─────────────────────────────────────────────────────────────────

def write_env(path: str, auth: str, tfa: str | None) -> None:
    p = Path(path)
    lines = p.read_text().splitlines(keepends=True) if p.exists() else []

    def upsert(key: str, value: str) -> None:
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
    print(f"  Written to {p}")


# ── output ───────────────────────────────────────────────────────────────────────

def print_results(auth: str, tfa: str | None) -> None:
    width = 72
    print()
    print("=" * width)
    print("  VRChat credentials")
    print("=" * width)
    print(f"\n  VRCHAT_AUTH_COOKIE={auth}")
    if tfa:
        print(f"\n  VRCHAT_TWO_FACTOR_AUTH={tfa}")
        exp = _decode_jwt_exp(tfa)
        if exp:
            print(f"\n  2FA token expires: {exp.strftime('%Y-%m-%d %H:%M UTC')}  (~30 days)")
    else:
        print("\n  (no 2FA token — account has no 2FA)")
    print()
    print("=" * width)
    print()


# ── main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vrchat-auth",
        description="Retrieve VRChat auth cookies via the official API.",
    )
    parser.add_argument(
        "--write-env",
        metavar="FILE",
        help="Write / update VRCHAT_AUTH_COOKIE and VRCHAT_TWO_FACTOR_AUTH in FILE",
    )
    args = parser.parse_args()

    print("=" * 72)
    print("  vrchat-auth-cli")
    print("=" * 72)

    auth, tfa = interactive_login()
    if not auth:
        print("\nAuthentication failed.", file=sys.stderr)
        sys.exit(1)

    print_results(auth, tfa)

    if args.write_env:
        write_env(args.write_env, auth, tfa)


if __name__ == "__main__":
    main()
