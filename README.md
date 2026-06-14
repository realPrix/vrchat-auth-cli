# vrchat-auth-cli

A minimal Python CLI to retrieve your VRChat `auth` cookie and `twoFactorAuth`
JWT via the official VRChat API.  Supports TOTP authenticator apps, email OTP,
and recovery codes.

## Requirements

- Python 3.10+
- `requests`

```bash
pip install requests
```

## Usage

### Print credentials to stdout

```bash
python3 vrchat_auth.py
```

```
========================================================================
  vrchat-auth-cli
========================================================================

  VRChat username or email: you@example.com
  Password:
  Logging in...
  2FA required. Available methods: totp
  Authenticator app code (6 digits): 123456
  Verifying 2FA...
  2FA verified.

========================================================================
  VRChat credentials
========================================================================

  VRCHAT_AUTH_COOKIE=authcookie_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

  VRCHAT_TWO_FACTOR_AUTH=eyJhbGci...

  2FA token expires: 2026-07-14 10:00 UTC  (~30 days)

========================================================================
```

### Write directly to a `.env` file

```bash
python3 vrchat_auth.py --write-env /path/to/.env
```

This upserts `VRCHAT_AUTH_COOKIE` and `VRCHAT_TWO_FACTOR_AUTH` in the target
file without touching any other keys.

## Security

- Credentials are entered via `getpass` (no terminal echo for the password).
- Nothing is sent anywhere except the official VRChat API (`api.vrchat.cloud`).
- Tokens are printed to stdout only; they are never stored unless you use
  `--write-env`.

## Token lifetime

| Token | Lifetime |
|---|---|
| `auth` cookie | Until you log out or VRChat expires the session |
| `twoFactorAuth` JWT | 30 days |

Run the script again when the 2FA token approaches expiry.

## License

MIT
