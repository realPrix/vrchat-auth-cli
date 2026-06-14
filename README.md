# vrchat-auth-cli

quick script to grab your VRChat auth cookie and 2FA token. made this because
i got tired of digging through browser dev tools every time the token expires.

## setup

```
pip install requests
```

## usage

just run it and follow the prompts:

```
python3 vrchat_auth.py
```

if you want it to write straight into a `.env` file:

```
python3 vrchat_auth.py --write-env /path/to/.env
```

it'll update `VRCHAT_AUTH_COOKIE` and `VRCHAT_TWO_FACTOR_AUTH` without touching anything else in the file.

## notes

- supports totp (authenticator app), email OTP, and recovery codes
- password is entered with no echo
- the 2FA token expires after 30 days so you'll need to run this again when it does
