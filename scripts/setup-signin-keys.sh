#!/usr/bin/env bash
# Makes the three sign-in keys and puts them straight into Vercel (Production only). Run it on your own computer,
# from this repository's folder. The keys go from your computer to Vercel without being shown, saved to a file or
# sent anywhere else, so nobody (Claude included) ever sees them.
#
# Before running:   npx vercel@62.0.0 login        (sign in to Vercel in your browser)
#                   npx vercel@62.0.0 link         (choose the chief-os team and the start-of-something-great project)
# Then run:         bash scripts/setup-signin-keys.sh
#
# It refuses to replace a key that already exists. FINGERPRINT_KEY_1 in particular must never be replaced or deleted:
# members are recognised by it. Rotating means adding FINGERPRINT_KEY_2 alongside it (db/README.md, "Sign-in").
# Each key is stored as a Vercel secret ("sensitive"), which nobody can read back, not even Aaron.
set -euo pipefail

VERCEL="npx --yes vercel@62.0.0"
command -v openssl >/dev/null || { echo "openssl is needed (it comes with macOS and most Linux)"; exit 1; }

existing="$($VERCEL env ls production 2>/dev/null || true)"
add() {
  local name="$1" value="$2"
  if grep -qw "$name" <<<"$existing"; then
    echo "skipped $name: it already exists in Production"
    return
  fi
  # From standard input, so the value never appears in a command line or process list.
  printf '%s' "$value" | $VERCEL env add "$name" production --sensitive --yes >/dev/null
  echo "added $name to Production"
}

add SESSION_SECRET "$(openssl rand -base64 32)"
add IP_HASH_KEY "$(openssl rand -base64 32)"
add FINGERPRINT_KEY_1 "$(openssl rand -base64 32)"

echo
echo "Done. Nothing was printed or saved on this computer. Vercel keeps the keys encrypted; preview deployments don't get them."
echo "Sign-in stays off until the database, GitHub or X settings are added too (SIGNIN-SETUP.md)."
