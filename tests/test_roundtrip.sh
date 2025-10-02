set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/cryptocore"
if [ ! -x "$BIN" ]; then
  echo "cryptocore binary not found. Build first: make"
  exit 1
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

PLAINTXT="$TMPDIR/plain.bin"
ENCRYPTED="$TMPDIR/ct.bin"
DECRYPTED="$TMPDIR/pt2.bin"
OPENSSL_CT="$TMPDIR/openssl_ct.bin"

echo "Hello, CryptoCore test!" > "$PLAINTXT"
KEY="000102030405060708090a0b0c0d0e0f"

"$BIN" --algorithm aes --mode ecb --encrypt --key "$KEY" --input "$PLAINTXT" --output "$ENCRYPTED"

"$BIN" --algorithm aes --mode ecb --decrypt --key "$KEY" --input "$ENCRYPTED" --output "$DECRYPTED"

if cmp -s "$PLAINTXT" "$DECRYPTED"; then
  echo "Roundtrip OK"
else
  echo "Roundtrip FAILED"
  exit 2
fi


openssl enc -aes-128-ecb -nosalt -K "$KEY" -in "$PLAINTXT" -out "$OPENSSL_CT"

if cmp -s "$ENCRYPTED" "$OPENSSL_CT"; then
  echo "Ciphertext matches OpenSSL"
else
  echo "Ciphertext differs from OpenSSL output"
  echo "You can inspect $ENCRYPTED and $OPENSSL_CT"
  exit 3
fi

echo "All checks passed."
