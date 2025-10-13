set -euo pipefail
BIN="./cryptocore"
TMPDIR=$(mktemp -d)
KEYFILE="$TMPDIR/key.hex"
PLAIN="$TMPDIR/plain.txt"
CT="$TMPDIR/cipher.bin"
PT="$TMPDIR/decrypted.txt"

echo "Hello CryptoCore CSPRNG test" > "$PLAIN"

OUT=$($BIN --algorithm aes --mode cbc --encrypt --input "$PLAIN" --output "$CT" 2>&1)
echo "$OUT"
KEY_HEX=$(printf "%s\n" "$OUT" | sed -n 's/.*Generated random key: //p' | tr -d '[:space:]' | tail -n1)

if [ -z "$KEY_HEX" ]; then
  echo "Failed to capture generated key. Output was:"
  echo "$OUT"
  exit 2
fi

echo "Captured key: $KEY_HEX"

$BIN --algorithm aes --mode cbc --decrypt --key @"$KEY_HEX" --input "$CT" --output "$PT"

if diff -q "$PLAIN" "$PT" >/dev/null 2>&1; then
  echo "[PASS] CSPRNG roundtrip OK"
  exit 0
else
  echo "[FAIL] Decrypted output differs"
  diff "$PLAIN" "$PT" || true
  exit 3
fi
