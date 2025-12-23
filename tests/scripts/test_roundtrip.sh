set -e

if [ ! -x "./cryptocore" ]; then
  echo "cryptocore binary not found. Build first: make"
  exit 1
fi

TMP=$(mktemp -d)
echo "[INFO] Temporary test dir: $TMP"

echo "Hello CryptoCore! Testing AES roundtrip." > "$TMP/plain.txt"

KEY="000102030405060708090a0b0c0d0e0f"

./cryptocore --algorithm aes --mode ecb --encrypt --key "$KEY" \
  --input "$TMP/plain.txt" --output "$TMP/cipher.bin"

./cryptocore --algorithm aes --mode ecb --decrypt --key "$KEY" \
  --input "$TMP/cipher.bin" --output "$TMP/decrypted.txt"


if cmp -s "$TMP/plain.txt" "$TMP/decrypted.txt"; then
  echo "[PASS] ECB roundtrip OK"
else
  echo "[FAIL] ECB roundtrip mismatch"
  diff "$TMP/plain.txt" "$TMP/decrypted.txt"
  exit 1
fi

echo "[INFO] All ECB tests passed."
