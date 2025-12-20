set -euo pipefail

BIN="./cryptocore"
if [ ! -x "$BIN" ]; then
  echo "cryptocore binary not found. Build first: make"
  exit 1
fi

TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

PLAINTXT="$TMP/plain.txt"
CT="$TMP/cipher.bin"
CT_ONLY="$TMP/cipher_only.bin"
IV="$TMP/iv.bin"
PT="$TMP/decrypted.txt"
OPENSSL_PT="$TMP/openssl_plain.txt"
KEY="000102030405060708090a0b0c0d0e0f"

echo "CBC roundtrip test at $(date)" > "$PLAINTXT"
for i in {1..8}; do echo "line $i - CBC test" >> "$PLAINTXT"; done

echo "1) Encrypt with cryptocore (CBC)"
$BIN --algorithm aes --mode cbc --encrypt --key @"$KEY" --input "$PLAINTXT" --output "$CT"

echo "2) Decrypt with cryptocore (auto IV from file)"
$BIN --algorithm aes --mode cbc --decrypt --key @"$KEY" --input "$CT" --output "$PT"

cmp -s "$PLAINTXT" "$PT" && echo "[PASS] cryptocore CBC roundtrip" || { echo "[FAIL] cryptocore CBC roundtrip"; exit 2; }

echo "3) Interop: cryptocore -> OpenSSL"
dd if="$CT" of="$IV" bs=16 count=1 status=none
dd if="$CT" of="$CT_ONLY" bs=16 skip=1 status=none
IVHEX=$(xxd -p "$IV" | tr -d '\n')
openssl enc -aes-128-cbc -d -K $KEY -iv $IVHEX -in "$CT_ONLY" -out "$OPENSSL_PT" -nosalt
cmp -s "$PLAINTXT" "$OPENSSL_PT" && echo "[PASS] cryptocore->OpenSSL CBC interop" || { echo "[FAIL] cryptocore->OpenSSL CBC interop"; exit 3; }

echo "4) Interop: OpenSSL -> cryptocore"
IV2HEX="aabbccddeeff00112233445566778899"
openssl enc -aes-128-cbc -K $KEY -iv $IV2HEX -in "$PLAINTXT" -out "$TMP/openssl_ct.bin" -nosalt
$BIN --algorithm aes --mode cbc --decrypt --key @"$KEY" --iv $IV2HEX --input "$TMP/openssl_ct.bin" --output "$TMP/our_decrypted.txt"
cmp -s "$PLAINTXT" "$TMP/our_decrypted.txt" && echo "[PASS] OpenSSL->cryptocore CBC interop" || { echo "[FAIL] OpenSSL->cryptocore CBC interop"; exit 4; }

echo "[OK] CBC tests passed."
