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

echo "CTR roundtrip test at $(date)" > "$PLAINTXT"
head -c 100 /dev/urandom > "$PLAINTXT"

echo "1) Encrypt with cryptocore (CTR)"
$BIN --algorithm aes --mode ctr --encrypt --key @"$KEY" --input "$PLAINTXT" --output "$CT"

echo "2) Decrypt with cryptocore (auto IV)"
$BIN --algorithm aes --mode ctr --decrypt --key @"$KEY" --input "$CT" --output "$PT"

cmp -s "$PLAINTXT" "$PT" && echo "[PASS] cryptocore CTR roundtrip" || { echo "[FAIL] cryptocore CTR roundtrip"; exit 2; }

echo "3) Interop: cryptocore -> OpenSSL"
dd if="$CT" of="$IV" bs=16 count=1 status=none
dd if="$CT" of="$CT_ONLY" bs=16 skip=1 status=none
IVHEX=$(xxd -p "$IV" | tr -d '\n')
openssl enc -aes-128-ctr -d -K $KEY -iv $IVHEX -in "$CT_ONLY" -out "$OPENSSL_PT" -nosalt
cmp -s "$PLAINTXT" "$OPENSSL_PT" && echo "[PASS] cryptocore->OpenSSL CTR interop" || { echo "[FAIL] cryptocore->OpenSSL CTR interop"; exit 3; }

echo "4) Interop: OpenSSL -> cryptocore"
IV2HEX="0102030405060708090a0b0c0d0e0f10"
openssl enc -aes-128-ctr -K $KEY -iv $IV2HEX -in "$PLAINTXT" -out "$TMP/openssl_ct.bin" -nosalt
$BIN --algorithm aes --mode ctr --decrypt --key @"$KEY" --iv $IV2HEX --input "$TMP/openssl_ct.bin" --output "$TMP/our_decrypted.txt"
cmp -s "$PLAINTXT" "$TMP/our_decrypted.txt" && echo "[PASS] OpenSSL->cryptocore CTR interop" || { echo "[FAIL] OpenSSL->cryptocore CTR interop"; exit 4; }

echo "[OK] CTR tests passed."
