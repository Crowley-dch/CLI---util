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

echo "OFB roundtrip test at $(date)" > "$PLAINTXT"
for i in {1..8}; do echo "line $i - OFB test" >> "$PLAINTXT"; done

echo "1) Encrypt with cryptocore (OFB)"
$BIN --algorithm aes --mode ofb --encrypt --key @"$KEY" --input "$PLAINTXT" --output "$CT"

echo "2) Decrypt with cryptocore (auto IV)"
$BIN --algorithm aes --mode ofb --decrypt --key @"$KEY" --input "$CT" --output "$PT"

cmp -s "$PLAINTXT" "$PT" && echo "[PASS] cryptocore OFB roundtrip" || { echo "[FAIL] cryptocore OFB roundtrip"; exit 2; }

echo "3) Interop: cryptocore -> OpenSSL"
dd if="$CT" of="$IV" bs=16 count=1 status=none
dd if="$CT" of="$CT_ONLY" bs=16 skip=1 status=none
IVHEX=$(xxd -p "$IV" | tr -d '\n')
openssl enc -aes-128-ofb -d -K $KEY -iv $IVHEX -in "$CT_ONLY" -out "$OPENSSL_PT" -nosalt
cmp -s "$PLAINTXT" "$OPENSSL_PT" && echo "[PASS] cryptocore->OpenSSL OFB interop" || { echo "[FAIL] cryptocore->OpenSSL OFB interop"; exit 3; }

echo "4) Interop: OpenSSL -> cryptocore"
IV2HEX="11223344556677889900aabbccddeeff"
openssl enc -aes-128-ofb -K $KEY -iv $IV2HEX -in "$PLAINTXT" -out "$TMP/openssl_ct.bin" -nosalt
$BIN --algorithm aes --mode ofb --decrypt --key @"$KEY" --iv $IV2HEX --input "$TMP/openssl_ct.bin" --output "$TMP/our_decrypted.txt"
cmp -s "$PLAINTXT" "$TMP/our_decrypted.txt" && echo "[PASS] OpenSSL->cryptocore OFB interop" || { echo "[FAIL] OpenSSL->cryptocore OFB interop"; exit 4; }

echo "[OK] OFB tests passed."
