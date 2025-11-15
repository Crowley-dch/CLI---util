set -euo pipefail


TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

cat >"$TMPDIR/empty" <<'EOF'
EOF

EXP_EMPTY="e3b0c44298fc1c149afbf4c8996fb924\
27ae41e4649b934ca495991b7852b855"

cat >"$TMPDIR/test.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "src/hash/sha256.h"

int main(void) {
    uint8_t hash[32];
    FILE *f = fopen("tests/test_input.bin", "rb");
    if (!f) { perror("open"); return 2; }
    SHA256_CTX ctx;
    sha256_init(&ctx);
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf,1,sizeof(buf),f)) > 0) {
        sha256_update(&ctx, buf, n);
    }
    sha256_final(&ctx, hash);
    char hex[65];
    sha256_to_hex(hash, hex);
    printf("%s\n", hex);
    return 0;
}
EOF

cp "$TMPDIR/empty" tests/test_input.bin

gcc -I. src/hash/sha256.c "$TMPDIR/test.c" -o "$TMPDIR/test_hash" -O2

OUT=$("$TMPDIR/test_hash")
echo "Computed: $OUT"
echo "Expected: $EXP_EMPTY"

if [ "$OUT" = "$EXP_EMPTY" ]; then
  echo "[PASS] SHA256 empty-string vector OK"
  exit 0
else
  echo "[FAIL] SHA256 mismatch"
  exit 3
fi
