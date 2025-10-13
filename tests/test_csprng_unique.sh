set -euo pipefail
BIN="./cryptocore"
TMPDIR=$(mktemp -d)
OUT="$TMPDIR/keys.txt"
COUNT=1000

> "$OUT"
for i in $(seq 1 $COUNT); do
  PLAIN="$TMPDIR/p${i}.txt"
  CT="$TMPDIR/c${i}.bin"
  echo "$i" > "$PLAIN"
  OUTP=$($BIN --algorithm aes --mode cfb --encrypt --input "$PLAIN" --output "$CT" 2>&1 | sed -n 's/.*Generated random key: //p' | tr -d '[:space:]')
  if [ -z "$OUTP" ]; then
    echo "Failed to generate key on iteration $i"
    exit 2
  fi
  echo "$OUTP" >> "$OUT"
  rm -f "$PLAIN" "$CT"
done

UNIQUES=$(sort "$OUT" | uniq | wc -l)
echo "Generated $COUNT keys, uniques: $UNIQUES"

if [ "$UNIQUES" -eq "$COUNT" ]; then
  echo "[PASS] All keys unique"
  exit 0
else
  echo "[FAIL] Some duplicates detected"
  exit 3
fi
