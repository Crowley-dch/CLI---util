set -euo pipefail

./tests/test_cbc_roundtrip.sh
./tests/test_ofb_roundtrip.sh
./tests/test_ctr_roundtrip.sh

echo "[ALL] All mode tests passed."