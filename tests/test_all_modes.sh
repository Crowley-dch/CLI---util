set -euo pipefail

./tests/test_cbc_roundtrip.sh
./tests/test_ofb_roundtrip.sh
./tests/test_ctr_roundtrip.sh
./tests/test_roundtrip.sh
./tests/test_csprng_roundstrip.sh
./tests/test_csprng_unique.sh

echo "[ALL] All mode tests passed."