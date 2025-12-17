set -euo pipefail

./tests/test_cbc_roundtrip.sh
./tests/test_ofb_roundtrip.sh
./tests/test_ctr_roundtrip.sh
./tests/test_roundtrip.sh
./tests/test_csprng_roundtrip.sh
./tests/test_csprng_unique.sh
./tests/test_hash_vectors.sh
./tests/test_sprint6.sh
./tests/test_aad.sh
./tests/test_gcm_security.sh
echo "[ALL] All mode tests passed."