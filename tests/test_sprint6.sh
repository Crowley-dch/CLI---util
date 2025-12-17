echo "=== Sprint 6: Authenticated Encryption Tests ==="

echo "Test 1: GCM round-trip with AAD"
echo "test" > test_gcm.txt
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00000000000000000000000000000000 \
  --aad aabbccdd \
  --input test_gcm.txt --output test_gcm.enc
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00000000000000000000000000000000 \
  --aad aabbccdd \
  --input test_gcm.enc --output test_gcm.dec
diff test_gcm.txt test_gcm.dec && echo "✓ GCM round-trip passed"

echo "Test 2: GCM wrong AAD detection"
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00000000000000000000000000000000 \
  --aad wrongaad \
  --input test_gcm.enc --output /dev/null 2>/dev/null
[ $? -ne 0 ] && echo "✓ GCM wrong AAD detection passed"

echo "Test 3: ETM round-trip"
echo "test" > test_etm.txt
./cryptocore --algorithm aes --mode etm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_etm.txt --output test_etm.enc
./cryptocore --algorithm aes --mode etm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test_etm.enc --output test_etm.dec
diff test_etm.txt test_etm.dec && echo "✓ ETM round-trip passed"

echo "Test 4: ETM tampered ciphertext detection"
cp test_etm.enc tampered.enc
printf '\x01' | dd of=tampered.enc bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
./cryptocore --algorithm aes --mode etm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input tampered.enc --output /dev/null 2>/dev/null
[ $? -ne 0 ] && echo "✓ ETM tamper detection passed"

echo "Test 5: Empty AAD handling"
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00000000000000000000000000000000 \
  --aad "" \
  --input test_gcm.txt --output test_gcm_empty.enc
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00000000000000000000000000000000 \
  --aad "" \
  --input test_gcm_empty.enc --output test_gcm_empty.dec
diff test_gcm.txt test_gcm_empty.dec && echo "✓ Empty AAD handling passed"

rm -f test_*.txt test_*.enc test_*.dec tampered.*

echo "=== Tests completed ==="

