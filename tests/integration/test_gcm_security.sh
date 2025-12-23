echo "=== GCM Security Tests ==="

echo "Test 1: Normal encryption/decryption"
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.gcm
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.gcm --output test_dec.txt
diff test.txt test_dec.txt && echo "✓ Test 1 passed"

echo "Test 2: Wrong key"
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key ffeeddccbbaa99887766554433221100 \
  --input test.gcm --output should_fail.txt 2>/dev/null
[ $? -ne 0 ] && echo "✓ Test 2 passed (correctly failed)"

echo "Test 3: Tampered ciphertext"
cp test.gcm tampered.gcm
printf '\xAA' | dd of=tampered.gcm bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input tampered.gcm --output should_fail2.txt 2>/dev/null
[ $? -ne 0 ] && echo "✓ Test 3 passed (correctly failed)"