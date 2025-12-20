echo "=== Testing GCM with AAD ==="

echo "Secret message with AAD" > secret.txt

echo "Test 1: Encryption with AAD"
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff00112233445566778899 \
  --input secret.txt --output secret_enc.gcm 2>&1

echo "Test 2: Decryption with correct AAD"
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccddeeff00112233445566778899 \
  --input secret_enc.gcm --output secret_dec.txt 2>&1
diff secret.txt secret_dec.txt && echo "✓ Test 2 passed: Decryption with correct AAD successful"

echo "Test 3: Decryption with wrong AAD"
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad wrongaadwrongaadwrongaadwrongaad \
  --input secret_enc.gcm --output should_fail.txt 2>&1
[ $? -ne 0 ] && echo "✓ Test 3 passed: Authentication correctly failed with wrong AAD"